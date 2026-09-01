"""IAM Privilege Revocation & STS Session Invalidation SOAR Handler.

Remediates compromised IAM Users and Roles by deactivating active Access Keys,
attaching inline emergency DenyAll policies, and invalidating existing STS session
tokens using AWS DateLessThan TokenIssueTime condition.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from soar_engine.handlers.alert_dispatcher import dispatch_alert
from soar_engine.utils.aws_client import get_boto3_client, get_logger

logger = get_logger(__name__)

EMERGENCY_POLICY_NAME = "SOAR-DenyAll-Emergency"


def extract_iam_target(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Extracts entity type ('user' or 'role') and entity name from event.

    Args:
        event: EventBridge CloudTrail payload or direct trigger dictionary.

    Returns:
        Tuple of (entity_type, entity_name) or (None, None).
    """
    # Direct payload support
    if "user_name" in event:
        return "user", event["user_name"]
    if "role_name" in event:
        return "role", event["role_name"]

    detail = event.get("detail", {})
    if "user_name" in detail:
        return "user", detail["user_name"]
    if "role_name" in detail:
        return "role", detail["role_name"]

    # CloudTrail requestParameters inspection
    req_params = detail.get("requestParameters", {})
    if "userName" in req_params:
        return "user", req_params["userName"]
    if "roleName" in req_params:
        return "role", req_params["roleName"]

    # CloudTrail userIdentity fallback
    user_identity = detail.get("userIdentity", {})
    principal_type = user_identity.get("type")
    if principal_type == "IAMUser" and "userName" in user_identity:
        return "user", user_identity["userName"]
    if principal_type == "AssumedRole":
        arn = user_identity.get("arn", "")
        # arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
        if "assumed-role" in arn:
            parts = arn.split("/")
            if len(parts) >= 2:
                return "role", parts[1]

    return None, None


def revoke_iam_user(iam_client: Any, user_name: str) -> Dict[str, Any]:
    """Deactivates user access keys and attaches an inline DenyAll policy.

    Args:
        iam_client: Boto3 IAM client.
        user_name: Name of compromised IAM user.

    Returns:
        Dictionary of actions executed.
    """
    deactivated_keys: List[str] = []

    # Step 1: List and deactivate all active access keys
    try:
        keys_res = iam_client.list_access_keys(UserName=user_name)
        for key_meta in keys_res.get("AccessKeyMetadata", []):
            key_id = key_meta["AccessKeyId"]
            if key_meta.get("Status") == "Active":
                iam_client.update_access_key(
                    UserName=user_name,
                    AccessKeyId=key_id,
                    Status="Inactive",
                )
                deactivated_keys.append(key_id)
                logger.info(f"Deactivated access key {key_id} for user {user_name}")
    except ClientError as exc:
        logger.warning(f"Error checking/deactivating access keys for {user_name}: {exc}")

    # Step 2: Put inline emergency DenyAll policy
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SOAREmergencyDenyAll",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }

    iam_client.put_user_policy(
        UserName=user_name,
        PolicyName=EMERGENCY_POLICY_NAME,
        PolicyDocument=json.dumps(deny_policy),
    )
    logger.info(f"Attached inline {EMERGENCY_POLICY_NAME} policy to user {user_name}")

    # Step 3: Tag user with incident metadata
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        iam_client.tag_user(
            UserName=user_name,
            Tags=[
                {"Key": "SOAR:Remediated", "Value": "True"},
                {"Key": "SOAR:RemediatedTimestamp", "Value": timestamp},
                {"Key": "SOAR:Reason", "Value": "CompromisedCredentials"},
            ],
        )
    except ClientError as exc:
        logger.warning(f"Unable to tag user {user_name}: {exc}")

    return {
        "entity_type": "user",
        "entity_name": user_name,
        "deactivated_keys": deactivated_keys,
        "policy_applied": EMERGENCY_POLICY_NAME,
        "timestamp": timestamp,
    }


def revoke_iam_role(iam_client: Any, role_name: str) -> Dict[str, Any]:
    """Invalidates active STS sessions for a role using DateLessThan TokenIssueTime.

    Attaches an inline policy denying all operations where aws:TokenIssueTime
    is prior to the incident containment timestamp.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # Invalidate all STS tokens issued before current time
    revoke_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SOAREmergencyRevokeSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": timestamp,
                    }
                },
            }
        ],
    }

    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=EMERGENCY_POLICY_NAME,
        PolicyDocument=json.dumps(revoke_policy),
    )
    logger.info(f"Attached STS session invalidation policy to role {role_name}")

    # Tag role with containment metadata
    try:
        iam_client.tag_role(
            RoleName=role_name,
            Tags=[
                {"Key": "SOAR:Remediated", "Value": "True"},
                {"Key": "SOAR:RemediatedTimestamp", "Value": timestamp},
                {"Key": "SOAR:Reason", "Value": "PrivilegeEscalationDetected"},
            ],
        )
    except ClientError as exc:
        logger.warning(f"Unable to tag role {role_name}: {exc}")

    return {
        "entity_type": "role",
        "entity_name": role_name,
        "revocation_timestamp": timestamp,
        "policy_applied": EMERGENCY_POLICY_NAME,
    }


def revoke_identity(
    entity_type: str,
    entity_name: str,
    iam_client: Optional[Any] = None,
) -> Dict[str, Any]:
    """Executes remediation against the specified IAM entity.

    Args:
        entity_type: 'user' or 'role'.
        entity_name: IAM entity name.
        iam_client: Optional boto3 client override.

    Returns:
        Summary dict of containment actions.
    """
    client = iam_client or get_boto3_client("iam")

    if entity_type == "user":
        remediation = revoke_iam_user(client, entity_name)
        action_text = (
            f"1. Deactivated active access keys: {remediation['deactivated_keys']}\n"
            f"2. Attached inline emergency DenyAll policy: {remediation['policy_applied']}\n"
            f"3. Tagged user with incident metadata"
        )
    elif entity_type == "role":
        remediation = revoke_iam_role(client, entity_name)
        action_text = (
            f"1. Attached inline policy {remediation['policy_applied']}\n"
            f"2. Invalidated all STS tokens issued before {remediation['revocation_timestamp']}\n"
            f"3. Tagged role with incident metadata"
        )
    else:
        raise ValueError(f"Unsupported entity type: {entity_type}")

    # Dispatch alert
    alert_summary = {
        "title": f"IAM {entity_type.capitalize()} Credentials Revoked",
        "severity": "CRITICAL",
        "status": "REMEDIATED",
        "resource_id": f"arn:aws:iam::{entity_type}/{entity_name}",
        "mitre_attack": "T1098 / T1078.004 - Account Manipulation / Cloud Accounts",
        "summary": f"Detected unauthorized privilege activity for {entity_type} '{entity_name}'. Sessions revoked.",
        "action_taken": action_text,
        "remediation_details": remediation,
    }
    dispatch_alert(alert_summary)

    return {
        "status": "REMEDIATED",
        "entity_type": entity_type,
        "entity_name": entity_name,
        "remediation": remediation,
    }


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for IAM Revocation Playbook."""
    logger.info("Executing revoke_iam_session handler", extra={"extra_fields": {"raw_event": event}})

    try:
        entity_type, entity_name = extract_iam_target(event)
        if not entity_type or not entity_name:
            logger.error("Failed to extract IAM entity from event")
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Unable to determine IAM user or role from event"}),
            }

        result = revoke_identity(entity_type, entity_name)

        return {
            "statusCode": 200,
            "body": json.dumps(result),
        }

    except Exception as exc:
        logger.exception(f"Failed to revoke IAM identity: {exc}")
        return {
            "statusCode": 500,
            "body": json.dumps({"status": "FAILED", "error": str(exc)}),
        }
