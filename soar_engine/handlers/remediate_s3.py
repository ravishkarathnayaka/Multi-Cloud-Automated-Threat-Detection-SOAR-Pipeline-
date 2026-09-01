"""S3 Bucket Public Exposure Remediation SOAR Handler.

Detects unauthorized public exposure of Amazon S3 buckets, re-enforces the four
S3 Public Access Block settings, removes or restricts insecure wildcard public policies,
and tags the resource for security auditing.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError

from soar_engine.handlers.alert_dispatcher import dispatch_alert
from soar_engine.utils.aws_client import get_boto3_client, get_logger

logger = get_logger(__name__)


def extract_bucket_name(event: Dict[str, Any]) -> Optional[str]:
    """Extracts target S3 bucket name from event payload.

    Supports CloudTrail events, S3 notifications, and direct invocation payloads.
    """
    # Direct payload
    if "bucket_name" in event:
        return event["bucket_name"]

    detail = event.get("detail", {})
    if "bucket_name" in detail:
        return detail["bucket_name"]
    if "bucket" in detail:
        return detail["bucket"]

    # CloudTrail requestParameters
    req_params = detail.get("requestParameters", {})
    if "bucketName" in req_params:
        return req_params["bucketName"]

    # CloudTrail resources list
    resources = detail.get("resources", [])
    for res in resources:
        if res.get("type") == "AWS::S3::Bucket":
            arn = res.get("ARN", "")
            return arn.split(":::")[-1] if ":::" in arn else arn

    return None


def enforce_public_access_block(s3_client: Any, bucket_name: str) -> Dict[str, bool]:
    """Enforces all 4 S3 Public Access Block settings on the bucket.

    Args:
        s3_client: Boto3 S3 client.
        bucket_name: Name of target bucket.

    Returns:
        Dictionary of applied public access block settings.
    """
    configuration = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration=configuration,
    )
    logger.info(f"Enforced strict Public Access Block on bucket {bucket_name}")
    return configuration


def sanitize_bucket_policy(s3_client: Any, bucket_name: str) -> Optional[str]:
    """Checks for and remediates wildcard public bucket policy statements.

    Args:
        s3_client: Boto3 S3 client.
        bucket_name: Name of target bucket.

    Returns:
        Remediation description or None if no changes made.
    """
    try:
        policy_res = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_str = policy_res.get("Policy", "")
        if not policy_str:
            return None

        policy_doc = json.loads(policy_str)
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        has_public_wildcard = False
        retained_statements = []

        for stmt in statements:
            effect = stmt.get("Effect")
            principal = stmt.get("Principal")

            is_wildcard = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")

            if effect == "Allow" and is_wildcard:
                has_public_wildcard = True
                logger.warning(
                    f"Found public wildcard allow in bucket {bucket_name} statement: {stmt.get('Sid', 'NoSid')}"
                )
            else:
                retained_statements.append(stmt)

        if has_public_wildcard:
            if not retained_statements:
                # Delete policy entirely if all statements were public wildcards
                s3_client.delete_bucket_policy(Bucket=bucket_name)
                logger.info(f"Deleted wholly public bucket policy from {bucket_name}")
                return "Deleted completely public bucket policy"
            else:
                # Update policy retaining only non-public statements
                policy_doc["Statement"] = retained_statements
                s3_client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps(policy_doc),
                )
                logger.info(f"Sanitized bucket policy on {bucket_name}, stripped public statements")
                return "Stripped public wildcard allow statements from policy"

    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")
        if error_code in ("NoSuchBucketPolicy", "404"):
            logger.info(f"No bucket policy attached to {bucket_name}")
            return None
        logger.warning(f"Error checking bucket policy on {bucket_name}: {exc}")

    return None


def tag_remediated_bucket(s3_client: Any, bucket_name: str) -> None:
    """Tags the S3 bucket with SOAR remediation evidence."""
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        # Retrieve existing tags
        existing_tags = []
        try:
            tag_res = s3_client.get_bucket_tagging(Bucket=bucket_name)
            existing_tags = tag_res.get("TagSet", [])
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code not in ("NoSuchTagSet", "404"):
                logger.warning(f"Error fetching tags for {bucket_name}: {exc}")

        # Update or append SOAR tags
        tag_dict = {t["Key"]: t["Value"] for t in existing_tags}
        tag_dict["SOAR:PublicAccessRemediated"] = "True"
        tag_dict["SOAR:RemediatedTimestamp"] = timestamp
        tag_dict["SOAR:Compliance"] = "StrictPrivate"

        new_tags = [{"Key": k, "Value": v} for k, v in tag_dict.items()]
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={"TagSet": new_tags},
        )
        logger.info(f"Tagged bucket {bucket_name} with remediation metadata")
    except ClientError as exc:
        logger.warning(f"Failed to update tags on bucket {bucket_name}: {exc}")


def remediate_bucket(
    bucket_name: str,
    s3_client: Optional[Any] = None,
) -> Dict[str, Any]:
    """Executes S3 public exposure remediation.

    Args:
        bucket_name: Name of exposed bucket.
        s3_client: Optional Boto3 S3 client override.

    Returns:
        Summary dict of actions executed.
    """
    client = s3_client or get_boto3_client("s3")

    # Step 1: Enforce Public Access Block
    pab_config = enforce_public_access_block(client, bucket_name)

    # Step 2: Sanitize bucket policy
    policy_action = sanitize_bucket_policy(client, bucket_name)

    # Step 3: Tag bucket
    tag_remediated_bucket(client, bucket_name)

    action_text = (
        f"1. Enabled all 4 S3 Public Access Block controls\n"
        f"2. Policy Action: {policy_action or 'None needed (no public policy)'}\n"
        f"3. Applied compliance tags"
    )

    # Step 4: Dispatch alert
    alert_summary = {
        "title": "S3 Public Exposure Neutralized",
        "severity": "HIGH",
        "status": "REMEDIATED",
        "resource_id": f"arn:aws:s3:::{bucket_name}",
        "mitre_attack": "T1530 - Data from Cloud Storage Object",
        "summary": f"Bucket '{bucket_name}' public exposure mitigated with Public Access Block.",
        "action_taken": action_text,
        "public_access_block": pab_config,
        "policy_action": policy_action,
    }
    dispatch_alert(alert_summary)

    return {
        "status": "REMEDIATED",
        "bucket_name": bucket_name,
        "public_access_block": pab_config,
        "policy_action": policy_action,
    }


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for S3 Remediation Playbook."""
    logger.info("Executing remediate_s3 handler", extra={"extra_fields": {"raw_event": event}})

    try:
        bucket_name = extract_bucket_name(event)
        if not bucket_name:
            logger.error("Could not determine bucket_name from event payload")
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "bucket_name could not be resolved from event"}),
            }

        result = remediate_bucket(bucket_name)

        return {
            "statusCode": 200,
            "body": json.dumps(result),
        }

    except Exception as exc:
        logger.exception(f"Failed to remediate bucket: {exc}")
        return {
            "statusCode": 500,
            "body": json.dumps({"status": "FAILED", "error": str(exc)}),
        }
