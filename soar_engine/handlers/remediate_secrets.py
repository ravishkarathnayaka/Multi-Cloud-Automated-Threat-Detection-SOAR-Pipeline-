"""AWS Secrets Manager Compromised Secret Rotation SOAR Handler.

Forces immediate rotation of compromised or exfiltrated API keys/passwords
stored within AWS Secrets Manager.
"""

from typing import Any, Dict, Optional
from soar_engine.handlers.alert_dispatcher import dispatch_alert
from soar_engine.utils.aws_client import get_boto3_client, get_logger

logger = get_logger(__name__)


def extract_secret_id(event: Dict[str, Any]) -> Optional[str]:
    """Extracts secret ID or ARN from incoming event."""
    if "secret_id" in event:
        return event["secret_id"]
    detail = event.get("detail", {})
    if "secret_id" in detail:
        return detail["secret_id"]
    req_params = detail.get("requestParameters", {})
    return req_params.get("secretId")


def force_secret_rotation(sm_client: Any, secret_id: str) -> Dict[str, Any]:
    """Triggers immediate rotation for target compromised secret."""
    logger.info("Triggering emergency rotation on secret: %s", secret_id)
    response = sm_client.rotate_secret(SecretId=secret_id)
    return {"secret_id": secret_id, "version_id": response.get("VersionId"), "rotated": True}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Handles Secrets Manager compromise events."""
    secret_id = extract_secret_id(event)
    if not secret_id:
        return {"statusCode": 400, "message": "Missing secret_id"}

    sm_client = get_boto3_client("secretsmanager")
    result = force_secret_rotation(sm_client, secret_id)

    dispatch_alert({
        "title": "AWS Secrets Manager Secret Rotated",
        "severity": "HIGH",
        "status": "REMEDIATED",
        "resource_id": secret_id,
        "mitre_attack": "T1555 - Credentials from Password Stores",
        "action_taken": f"Triggered emergency rotation for secret {secret_id}",
    })

    return {"statusCode": 200, "result": result}
