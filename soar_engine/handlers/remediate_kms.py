"""AWS KMS Scheduled Key Deletion Cancellation SOAR Handler.

Detects unauthorized ScheduleKeyDeletion events on critical encryption keys,
cancels the deletion countdown, and dispatches high-priority security notifications.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from soar_engine.handlers.alert_dispatcher import dispatch_alert
from soar_engine.utils.aws_client import get_boto3_client, get_logger

logger = get_logger(__name__)


def extract_key_id(event: Dict[str, Any]) -> Optional[str]:
    """Extracts target KMS Key ID or ARN from incoming event."""
    if "key_id" in event:
        return event["key_id"]
    detail = event.get("detail", {})
    if "key_id" in detail:
        return detail["key_id"]
    req_params = detail.get("requestParameters", {})
    return req_params.get("keyId")


def cancel_key_deletion(kms_client: Any, key_id: str) -> Dict[str, Any]:
    """Cancels scheduled key deletion and re-enables cryptographic key."""
    logger.info("Canceling deletion for KMS key: %s", key_id)
    kms_client.cancel_key_deletion(KeyId=key_id)
    kms_client.enable_key(KeyId=key_id)
    return {"key_id": key_id, "status": "DELETION_CANCELED", "re_enabled": True}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Entry point for EventBridge KMS deletion prevention rule."""
    key_id = extract_key_id(event)
    if not key_id:
        return {"statusCode": 400, "message": "Missing keyId in payload"}

    kms_client = get_boto3_client("kms")
    remediation = cancel_key_deletion(kms_client, key_id)

    dispatch_alert({
        "title": "AWS KMS Key Destruction Prevented",
        "severity": "CRITICAL",
        "status": "REMEDIATED",
        "resource_id": key_id,
        "mitre_attack": "T1485 - Data Destruction",
        "action_taken": f"Canceled deletion countdown and re-enabled key {key_id}",
    })

    return {"statusCode": 200, "remediation": remediation}
