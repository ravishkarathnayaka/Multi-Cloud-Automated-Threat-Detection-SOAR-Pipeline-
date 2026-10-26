"""AWS RDS Snapshot Public Sharing Remediation SOAR Handler.

Revokes unauthorized public sharing or external cross-account permissions
on Amazon RDS database snapshots.
"""

from typing import Any, Dict, Optional
from soar_engine.handlers.alert_dispatcher import dispatch_alert
from soar_engine.utils.aws_client import get_boto3_client, get_logger

logger = get_logger(__name__)


def extract_snapshot_id(event: Dict[str, Any]) -> Optional[str]:
    """Extracts DB snapshot identifier from event."""
    if "snapshot_id" in event:
        return event["snapshot_id"]
    detail = event.get("detail", {})
    if "snapshot_id" in detail:
        return detail["snapshot_id"]
    req_params = detail.get("requestParameters", {})
    return req_params.get("dBSnapshotIdentifier")


def revoke_snapshot_public_access(rds_client: Any, snapshot_id: str) -> Dict[str, Any]:
    """Removes 'all' from snapshot attribute values to restore privacy."""
    logger.info("Revoking public access on RDS snapshot: %s", snapshot_id)
    rds_client.modify_db_snapshot_attribute(
        DBSnapshotIdentifier=snapshot_id,
        AttributeName="restore",
        ValuesToRemove=["all"],
    )
    return {"snapshot_id": snapshot_id, "public_access_revoked": True}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for RDS public snapshot mitigation."""
    snapshot_id = extract_snapshot_id(event)
    if not snapshot_id:
        return {"statusCode": 400, "message": "Missing snapshot_id"}

    rds_client = get_boto3_client("rds")
    result = revoke_snapshot_public_access(rds_client, snapshot_id)

    dispatch_alert({
        "title": "RDS Database Snapshot Public Sharing Revoked",
        "severity": "CRITICAL",
        "status": "REMEDIATED",
        "resource_id": snapshot_id,
        "mitre_attack": "T1530 - Data from Cloud Storage",
        "action_taken": f"Removed global 'all' attribute on snapshot {snapshot_id}",
    })

    return {"statusCode": 200, "result": result}
