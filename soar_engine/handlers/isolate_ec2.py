"""EC2 Host Isolation & Forensic Snapshot SOAR Handler.

Swaps compromised instance security groups to an isolated Quarantine SG (zero ingress/egress),
preserves original security group state in instance tags for rollback, and triggers
point-in-time forensic EBS snapshots on all attached volumes.
"""

from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
import uuid

from botocore.exceptions import ClientError

from soar_engine.handlers.alert_dispatcher import dispatch_alert
from soar_engine.utils.aws_client import get_boto3_client, get_logger

logger = get_logger(__name__)

QUARANTINE_SG_NAME = os.environ.get("QUARANTINE_SG_NAME", "soar-quarantine-sg")


def extract_instance_id(event: Dict[str, Any]) -> Optional[str]:
    """Extracts target EC2 instance ID from varied event schemas.

    Supports GuardDuty findings, CloudTrail events, and direct invocation payloads.
    """
    # Direct payload
    if "instance_id" in event:
        return event["instance_id"]

    detail = event.get("detail", {})

    # Direct nested in detail
    if "instance_id" in detail:
        return detail["instance_id"]
    if "instance-id" in detail:
        return detail["instance-id"]

    # GuardDuty finding schema
    gd_instance = detail.get("resource", {}).get("instanceDetails", {}).get("instanceId")
    if gd_instance:
        return gd_instance

    # CloudTrail RunInstances / ModifyInstanceAttribute schema
    request_params = detail.get("requestParameters", {})
    if "instanceId" in request_params:
        return request_params["instanceId"]
    if "instancesSet" in request_params:
        items = request_params["instancesSet"].get("items", [])
        if items and "instanceId" in items[0]:
            return items[0]["instanceId"]

    # CloudTrail responseElements
    response_elements = detail.get("responseElements", {}) or {}
    if "instancesSet" in response_elements:
        items = response_elements["instancesSet"].get("items", [])
        if items and "instanceId" in items[0]:
            return items[0]["instanceId"]

    return None


def get_or_create_quarantine_sg(ec2_client: Any, vpc_id: str) -> str:
    """Finds or creates a zero-traffic quarantine security group inside the VPC.

    Args:
        ec2_client: Boto3 EC2 client.
        vpc_id: VPC ID where the compromised instance resides.

    Returns:
        Quarantine Security Group ID.
    """
    configured_sg_id = os.environ.get("QUARANTINE_SG_ID")
    if configured_sg_id:
        return configured_sg_id

    # Search for existing SG by name in the target VPC
    try:
        response = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
        )
        groups = response.get("SecurityGroups", [])
        if groups:
            return groups[0]["GroupId"]
    except ClientError as exc:
        logger.warning(f"Error checking existing quarantine SG: {exc}")

    # Create new quarantine security group
    logger.info(f"Creating new quarantine security group in VPC: {vpc_id}")
    create_res = ec2_client.create_security_group(
        GroupName=QUARANTINE_SG_NAME,
        Description="SOAR Automated Quarantine Security Group - Zero Ingress and Zero Egress",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": "Name", "Value": QUARANTINE_SG_NAME},
                    {"Key": "ManagedBy", "Value": "SOAR-Pipeline"},
                    {"Key": "Purpose", "Value": "Host-Isolation"},
                ],
            }
        ],
    )
    sg_id = create_res["GroupId"]

    # In standard AWS VPCs, a newly created SG comes with an allow-all egress rule. Revoke it.
    try:
        sg_info = ec2_client.describe_security_groups(GroupIds=[sg_id])
        for sg in sg_info.get("SecurityGroups", []):
            egress_permissions = sg.get("IpPermissionsEgress", [])
            if egress_permissions:
                ec2_client.revoke_security_group_egress(
                    GroupId=sg_id,
                    IpPermissions=egress_permissions,
                )
                logger.info(f"Revoked all default egress permissions on quarantine SG: {sg_id}")
    except ClientError as exc:
        logger.warning(f"Unable to revoke default egress on {sg_id}: {exc}")

    return sg_id


def capture_forensic_snapshots(ec2_client: Any, instance_id: str, incident_id: str) -> List[str]:
    """Captures forensic EBS snapshots for all attached volumes on the instance.

    Args:
        ec2_client: Boto3 EC2 client.
        instance_id: Target instance ID.
        incident_id: Unique incident tracking identifier.

    Returns:
        List of created snapshot IDs.
    """
    snapshot_ids: List[str] = []
    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
    reservations = instance_info.get("Reservations", [])
    if not reservations or not reservations[0].get("Instances"):
        return snapshot_ids

    instance = reservations[0]["Instances"][0]
    block_mappings = instance.get("BlockDeviceMappings", [])
    timestamp = datetime.now(timezone.utc).isoformat()

    for mapping in block_mappings:
        ebs_info = mapping.get("Ebs")
        if not ebs_info:
            continue
        volume_id = ebs_info.get("VolumeId")
        device_name = mapping.get("DeviceName", "unknown")

        if not volume_id:
            continue

        try:
            logger.info(f"Initiating forensic snapshot for volume {volume_id} ({device_name})")
            snap_res = ec2_client.create_snapshot(
                VolumeId=volume_id,
                Description=f"SOAR Forensic snapshot of {volume_id} attached to {instance_id} at {device_name}",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "IncidentId", "Value": incident_id},
                            {"Key": "SourceInstanceId", "Value": instance_id},
                            {"Key": "SourceVolumeId", "Value": volume_id},
                            {"Key": "DeviceName", "Value": device_name},
                            {"Key": "SOAR:ForensicEvidence", "Value": "True"},
                            {"Key": "CreatedAt", "Value": timestamp},
                        ],
                    }
                ],
            )
            snapshot_ids.append(snap_res["SnapshotId"])
            logger.info(f"Forensic snapshot created: {snap_res['SnapshotId']}")
        except ClientError as exc:
            logger.error(f"Failed to create snapshot for volume {volume_id}: {exc}")

    return snapshot_ids


def isolate_instance(
    instance_id: str,
    ec2_client: Optional[Any] = None,
    incident_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Isolates the EC2 instance, captures EBS snapshots, and preserves original state.

    Args:
        instance_id: EC2 instance ID to isolate.
        ec2_client: Optional boto3 EC2 client instance.
        incident_id: Optional tracking identifier.

    Returns:
        Execution summary dictionary.
    """
    client = ec2_client or get_boto3_client("ec2")
    inc_id = incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    # Step 1: Describe instance to get VPC and current security groups
    describe_res = client.describe_instances(InstanceIds=[instance_id])
    reservations = describe_res.get("Reservations", [])
    if not reservations or not reservations[0].get("Instances"):
        raise ValueError(f"Instance {instance_id} not found")

    instance = reservations[0]["Instances"][0]
    vpc_id = instance.get("VpcId")
    if not vpc_id:
        raise ValueError(f"Instance {instance_id} has no attached VPC")

    current_groups = [g["GroupId"] for g in instance.get("SecurityGroups", [])]
    pre_quarantine_sgs = ",".join(current_groups)

    # Step 2: Ensure Quarantine Security Group exists
    quarantine_sg_id = get_or_create_quarantine_sg(client, vpc_id)

    # Step 3: Tag instance with original security groups & containment status
    client.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "SOAR:PreQuarantineSG", "Value": pre_quarantine_sgs},
            {"Key": "SOAR:QuarantineState", "Value": "Quarantined"},
            {"Key": "SOAR:QuarantineTimestamp", "Value": iso_timestamp},
            {"Key": "SOAR:IncidentId", "Value": inc_id},
        ],
    )
    logger.info(f"Tagged instance {instance_id} with pre-quarantine security groups: {pre_quarantine_sgs}")

    # Step 4: Swap Security Group to Quarantine SG
    client.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg_id],
    )
    logger.info(f"Replaced security groups on {instance_id} with Quarantine SG {quarantine_sg_id}")

    # Step 5: Capture forensic EBS snapshots
    snapshots = capture_forensic_snapshots(client, instance_id, inc_id)

    # Step 6: Dispatch notification
    alert_summary = {
        "title": "EC2 Host Isolated & Forensics Captured",
        "severity": "CRITICAL",
        "status": "CONTAINED",
        "resource_id": instance_id,
        "mitre_attack": "T1071 / T1562.001 - Application Protocol / Impair Defenses",
        "summary": f"Compromised host {instance_id} isolated into {quarantine_sg_id}. Active network access severed.",
        "action_taken": (
            f"1. Swapped SGs ({pre_quarantine_sgs}) -> [{quarantine_sg_id}]\n"
            f"2. Tagged instance with incident metadata\n"
            f"3. Captured {len(snapshots)} EBS forensic snapshot(s): {', '.join(snapshots)}"
        ),
        "incident_id": inc_id,
        "snapshots": snapshots,
    }
    dispatch_alert(alert_summary)

    return {
        "status": "CONTAINED",
        "instance_id": instance_id,
        "quarantine_sg_id": quarantine_sg_id,
        "previous_sgs": current_groups,
        "snapshots": snapshots,
        "incident_id": inc_id,
    }


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for EC2 isolation playbook."""
    logger.info("Executing isolate_ec2 handler", extra={"extra_fields": {"raw_event": event}})

    try:
        instance_id = extract_instance_id(event)
        if not instance_id:
            logger.error("Could not determine instance_id from event payload")
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "instance_id could not be resolved from event"}),
            }

        result = isolate_instance(instance_id)

        return {
            "statusCode": 200,
            "body": json.dumps(result),
        }

    except Exception as exc:
        logger.exception(f"Failed to isolate instance: {exc}")
        return {
            "statusCode": 500,
            "body": json.dumps({"status": "FAILED", "error": str(exc)}),
        }
