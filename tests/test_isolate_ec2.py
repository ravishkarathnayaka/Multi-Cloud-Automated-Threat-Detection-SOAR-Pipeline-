"""Unit Tests for EC2 Host Isolation Playbook Handler."""

import json
from typing import Any
from moto import mock_aws

from soar_engine.handlers.isolate_ec2 import (
    extract_instance_id,
    get_or_create_quarantine_sg,
    isolate_instance,
    lambda_handler,
)


def test_extract_instance_id_formats() -> None:
    """Tests instance ID extraction across multiple event schemas."""
    # Direct dictionary
    assert extract_instance_id({"instance_id": "i-11111111"}) == "i-11111111"

    # Nested in detail
    assert extract_instance_id({"detail": {"instance-id": "i-22222222"}}) == "i-22222222"

    # GuardDuty schema
    gd_event = {"detail": {"resource": {"instanceDetails": {"instanceId": "i-33333333"}}}}
    assert extract_instance_id(gd_event) == "i-33333333"

    # CloudTrail requestParameters
    ct_event = {"detail": {"requestParameters": {"instanceId": "i-44444444"}}}
    assert extract_instance_id(ct_event) == "i-44444444"

    # Missing returns None
    assert extract_instance_id({"detail": {}}) is None


@mock_aws
def test_get_or_create_quarantine_sg(ec2_client: Any) -> None:
    """Verifies creation and retrieval of quarantine security group."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    # 1. Create when does not exist
    sg_id = get_or_create_quarantine_sg(ec2_client, vpc_id)
    assert sg_id.startswith("sg-")

    # Verify egress is revoked
    sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])
    assert sg_details["SecurityGroups"][0]["IpPermissionsEgress"] == []

    # 2. Retrieve existing SG
    sg_id_2 = get_or_create_quarantine_sg(ec2_client, vpc_id)
    assert sg_id_2 == sg_id


@mock_aws
def test_isolate_instance_workflow(ec2_client: Any) -> None:
    """Verifies end-to-end instance isolation, SG swapping, and EBS snapshotting."""
    # Setup VPC, Subnet, and Security Group
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    subnet = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    subnet_id = subnet["Subnet"]["SubnetId"]

    initial_sg = ec2_client.create_security_group(
        GroupName="web-tier-sg",
        Description="Initial Web SG",
        VpcId=vpc_id,
    )
    initial_sg_id = initial_sg["GroupId"]

    # Launch instance with an EBS block device
    run_res = ec2_client.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet_id,
        SecurityGroupIds=[initial_sg_id],
        BlockDeviceMappings=[
            {
                "DeviceName": "/dev/sda1",
                "Ebs": {
                    "VolumeSize": 20,
                    "DeleteOnTermination": True,
                    "VolumeType": "gp3",
                },
            }
        ],
    )
    instance_id = run_res["Instances"][0]["InstanceId"]

    # Execute isolation
    result = isolate_instance(instance_id, ec2_client=ec2_client, incident_id="INC-TEST01")

    assert result["status"] == "CONTAINED"
    assert result["instance_id"] == instance_id
    assert initial_sg_id in result["previous_sgs"]
    assert len(result["snapshots"]) == 1

    # Verify instance attributes
    inst_desc = ec2_client.describe_instances(InstanceIds=[instance_id])
    inst = inst_desc["Reservations"][0]["Instances"][0]

    # Active SG must be the quarantine SG
    active_sgs = [g["GroupId"] for g in inst["SecurityGroups"]]
    assert active_sgs == [result["quarantine_sg_id"]]

    # Verify tags on instance
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    assert tags["SOAR:QuarantineState"] == "Quarantined"
    assert tags["SOAR:PreQuarantineSG"] == initial_sg_id
    assert tags["SOAR:IncidentId"] == "INC-TEST01"

    # Verify snapshot tags
    snap_desc = ec2_client.describe_snapshots(SnapshotIds=result["snapshots"])
    snap = snap_desc["Snapshots"][0]
    snap_tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
    assert snap_tags["IncidentId"] == "INC-TEST01"
    assert snap_tags["SOAR:ForensicEvidence"] == "True"


@mock_aws
def test_lambda_handler_validation(ec2_client: Any) -> None:
    """Verifies Lambda entry point behavior on missing or invalid parameters."""
    # Missing instance_id
    res = lambda_handler({"detail": {}})
    assert res["statusCode"] == 400
    body = json.loads(res["body"])
    assert "error" in body

    # Non-existent instance_id
    res_nonexistent = lambda_handler({"instance_id": "i-nonexistent999"})
    assert res_nonexistent["statusCode"] == 500
    err_body = json.loads(res_nonexistent["body"])
    assert err_body["status"] == "FAILED"
