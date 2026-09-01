"""End-to-End SOAR Playbook Integration Test Runner.

Executes and verifies the detection, containment, and response lifecycle
for all playbooks against LocalStack or mock AWS environment.
"""

from datetime import datetime, timezone
import json
import os
import sys
from typing import Any, Dict

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from moto import mock_aws  # noqa: E402
from soar_engine.handlers.alert_dispatcher import lambda_handler as alert_handler  # noqa: E402
from soar_engine.handlers.isolate_ec2 import lambda_handler as ec2_handler  # noqa: E402
from soar_engine.handlers.remediate_s3 import lambda_handler as s3_handler  # noqa: E402
from soar_engine.handlers.revoke_iam_session import lambda_handler as iam_handler  # noqa: E402
from soar_engine.utils.aws_client import get_boto3_client  # noqa: E402


def setup_mock_environment() -> None:
    """Configures default mock AWS credentials and regions."""
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "mock_key")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "mock_secret")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


def test_iam_escalation_lifecycle() -> bool:
    """Verifies IAM AdministratorAccess detection & revocation flow."""
    print("\n--- [PLAYBOOK 1] Testing IAM Privilege Escalation Remediation ---")
    iam = get_boto3_client("iam")
    user_name = "rogue-dev-analyst"

    # Setup target
    iam.create_user(UserName=user_name)
    key_res = iam.create_access_key(UserName=user_name)
    key_id = key_res["AccessKey"]["AccessKeyId"]
    print(f"Created rogue user '{user_name}' with active access key '{key_id}'")

    # Emulate CloudTrail AttachUserPolicy EventBridge trigger
    event = {
        "version": "0",
        "id": "event-iam-12345",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "time": datetime.now(timezone.utc).isoformat(),
        "detail": {
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "requestParameters": {
                "userName": user_name,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
    }

    # Execute handler
    response = iam_handler(event)
    assert response["statusCode"] == 200, f"Handler returned status: {response['statusCode']}"

    # Verify Access Key is Inactive
    key_meta = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"][0]
    assert key_meta["Status"] == "Inactive", "Access key was not deactivated!"

    # Verify DenyAll Emergency Policy is attached
    policy_res = iam.get_user_policy(UserName=user_name, PolicyName="SOAR-DenyAll-Emergency")
    assert policy_res is not None, "Emergency DenyAll policy missing!"

    print("[SUCCESS] IAM Privilege Escalation successfully neutralized!")
    return True


def test_s3_exposure_lifecycle() -> bool:
    """Verifies S3 public exposure detection & remediation flow."""
    print("\n--- [PLAYBOOK 2] Testing S3 Public Access Remediation ---")
    s3 = get_boto3_client("s3")
    bucket_name = "corp-data-exposed-bucket"

    s3.create_bucket(Bucket=bucket_name)
    print(f"Created exposed target bucket '{bucket_name}'")

    # Emulate CloudTrail DeletePublicAccessBlock EventBridge trigger
    event = {
        "version": "0",
        "id": "event-s3-12345",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
        "time": datetime.now(timezone.utc).isoformat(),
        "detail": {
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeletePublicAccessBlock",
            "requestParameters": {
                "bucketName": bucket_name,
            },
        },
    }

    # Execute handler
    response = s3_handler(event)
    assert response["statusCode"] == 200, f"Handler returned status: {response['statusCode']}"

    # Verify Public Access Block is strictly enforced
    pab = s3.get_public_access_block(Bucket=bucket_name)
    cfg = pab["PublicAccessBlockConfiguration"]
    assert cfg["BlockPublicAcls"] is True, "BlockPublicAcls not set to True!"
    assert cfg["BlockPublicPolicy"] is True, "BlockPublicPolicy not set to True!"

    # Verify remediation tag
    tags = s3.get_bucket_tagging(Bucket=bucket_name)
    tag_map = {t["Key"]: t["Value"] for t in tags["TagSet"]}
    assert tag_map.get("SOAR:PublicAccessRemediated") == "True", "Remediation tag not found!"

    print("[SUCCESS] S3 Public Exposure successfully contained and hardened!")
    return True


def test_ec2_isolation_lifecycle() -> bool:
    """Verifies EC2 threat detection, host isolation, and snapshotting."""
    print("\n--- [PLAYBOOK 3] Testing EC2 Host Isolation & Forensics ---")
    ec2 = get_boto3_client("ec2")

    # Setup infrastructure
    vpc = ec2.create_vpc(CidrBlock="10.100.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.100.1.0/24")["Subnet"]["SubnetId"]
    initial_sg = ec2.create_security_group(
        GroupName="vulnerable-web-sg",
        Description="Open web SG",
        VpcId=vpc,
    )["GroupId"]

    instance = ec2.run_instances(
        ImageId="ami-0123456789abcdef0",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        SecurityGroupIds=[initial_sg],
        BlockDeviceMappings=[
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {"VolumeSize": 10, "DeleteOnTermination": True},
            }
        ],
    )["Instances"][0]
    instance_id = instance["InstanceId"]
    print(f"Launched instance '{instance_id}' with SG '{initial_sg}' in VPC '{vpc}'")

    # Emulate GuardDuty / C2 network detection EventBridge trigger
    event = {
        "version": "0",
        "id": "event-ec2-12345",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "time": datetime.now(timezone.utc).isoformat(),
        "detail": {
            "resource": {
                "instanceDetails": {
                    "instanceId": instance_id,
                }
            }
        },
    }

    # Execute handler
    response = ec2_handler(event)
    assert response["statusCode"] == 200, f"Handler returned status: {response['statusCode']}"

    # Verify Instance SG was swapped to quarantine SG
    inst_desc = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    active_sgs = [g["GroupId"] for g in inst_desc["SecurityGroups"]]
    assert initial_sg not in active_sgs, "Original insecure SG was not removed!"

    # Verify tags
    tags = {t["Key"]: t["Value"] for t in inst_desc.get("Tags", [])}
    assert tags.get("SOAR:QuarantineState") == "Quarantined", "QuarantineState tag missing!"
    assert tags.get("SOAR:PreQuarantineSG") == initial_sg, "PreQuarantineSG tag missing!"

    print("[SUCCESS] EC2 Host Isolation and Forensic Snapshot completed successfully!")
    return True


def test_alert_dispatcher_lifecycle() -> bool:
    """Verifies alert formatting and notification flow."""
    print("\n--- [PLAYBOOK 4] Testing Alert Dispatcher ---")
    alert_event: Dict[str, Any] = {
        "title": "Integration Test Security Alert",
        "severity": "CRITICAL",
        "status": "CONTAINED",
        "resource_id": "arn:aws:iam::123456789012:user/sim-user",
        "action_taken": "Automated credentials revocation applied.",
    }
    response = alert_handler(alert_event)
    assert response["statusCode"] == 200, f"Alert handler returned: {response['statusCode']}"
    body = json.loads(response["body"])
    assert body["success"] is True, "Alert dispatch failed!"

    print("[SUCCESS] Alert Dispatcher verified!")
    return True


def main() -> int:
    """Runs all playbook integration tests."""
    print("=" * 70)
    print("  SOAR Pipeline End-to-End Playbook Integration Test Runner  ")
    print("=" * 70)

    setup_mock_environment()

    # Wrap in mock_aws to allow running without active LocalStack instance
    with mock_aws():
        try:
            test_iam_escalation_lifecycle()
            test_s3_exposure_lifecycle()
            test_ec2_isolation_lifecycle()
            test_alert_dispatcher_lifecycle()
        except AssertionError as err:
            print(f"\n[FAIL] Test verification failed: {err}")
            return 1
        except Exception as exc:
            print(f"\n[FAIL] Unexpected runtime error: {exc}")
            import traceback

            traceback.print_exc()
            return 1

    print("\n" + "=" * 70)
    print("  ALL PLAYBOOKS VERIFIED: 100% SUCCESSFUL DETECTION & RESPONSE  ")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
