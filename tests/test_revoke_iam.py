"""Unit Tests for IAM Revocation Playbook Handler."""

import json
from typing import Any
from moto import mock_aws

from soar_engine.handlers.revoke_iam_session import (
    EMERGENCY_POLICY_NAME,
    extract_iam_target,
    lambda_handler,
    revoke_iam_role,
    revoke_iam_user,
    revoke_identity,
)


def test_extract_iam_target_formats() -> None:
    """Verifies extraction of user/role targets from varied event formats."""
    assert extract_iam_target({"user_name": "compromised-dev"}) == ("user", "compromised-dev")
    assert extract_iam_target({"role_name": "compromised-role"}) == ("role", "compromised-role")

    # CloudTrail requestParameters
    ct_user_event = {"detail": {"requestParameters": {"userName": "escalated-user"}}}
    assert extract_iam_target(ct_user_event) == ("user", "escalated-user")

    ct_role_event = {"detail": {"requestParameters": {"roleName": "escalated-role"}}}
    assert extract_iam_target(ct_role_event) == ("role", "escalated-role")

    # CloudTrail AssumedRole ARN
    ct_assumed_event = {
        "detail": {
            "userIdentity": {
                "type": "AssumedRole",
                "arn": "arn:aws:sts::123456789012:assumed-role/TargetRole/Session123",
            }
        }
    }
    assert extract_iam_target(ct_assumed_event) == ("role", "TargetRole")

    # Missing
    assert extract_iam_target({"detail": {}}) == (None, None)


@mock_aws
def test_revoke_iam_user(iam_client: Any) -> None:
    """Verifies deactivation of access keys and attachment of DenyAll policy to user."""
    user_name = "test-attacker-user"
    iam_client.create_user(UserName=user_name)

    # Create active access key
    key_res = iam_client.create_access_key(UserName=user_name)
    key_id = key_res["AccessKey"]["AccessKeyId"]
    assert key_res["AccessKey"]["Status"] == "Active"

    # Execute revocation
    result = revoke_iam_user(iam_client, user_name)

    assert result["entity_name"] == user_name
    assert key_id in result["deactivated_keys"]

    # Verify key status is now Inactive
    key_list = iam_client.list_access_keys(UserName=user_name)
    assert key_list["AccessKeyMetadata"][0]["Status"] == "Inactive"

    # Verify inline policy is DenyAll
    policy_res = iam_client.get_user_policy(UserName=user_name, PolicyName=EMERGENCY_POLICY_NAME)
    raw_doc = policy_res["PolicyDocument"]
    policy_doc = raw_doc if isinstance(raw_doc, dict) else json.loads(raw_doc)
    assert policy_doc["Statement"][0]["Effect"] == "Deny"
    assert policy_doc["Statement"][0]["Action"] == "*"


@mock_aws
def test_revoke_iam_role(iam_client: Any) -> None:
    """Verifies STS session invalidation policy attachment to role."""
    role_name = "test-compromised-role"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )

    # Execute role revocation
    result = revoke_iam_role(iam_client, role_name)

    assert result["entity_name"] == role_name

    # Verify inline policy has TokenIssueTime revocation
    policy_res = iam_client.get_role_policy(RoleName=role_name, PolicyName=EMERGENCY_POLICY_NAME)
    raw_role_doc = policy_res["PolicyDocument"]
    policy_doc = raw_role_doc if isinstance(raw_role_doc, dict) else json.loads(raw_role_doc)
    stmt = policy_doc["Statement"][0]
    assert stmt["Effect"] == "Deny"
    assert "DateLessThan" in stmt["Condition"]
    assert "aws:TokenIssueTime" in stmt["Condition"]["DateLessThan"]


@mock_aws
def test_revoke_identity_wrapper(iam_client: Any) -> None:
    """Verifies revoke_identity high level wrapper."""
    user_name = "wrapped-user"
    iam_client.create_user(UserName=user_name)

    res = revoke_identity("user", user_name, iam_client=iam_client)
    assert res["status"] == "REMEDIATED"
    assert res["entity_name"] == user_name


@mock_aws
def test_lambda_handler_validation(iam_client: Any) -> None:
    """Verifies Lambda handler input validation and error status codes."""
    res_missing = lambda_handler({"detail": {}})
    assert res_missing["statusCode"] == 400

    res_unknown = lambda_handler({"user_name": "non-existent-user-12345"})
    assert res_unknown["statusCode"] == 500
    body = json.loads(res_unknown["body"])
    assert body["status"] == "FAILED"
