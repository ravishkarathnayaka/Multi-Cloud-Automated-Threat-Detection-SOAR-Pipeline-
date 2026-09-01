"""Unit Tests for S3 Remediation Playbook Handler."""

import json
from typing import Any
from moto import mock_aws
import pytest

from soar_engine.handlers.remediate_s3 import (
    enforce_public_access_block,
    extract_bucket_name,
    lambda_handler,
    remediate_bucket,
    sanitize_bucket_policy,
)


def test_extract_bucket_name_formats() -> None:
    """Verifies bucket name parsing across multiple event representations."""
    assert extract_bucket_name({"bucket_name": "my-secure-bucket"}) == "my-secure-bucket"
    assert extract_bucket_name({"detail": {"bucket_name": "sub-bucket"}}) == "sub-bucket"
    assert extract_bucket_name({"detail": {"bucket": "direct-bucket"}}) == "direct-bucket"

    # CloudTrail requestParameters
    ct_event = {"detail": {"requestParameters": {"bucketName": "trail-bucket"}}}
    assert extract_bucket_name(ct_event) == "trail-bucket"

    # CloudTrail resources ARN
    ct_arn_event = {
        "detail": {
            "resources": [
                {
                    "type": "AWS::S3::Bucket",
                    "ARN": "arn:aws:s3:::arn-extracted-bucket",
                }
            ]
        }
    }
    assert extract_bucket_name(ct_arn_event) == "arn-extracted-bucket"

    # Missing
    assert extract_bucket_name({"detail": {}}) is None


@mock_aws
def test_enforce_public_access_block(s3_client: Any) -> None:
    """Verifies that all 4 Public Access Block settings are enabled."""
    bucket_name = "test-pab-bucket"
    s3_client.create_bucket(Bucket=bucket_name)

    res = enforce_public_access_block(s3_client, bucket_name)
    assert res["BlockPublicAcls"] is True
    assert res["IgnorePublicAcls"] is True
    assert res["BlockPublicPolicy"] is True
    assert res["RestrictPublicBuckets"] is True

    # Verify via API
    pab = s3_client.get_public_access_block(Bucket=bucket_name)
    config = pab["PublicAccessBlockConfiguration"]
    assert config["BlockPublicAcls"] is True
    assert config["BlockPublicPolicy"] is True


@mock_aws
def test_sanitize_public_bucket_policy(s3_client: Any) -> None:
    """Verifies removal of public wildcard bucket policies."""
    bucket_name = "test-public-policy-bucket"
    s3_client.create_bucket(Bucket=bucket_name)

    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
        ],
    }
    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))

    action = sanitize_bucket_policy(s3_client, bucket_name)
    assert action is not None

    # Check policy was removed
    with pytest.raises(Exception):
        s3_client.get_bucket_policy(Bucket=bucket_name)


@mock_aws
def test_remediate_bucket_end_to_end(s3_client: Any) -> None:
    """Verifies end-to-end bucket remediation and tagging."""
    bucket_name = "test-e2e-exposed-bucket"
    s3_client.create_bucket(Bucket=bucket_name)

    result = remediate_bucket(bucket_name, s3_client=s3_client)
    assert result["status"] == "REMEDIATED"
    assert result["bucket_name"] == bucket_name

    # Check tags
    tags_res = s3_client.get_bucket_tagging(Bucket=bucket_name)
    tag_map = {t["Key"]: t["Value"] for t in tags_res["TagSet"]}
    assert tag_map["SOAR:PublicAccessRemediated"] == "True"
    assert tag_map["SOAR:Compliance"] == "StrictPrivate"


@mock_aws
def test_lambda_handler_validation(s3_client: Any) -> None:
    """Verifies Lambda entry point behavior on missing or invalid bucket."""
    res_missing = lambda_handler({"detail": {}})
    assert res_missing["statusCode"] == 400

    res_nonexistent = lambda_handler({"bucket_name": "non-existent-bucket-9999"})
    assert res_nonexistent["statusCode"] == 500
    body = json.loads(res_nonexistent["body"])
    assert body["status"] == "FAILED"
