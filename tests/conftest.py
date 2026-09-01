"""Pytest Configuration and Moto Fixtures for SOAR Engine Tests."""

import os
from typing import Generator
import boto3
from moto import mock_aws
import pytest


@pytest.fixture(autouse=True)
def aws_credentials() -> None:
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ.pop("LOCALSTACK_ENDPOINT_URL", None)
    os.environ.pop("AWS_ENDPOINT_URL", None)
    os.environ.pop("ALERT_WEBHOOK_URL", None)


@pytest.fixture
def ec2_client(aws_credentials: None) -> Generator[boto3.client, None, None]:
    """Yields a mocked Boto3 EC2 client."""
    with mock_aws():
        client = boto3.client("ec2", region_name="us-east-1")
        yield client


@pytest.fixture
def iam_client(aws_credentials: None) -> Generator[boto3.client, None, None]:
    """Yields a mocked Boto3 IAM client."""
    with mock_aws():
        client = boto3.client("iam", region_name="us-east-1")
        yield client


@pytest.fixture
def s3_client(aws_credentials: None) -> Generator[boto3.client, None, None]:
    """Yields a mocked Boto3 S3 client."""
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        yield client
