"""Resilient AWS Boto3 Client Wrapper and Structured JSON Logger.

Supports seamless switching between live AWS environments and LocalStack
for local emulation and testing.
"""

from datetime import datetime, timezone
import json
import logging
import os
import sys
from typing import Any, Dict, Optional

import boto3
from botocore.config import Config


class JsonFormatter(logging.Formatter):
    """Custom logging formatter that outputs log records as structured JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include custom attributes if passed via extra
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_payload.update(record.extra_fields)

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload)


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """Creates or retrieves a logger configured with structured JSON formatting.

    Args:
        name: Name of the logger, typically __name__.
        level: Optional log level (defaults to INFO or LOG_LEVEL env var).

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)

    log_level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    effective_level = level if level is not None else getattr(logging, log_level_name, logging.INFO)
    logger.setLevel(effective_level)
    logger.propagate = False

    return logger


def get_endpoint_url() -> Optional[str]:
    """Resolves the AWS endpoint URL for LocalStack or custom endpoints.

    Checks LOCALSTACK_ENDPOINT_URL first, then AWS_ENDPOINT_URL.
    Returns None when communicating with real AWS services.
    """
    return os.environ.get("LOCALSTACK_ENDPOINT_URL") or os.environ.get("AWS_ENDPOINT_URL") or None


def get_default_region() -> str:
    """Returns the default configured AWS region."""
    return os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"


def get_boto3_client(
    service_name: str,
    region_name: Optional[str] = None,
    max_retries: int = 3,
) -> Any:
    """Instantiates a resilient Boto3 client with retry logic and LocalStack support.

    Args:
        service_name: AWS service identifier (e.g., 'ec2', 's3', 'iam', 'sts').
        region_name: AWS region string. If None, defaults to environment region.
        max_retries: Number of standard exponential backoff retries.

    Returns:
        boto3.client instance.
    """
    endpoint_url = get_endpoint_url()
    region = region_name or get_default_region()

    client_config = Config(
        retries={
            "max_attempts": max_retries,
            "mode": "standard",
        }
    )

    client_kwargs: Dict[str, Any] = {
        "service_name": service_name,
        "region_name": region,
        "config": client_config,
    }

    if endpoint_url:
        client_kwargs["endpoint_url"] = endpoint_url

    return boto3.client(**client_kwargs)


def get_boto3_resource(
    service_name: str,
    region_name: Optional[str] = None,
    max_retries: int = 3,
) -> Any:
    """Instantiates a resilient Boto3 resource with retry logic and LocalStack support.

    Args:
        service_name: AWS service identifier (e.g., 'ec2', 's3', 'iam').
        region_name: AWS region string. If None, defaults to environment region.
        max_retries: Number of standard exponential backoff retries.

    Returns:
        boto3.resource instance.
    """
    endpoint_url = get_endpoint_url()
    region = region_name or get_default_region()

    resource_config = Config(
        retries={
            "max_attempts": max_retries,
            "mode": "standard",
        }
    )

    resource_kwargs: Dict[str, Any] = {
        "service_name": service_name,
        "region_name": region,
        "config": resource_config,
    }

    if endpoint_url:
        resource_kwargs["endpoint_url"] = endpoint_url

    return boto3.resource(**resource_kwargs)
