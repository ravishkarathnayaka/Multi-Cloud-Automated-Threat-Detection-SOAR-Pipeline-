"""Atomic Red Team Test: T1530 - Data from Cloud Storage Object (AWS S3)."""

import json
from typing import Any, Dict


def emulate_s3_public_exposure(bucket_name: str = "art-financial-records") -> Dict[str, Any]:
    """Emulates an attacker deleting the S3 Public Access Block configuration."""
    return {
        "technique": "T1530",
        "name": "Cloud Storage Exposure: Delete Public Access Block",
        "eventSource": "s3.amazonaws.com",
        "eventName": "DeletePublicAccessBlock",
        "requestParameters": {"bucketName": bucket_name},
        "emulated": True,
    }


if __name__ == "__main__":
    print(json.dumps(emulate_s3_public_exposure(), indent=2))
