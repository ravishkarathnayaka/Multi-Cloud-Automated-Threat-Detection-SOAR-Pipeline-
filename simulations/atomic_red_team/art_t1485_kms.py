"""Atomic Red Team Test: T1485 - Data Destruction (KMS Key Deletion)."""

import json
from typing import Any, Dict


def emulate_kms_scheduled_deletion(key_id: str = "arn:aws:kms:us-east-1:123456789012:key/art-key") -> Dict[str, Any]:
    """Emulates an attacker scheduling KMS key destruction with 7-day window."""
    return {
        "technique": "T1485",
        "name": "Data Destruction: Schedule KMS Key Deletion",
        "eventSource": "kms.amazonaws.com",
        "eventName": "ScheduleKeyDeletion",
        "requestParameters": {"keyId": key_id, "pendingWindowInDays": 7},
        "emulated": True,
    }


if __name__ == "__main__":
    print(json.dumps(emulate_kms_scheduled_deletion(), indent=2))
