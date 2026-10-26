"""Atomic Red Team Test: T1555 - Credentials from Password Stores."""

import json
from typing import Any, Dict


def emulate_secrets_manager_dump(secret_id: str = "art/db/master_password") -> Dict[str, Any]:
    """Emulates high-volume GetSecretValue exfiltration."""
    return {
        "technique": "T1555",
        "name": "Credential Access: Secrets Manager Harvesting",
        "eventSource": "secretsmanager.amazonaws.com",
        "eventName": "GetSecretValue",
        "requestParameters": {"secretId": secret_id},
        "emulated": True,
    }


if __name__ == "__main__":
    print(json.dumps(emulate_secrets_manager_dump(), indent=2))
