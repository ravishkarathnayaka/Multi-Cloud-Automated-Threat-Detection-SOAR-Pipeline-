"""Atomic Red Team Test: T1496 - Resource Hijacking: Cryptomining."""

import json
from typing import Any, Dict


def emulate_cryptomining_finding(instance_id: str = "i-0987654321fedcba0") -> Dict[str, Any]:
    """Generates synthetic GuardDuty Bitcoin mining alert payload."""
    return {
        "technique": "T1496",
        "name": "Resource Hijacking: BitcoinTool Mining Workload",
        "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "severity": 8.5,
        "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": instance_id}},
        "emulated": True,
    }


if __name__ == "__main__":
    print(json.dumps(emulate_cryptomining_finding(), indent=2))
