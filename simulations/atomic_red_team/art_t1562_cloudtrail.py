"""Atomic Red Team Test: T1562.001 - Impair Defenses: Disable CloudTrail."""

import json
from typing import Any, Dict


def emulate_cloudtrail_stop_logging(trail_name: str = "art-org-trail") -> Dict[str, Any]:
    """Emulates an attacker invoking StopLogging on multi-region CloudTrail."""
    return {
        "technique": "T1562.001",
        "name": "Defense Evasion: Stop CloudTrail Logging",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "requestParameters": {"name": trail_name},
        "emulated": True,
    }


if __name__ == "__main__":
    print(json.dumps(emulate_cloudtrail_stop_logging(), indent=2))
