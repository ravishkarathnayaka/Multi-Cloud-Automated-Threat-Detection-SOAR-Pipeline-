"""Atomic Red Team Test: T1098 - Account Manipulation (AWS IAM)."""

import json
from typing import Any, Dict


def emulate_iam_privilege_escalation(user_name: str = "art-adversary-sim") -> Dict[str, Any]:
    """Emulates an attacker attaching AdministratorAccess to a compromised user."""
    return {
        "technique": "T1098",
        "name": "Account Manipulation: IAM Policy Attachment",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "requestParameters": {
            "userName": user_name,
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        "emulated": True,
    }


if __name__ == "__main__":
    print(json.dumps(emulate_iam_privilege_escalation(), indent=2))
