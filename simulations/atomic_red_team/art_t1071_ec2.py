"""Atomic Red Team Test: T1071 - Application Layer Protocol (EC2 C2 Ingress)."""

import json
from typing import Any, Dict


def emulate_ec2_c2_ingress(security_group_id: str = "sg-0123456789abcdef0") -> Dict[str, Any]:
    """Emulates an attacker authorizing 0.0.0.0/0 ingress to an EC2 instance."""
    return {
        "technique": "T1071",
        "name": "C2 Ingress: Authorize Security Group Rule",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "requestParameters": {
            "groupId": security_group_id,
            "ipPermissions": [{"ipProtocol": "tcp", "fromPort": 4444, "toPort": 4444, "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}],
        },
        "emulated": True,
    }


if __name__ == "__main__":
    print(json.dumps(emulate_ec2_c2_ingress(), indent=2))
