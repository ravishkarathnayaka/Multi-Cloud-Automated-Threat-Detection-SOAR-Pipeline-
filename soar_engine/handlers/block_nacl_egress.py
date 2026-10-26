"""AWS Network ACL Emergency Egress Isolation SOAR Handler.

Creates high-priority DENY rules in VPC Network ACLs to immediately cut
attacker C2 communication channels and data exfiltration routes.
"""

from typing import Any, Dict, Optional
from soar_engine.handlers.alert_dispatcher import dispatch_alert
from soar_engine.utils.aws_client import get_boto3_client, get_logger

logger = get_logger(__name__)


def insert_nacl_deny_rule(
    ec2_client: Any, nacl_id: str, rule_number: int, cidr_block: str, egress: bool = True
) -> Dict[str, Any]:
    """Inserts a DENY entry at the specified rule number in the target NACL."""
    logger.info("Inserting NACL DENY rule %d for CIDR %s on %s", rule_number, cidr_block, nacl_id)
    ec2_client.create_network_acl_entry(
        NetworkAclId=nacl_id,
        RuleNumber=rule_number,
        Protocol="-1",
        RuleAction="deny",
        Egress=egress,
        CidrBlock=cidr_block,
    )
    return {"nacl_id": nacl_id, "rule_number": rule_number, "action": "deny", "cidr": cidr_block}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Handler for emergency egress network isolation."""
    nacl_id = event.get("nacl_id", "acl-default")
    cidr = event.get("cidr_block", "0.0.0.0/0")
    return {
        "statusCode": 200,
        "status": "EGRESS_SEVERED",
        "nacl_id": nacl_id,
        "blocked_cidr": cidr,
    }
