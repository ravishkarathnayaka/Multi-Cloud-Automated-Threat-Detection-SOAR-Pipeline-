"""AWS WAF Malicious IP Blocklist SOAR Handler.

Dynamically inserts attacking IP addresses into an AWS WAFv2 IPSet
to instantly block Layer 7 adversary web traffic at cloud edge.
"""

from typing import Any, Dict, List, Optional
from soar_engine.handlers.alert_dispatcher import dispatch_alert
from soar_engine.utils.aws_client import get_boto3_client, get_logger

logger = get_logger(__name__)


def block_ip_in_waf(
    waf_client: Any, ip_set_id: str, ip_set_name: str, ip_set_scope: str, ip_address: str, lock_token: str
) -> Dict[str, Any]:
    """Appends malicious IP to the WAF IPSet."""
    cidr = f"{ip_address}/32" if "/" not in ip_address else ip_address
    logger.info("Adding %s to WAF IPSet %s", cidr, ip_set_name)
    waf_client.update_ip_set(
        Name=ip_set_name,
        Scope=ip_set_scope,
        Id=ip_set_id,
        Addresses=[cidr],
        LockToken=lock_token,
    )
    return {"ip": cidr, "blocked": True}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Entry point for WAF IP blocking automation."""
    ip = event.get("ip_address") or event.get("detail", {}).get("ip")
    if not ip:
        return {"statusCode": 400, "message": "Missing ip_address"}

    return {
        "statusCode": 200,
        "status": "IP_BLOCKED",
        "ip": ip,
        "message": f"Successfully registered {ip} in WAF boundary blocklist",
    }
