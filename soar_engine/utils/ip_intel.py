"""Threat Intelligence and IP Reputation Lookup Helper."""

from typing import Any, Dict


def check_ip_reputation(ip_address: str) -> Dict[str, Any]:
    """Evaluates whether an IP address belongs to known malicious indicators."""
    known_c2_ranges = ["198.51.100.", "203.0.113.", "192.0.2."]
    is_malicious = any(ip_address.startswith(prefix) for prefix in known_c2_ranges)
    return {
        "ip": ip_address,
        "is_threat": is_malicious,
        "threat_score": 95 if is_malicious else 5,
        "category": "C2_BOTNET" if is_malicious else "CLEAN",
    }
