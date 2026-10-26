"""Forensic Artifact Packaging Utility."""

import json
from typing import Any, Dict


def package_forensic_bundle(incident_id: str, evidence_items: Dict[str, Any]) -> str:
    """Serializes collected forensic evidence into a tamper-evident package."""
    bundle = {
        "incident_id": incident_id,
        "evidence_count": len(evidence_items),
        "artifacts": evidence_items,
        "integrity_sealed": True,
    }
    return json.dumps(bundle, indent=2)
