"""Unit tests for forensic artifact packager."""

import json
from soar_engine.utils.forensic_bundle import package_forensic_bundle


def test_package_forensic_bundle():
    bundle_str = package_forensic_bundle("INC-101", {"log": "threat_event"})
    parsed = json.loads(bundle_str)
    assert parsed["incident_id"] == "INC-101"
    assert parsed["integrity_sealed"] is True
