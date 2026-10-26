"""Unit tests for RDS snapshot quarantine handler."""

from unittest.mock import MagicMock
from soar_engine.handlers.quarantine_rds import extract_snapshot_id, revoke_snapshot_public_access


def test_extract_snapshot_id():
    event = {"detail": {"requestParameters": {"dBSnapshotIdentifier": "prod-db-snap"}}}
    assert extract_snapshot_id(event) == "prod-db-snap"


def test_revoke_snapshot_public_access():
    rds = MagicMock()
    result = revoke_snapshot_public_access(rds, "snap-01")
    assert result["public_access_revoked"] is True
    rds.modify_db_snapshot_attribute.assert_called_once()
