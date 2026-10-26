"""Unit tests for Secrets Manager rotation handler."""

from unittest.mock import MagicMock
from soar_engine.handlers.remediate_secrets import extract_secret_id, force_secret_rotation


def test_extract_secret_id():
    event = {"detail": {"requestParameters": {"secretId": "prod/api/stripe"}}}
    assert extract_secret_id(event) == "prod/api/stripe"


def test_force_secret_rotation():
    sm = MagicMock()
    sm.rotate_secret.return_value = {"VersionId": "v2"}
    result = force_secret_rotation(sm, "sec-1")
    assert result["rotated"] is True
    assert result["version_id"] == "v2"
