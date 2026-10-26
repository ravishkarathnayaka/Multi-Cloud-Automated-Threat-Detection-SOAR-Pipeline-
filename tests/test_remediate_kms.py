"""Unit tests for KMS key deletion remediation handler."""

from unittest.mock import MagicMock
from soar_engine.handlers.remediate_kms import cancel_key_deletion, extract_key_id


def test_extract_key_id():
    event = {"detail": {"requestParameters": {"keyId": "arn:aws:kms:us-east-1:123:key/abc"}}}
    assert extract_key_id(event) == "arn:aws:kms:us-east-1:123:key/abc"


def test_cancel_key_deletion():
    kms = MagicMock()
    result = cancel_key_deletion(kms, "key-123")
    assert result["status"] == "DELETION_CANCELED"
    kms.cancel_key_deletion.assert_called_once_with(KeyId="key-123")
    kms.enable_key.assert_called_once_with(KeyId="key-123")
