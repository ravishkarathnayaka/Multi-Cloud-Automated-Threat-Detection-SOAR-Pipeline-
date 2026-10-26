"""Unit tests for NACL egress blocking handler."""

from unittest.mock import MagicMock
from soar_engine.handlers.block_nacl_egress import insert_nacl_deny_rule, lambda_handler


def test_insert_nacl_deny_rule():
    ec2 = MagicMock()
    result = insert_nacl_deny_rule(ec2, "acl-123", 1, "0.0.0.0/0")
    assert result["action"] == "deny"
    assert result["nacl_id"] == "acl-123"
    ec2.create_network_acl_entry.assert_called_once()


def test_nacl_lambda_handler():
    res = lambda_handler({"nacl_id": "acl-test"})
    assert res["statusCode"] == 200
    assert res["status"] == "EGRESS_SEVERED"
