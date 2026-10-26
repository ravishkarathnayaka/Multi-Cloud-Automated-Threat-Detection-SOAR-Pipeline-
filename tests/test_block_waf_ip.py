"""Unit tests for WAF IP blocking handler."""

from unittest.mock import MagicMock
from soar_engine.handlers.block_waf_ip import block_ip_in_waf, lambda_handler


def test_block_ip_in_waf():
    waf = MagicMock()
    result = block_ip_in_waf(waf, "set-1", "WAF-Block", "REGIONAL", "1.2.3.4", "lock-01")
    assert result["blocked"] is True
    assert result["ip"] == "1.2.3.4/32"


def test_lambda_handler_waf():
    res = lambda_handler({"ip_address": "10.0.0.1"})
    assert res["statusCode"] == 200
    assert res["status"] == "IP_BLOCKED"
