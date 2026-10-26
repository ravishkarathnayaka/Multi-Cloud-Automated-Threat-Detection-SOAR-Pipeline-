"""Unit tests for IP reputation utility."""

from soar_engine.utils.ip_intel import check_ip_reputation


def test_check_ip_reputation_clean():
    res = check_ip_reputation("8.8.8.8")
    assert res["is_threat"] is False
    assert res["category"] == "CLEAN"


def test_check_ip_reputation_malicious():
    res = check_ip_reputation("198.51.100.42")
    assert res["is_threat"] is True
    assert res["threat_score"] == 95
