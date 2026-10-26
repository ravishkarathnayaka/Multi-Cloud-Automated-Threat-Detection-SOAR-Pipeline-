"""Unit tests for session token validator."""

from soar_engine.utils.token_validator import inspect_session_token


def test_inspect_session_token_valid():
    res = inspect_session_token("ASIAABCDEFGHIJKLMNOP123456")
    assert res["is_valid"] is True
    assert res["is_expired"] is False


def test_inspect_session_token_invalid():
    res = inspect_session_token("short")
    assert res["is_valid"] is False
    assert res["is_expired"] is True
