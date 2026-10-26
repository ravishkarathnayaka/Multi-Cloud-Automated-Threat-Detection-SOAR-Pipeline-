"""Unit tests for GCP Service Account key disabling handler."""

from soar_engine.handlers.gcp_disable_sa_key import disable_service_account_key, handler


def test_disable_sa_key():
    res = disable_service_account_key("sa@proj.iam.gserviceaccount.com", "key-123")
    assert res["status"] == "DISABLED"
    assert res["remediated"] is True


def test_gcp_key_handler():
    res = handler({"keyId": "k-1"})
    assert res["statusCode"] == 200
