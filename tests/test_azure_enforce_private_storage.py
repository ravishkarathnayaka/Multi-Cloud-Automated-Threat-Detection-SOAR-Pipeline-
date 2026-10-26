"""Unit tests for Azure Storage private access handler."""

from soar_engine.handlers.azure_enforce_private_storage import enforce_private_storage, handler


def test_enforce_private_storage():
    res = enforce_private_storage("rg-test", "strgtest")
    assert res["allowBlobPublicAccess"] is False
    assert res["status"] == "HARDENED"


def test_azure_storage_handler():
    res = handler({"storageAccountName": "strg1"})
    assert res["statusCode"] == 200
    assert res["result"]["allowBlobPublicAccess"] is False
