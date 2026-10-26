"""Unit tests for GCP Storage remediation handler."""

from soar_engine.handlers.gcp_remediate_storage import handler, remediate_gcp_bucket


def test_remediate_gcp_bucket():
    res = remediate_gcp_bucket("bucket-public")
    assert res["uniform_bucket_level_access"] is True
    assert res["status"] == "REMEDIATED"


def test_gcp_storage_handler():
    res = handler({"bucketName": "b-test"})
    assert res["statusCode"] == 200
