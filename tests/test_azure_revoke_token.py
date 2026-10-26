"""Unit tests for Azure Entra ID token revocation."""

from unittest.mock import MagicMock, patch
from soar_engine.handlers.azure_revoke_token import handler, revoke_entra_user_sessions


@patch("requests.post")
def test_revoke_entra_sessions(mock_post: MagicMock):
    mock_post.return_value.status_code = 200
    result = revoke_entra_user_sessions("user@domain.com", "mock_token")
    assert result["revoked"] is True


def test_azure_revoke_handler():
    res = handler({"userPrincipalName": "admin@cloud.com"})
    assert res["statusCode"] == 200
    assert res["status"] == "SESSION_REVOKED"
