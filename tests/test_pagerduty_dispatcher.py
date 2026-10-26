"""Unit tests for multi-channel incident dispatcher."""

from unittest.mock import MagicMock, patch
from soar_engine.handlers.pagerduty_dispatcher import dispatch_discord, dispatch_pagerduty


@patch("requests.post")
def test_dispatch_pagerduty_success(mock_post: MagicMock):
    mock_post.return_value.status_code = 202
    res = dispatch_pagerduty("key-123", {"title": "Test Incident"})
    assert res is True


@patch("requests.post")
def test_dispatch_discord_success(mock_post: MagicMock):
    mock_post.return_value.status_code = 204
    res = dispatch_discord("https://discord.com/webhook", {"title": "Test Incident"})
    assert res is True
