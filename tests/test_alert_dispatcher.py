"""Unit Tests for Alert Dispatcher Handler."""

import json
from unittest.mock import MagicMock, patch

from soar_engine.handlers.alert_dispatcher import (
    build_slack_block_kit,
    dispatch_alert,
    lambda_handler,
)


def test_build_slack_block_kit() -> None:
    """Verifies Slack Block Kit payload composition."""
    alert_data = {
        "title": "Unauthorized Admin Role Attached",
        "severity": "CRITICAL",
        "status": "CONTAINED",
        "resource_id": "arn:aws:iam::123456789012:user/bad-actor",
        "mitre_attack": "T1098 - Account Manipulation",
        "action_taken": "Attached emergency DenyAll inline policy",
    }
    payload = build_slack_block_kit(alert_data)

    assert "blocks" in payload
    assert "[CRITICAL]" in payload["text"]

    blocks = payload["blocks"]
    assert len(blocks) >= 5
    assert blocks[0]["type"] == "header"
    assert "CRITICAL" in blocks[0]["text"]["text"]
    assert "T1098" in str(blocks)


def test_dispatch_alert_no_webhook() -> None:
    """Verifies fallback when no webhook URL is configured."""
    alert_data = {
        "title": "Test Local Alert",
        "severity": "LOW",
        "resource_id": "res-123",
    }
    result = dispatch_alert(alert_data, webhook_url=None)
    assert result["success"] is True
    assert result["dispatched"] is False
    assert "logged locally" in result["message"]


@patch("requests.post")
def test_dispatch_alert_webhook_success(mock_post: MagicMock) -> None:
    """Verifies successful alert dispatch to HTTP webhook."""
    mock_post.return_value.status_code = 200
    mock_post.return_value.raise_for_status = MagicMock()

    alert_data = {
        "title": "Test Critical Alert",
        "severity": "CRITICAL",
        "status": "REMEDIATED",
        "resource_id": "i-test999",
    }
    result = dispatch_alert(alert_data, webhook_url="https://hooks.example.com/services/test")

    assert result["success"] is True
    assert result["dispatched"] is True
    assert result["status_code"] == 200
    mock_post.assert_called_once()


@patch("requests.post")
def test_dispatch_alert_webhook_failure(mock_post: MagicMock) -> None:
    """Verifies graceful handling of webhook connectivity failure."""
    import requests

    mock_post.side_effect = requests.RequestException("Connection refused")

    alert_data = {
        "title": "Failed Alert",
        "severity": "HIGH",
        "resource_id": "bucket-xyz",
    }
    result = dispatch_alert(alert_data, webhook_url="https://hooks.example.com/down")

    assert result["success"] is False
    assert result["dispatched"] is False
    assert "Connection refused" in result["error"]


def test_lambda_handler_direct() -> None:
    """Verifies Lambda entry point with direct event structure."""
    event = {
        "title": "Direct Notification",
        "severity": "INFO",
        "resource_id": "res-direct",
    }
    response = lambda_handler(event)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["success"] is True


def test_lambda_handler_eventbridge() -> None:
    """Verifies Lambda entry point with EventBridge detail wrapper."""
    event = {
        "detail-type": "SOAR Alert Trigger",
        "detail": {
            "title": "EventBridge Alert",
            "severity": "HIGH",
            "resource_id": "i-eventbridge",
        },
    }
    response = lambda_handler(event)
    assert response["statusCode"] == 200
