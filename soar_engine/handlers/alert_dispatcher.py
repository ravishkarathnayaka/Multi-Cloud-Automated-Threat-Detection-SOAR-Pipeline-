"""Alert Dispatcher Handler.

Formats and dispatches enriched security alerts to external incident response
channels (Slack Webhook, Microsoft Teams, or Generic HTTP Webhook).
"""

from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, Optional

import requests
from botocore.exceptions import BotoCoreError

from soar_engine.utils.aws_client import get_logger

logger = get_logger(__name__)


def build_slack_block_kit(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Constructs a Slack Block Kit formatted message payload.

    Args:
        alert_data: Standardized alert metadata.

    Returns:
        Slack payload dictionary with blocks.
    """
    severity = alert_data.get("severity", "MEDIUM").upper()
    status = alert_data.get("status", "NOTIFIED").upper()

    severity_emojis = {
        "CRITICAL": "🚨",
        "HIGH": "🔥",
        "MEDIUM": "⚠️",
        "LOW": "ℹ️",
    }
    status_emojis = {
        "CONTAINED": "🛡️",
        "REMEDIATED": "✅",
        "FAILED": "❌",
        "ALERT": "🔔",
    }

    s_emoji = severity_emojis.get(severity, "⚠️")
    st_emoji = status_emojis.get(status, "🔔")

    title = alert_data.get("title", "SOAR Automated Security Alert")
    summary = alert_data.get("summary", "An automated threat detection event was processed.")
    resource_id = alert_data.get("resource_id", "Unknown Resource")
    mitre_attack = alert_data.get("mitre_attack", "N/A")
    action_taken = alert_data.get("action_taken", "None")
    timestamp = alert_data.get("timestamp", datetime.now(timezone.utc).isoformat())

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{s_emoji} [{severity}] {title}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{summary}*",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Status:*\n{st_emoji} {status}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n`{severity}`"},
                {"type": "mrkdwn", "text": f"*Resource:*\n`{resource_id}`"},
                {"type": "mrkdwn", "text": f"*MITRE ATT&CK:*\n{mitre_attack}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Remediation Action Executed:*\n```{action_taken}```",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🕒 *Triggered:* {timestamp} | *SOAR Engine Pipeline v1.0*",
                }
            ],
        },
    ]

    return {"blocks": blocks, "text": f"[{severity}] {title}"}


def dispatch_alert(alert_data: Dict[str, Any], webhook_url: Optional[str] = None) -> Dict[str, Any]:
    """Dispatches formatted alert to configured webhook destination.

    Args:
        alert_data: Standardized alert metadata dictionary.
        webhook_url: Optional override destination URL.

    Returns:
        Result summary dict.
    """
    target_url = webhook_url or os.environ.get("ALERT_WEBHOOK_URL")

    if not alert_data.get("timestamp"):
        alert_data["timestamp"] = datetime.now(timezone.utc).isoformat()

    slack_payload = build_slack_block_kit(alert_data)

    logger.info(
        "Preparing alert dispatch",
        extra={
            "extra_fields": {
                "alert_title": alert_data.get("title"),
                "severity": alert_data.get("severity"),
                "resource_id": alert_data.get("resource_id"),
                "status": alert_data.get("status"),
                "has_webhook": bool(target_url),
            }
        },
    )

    if not target_url:
        logger.info(
            "No ALERT_WEBHOOK_URL configured. Emitting structured alert to standard output only.",
            extra={"extra_fields": {"raw_alert": alert_data}},
        )
        return {
            "success": True,
            "dispatched": False,
            "message": "Webhook URL not configured; logged locally.",
            "alert": alert_data,
        }

    try:
        response = requests.post(
            target_url,
            json=slack_payload,
            headers={"Content-Type": "application/json"},
            timeout=5.0,
        )
        response.raise_for_status()

        logger.info(
            "Alert successfully dispatched to webhook destination",
            extra={"extra_fields": {"status_code": response.status_code}},
        )
        return {
            "success": True,
            "dispatched": True,
            "status_code": response.status_code,
            "alert": alert_data,
        }

    except requests.RequestException as exc:
        logger.error(
            f"Failed to post alert to webhook endpoint: {exc}",
            extra={"extra_fields": {"target_url": target_url, "error": str(exc)}},
        )
        return {
            "success": False,
            "dispatched": False,
            "error": str(exc),
            "alert": alert_data,
        }


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda entry point for Alert Dispatcher.

    Args:
        event: EventBridge detail payload or direct invocation dictionary.
        context: Lambda execution context.

    Returns:
        JSON response structure with statusCode and response body.
    """
    logger.info("Received alert dispatcher event", extra={"extra_fields": {"event_keys": list(event.keys())}})

    try:
        # Check if event is from EventBridge or direct dictionary
        alert_payload = event.get("detail", event)
        if not isinstance(alert_payload, dict):
            alert_payload = {"raw_payload": event}

        result = dispatch_alert(alert_payload)

        return {
            "statusCode": 200 if result.get("success") else 502,
            "body": json.dumps(result),
        }

    except (BotoCoreError, Exception) as exc:
        logger.exception(f"Unhandled exception in alert_dispatcher: {exc}")
        return {
            "statusCode": 500,
            "body": json.dumps({"success": False, "error": str(exc)}),
        }
