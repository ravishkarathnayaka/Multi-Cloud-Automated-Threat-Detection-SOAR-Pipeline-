"""Multi-Channel SOC Incident Dispatcher (PagerDuty & Discord).

Dispatches standardized incident notifications to on-call security engineers
via PagerDuty Events API v2 and Discord Webhook embeds.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import requests
from soar_engine.utils.aws_client import get_logger

logger = get_logger(__name__)


def dispatch_pagerduty(routing_key: str, alert: Dict[str, Any]) -> bool:
    """Sends a trigger event to PagerDuty Events API v2."""
    url = "https://events.pagerduty.com/v2/enqueue"
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": alert.get("title", "Cloud SOAR Security Alert"),
            "severity": alert.get("severity", "critical").lower(),
            "source": "cloud-soar-engine",
            "custom_details": alert,
        },
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
        return resp.status_code == 202
    except Exception as exc:
        logger.error("PagerDuty dispatch failed: %s", exc)
        return False


def dispatch_discord(webhook_url: str, alert: Dict[str, Any]) -> bool:
    """Dispatches a formatted embed card to Discord."""
    payload = {
        "content": f"🚨 **[SOAR ALERT]** {alert.get('title')}",
        "embeds": [
            {
                "title": alert.get("title"),
                "description": alert.get("summary", "Incident contained by SOAR"),
                "color": 15158332 if alert.get("severity") == "CRITICAL" else 15844367,
                "fields": [
                    {"name": "Status", "value": alert.get("status", "REMEDIATED"), "inline": True},
                    {"name": "Severity", "value": alert.get("severity", "HIGH"), "inline": True},
                    {"name": "Resource", "value": f"`{alert.get('resource_id')}`", "inline": False},
                ],
                "footer": {"text": "Multi-Cloud SOAR Engine v1.0"},
            }
        ],
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=5)
        return resp.status_code in (200, 204)
    except Exception as exc:
        logger.error("Discord dispatch failed: %s", exc)
        return False
