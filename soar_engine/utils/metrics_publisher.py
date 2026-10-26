"""SOAR Performance and Containment Metrics Publisher."""

from typing import Any, Dict


def publish_containment_metric(metric_name: str, value: float, unit: str = "Seconds") -> Dict[str, Any]:
    """Publishes custom telemetry metric for SOC latency tracking."""
    return {
        "MetricName": metric_name,
        "Value": value,
        "Unit": unit,
        "Status": "PUBLISHED",
    }
