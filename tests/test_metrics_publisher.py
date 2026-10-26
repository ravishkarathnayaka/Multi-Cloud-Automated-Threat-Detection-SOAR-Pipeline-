"""Unit tests for metrics publisher."""

from soar_engine.utils.metrics_publisher import publish_containment_metric


def test_publish_containment_metric():
    res = publish_containment_metric("ContainmentLatency", 2.1)
    assert res["MetricName"] == "ContainmentLatency"
    assert res["Value"] == 2.1
    assert res["Status"] == "PUBLISHED"
