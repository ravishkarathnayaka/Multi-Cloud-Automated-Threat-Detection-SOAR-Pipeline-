# CloudWatch Alarms for SOAR Execution Telemetry

resource "aws_cloudwatch_metric_alarm" "soar_containment_latency" {
  alarm_name          = "soar-containment-latency-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ContainmentLatency"
  namespace           = "Security/SOAR"
  period              = 60
  statistic           = "Average"
  threshold           = 5.0
  alarm_description   = "Triggered when automated containment takes longer than 5 seconds"
}
