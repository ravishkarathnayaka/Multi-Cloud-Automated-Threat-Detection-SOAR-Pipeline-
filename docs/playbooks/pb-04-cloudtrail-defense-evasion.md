# Incident Response Playbook 04: CloudTrail Defense Evasion Recovery

## Objective
Prevent attackers from blinding telemetry and audit logging across AWS accounts.

## Detection Trigger
- **Sigma Rule**: `aws_cloudtrail_logging_disabled.yml`
- **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable Cloud Logs)

## Automated Containment Procedure
1. Detect `StopLogging` or `DeleteTrail` API calls via EventBridge.
2. Automatically invoke `StartLogging` to resume telemetry ingestion.
3. Lock trail configuration against deletion via SCP or KMS policy.
4. Dispatch P1 incident notification to SOC security on-call.
