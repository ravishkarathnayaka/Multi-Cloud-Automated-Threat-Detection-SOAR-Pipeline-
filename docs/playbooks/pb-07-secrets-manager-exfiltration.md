# Incident Response Playbook 07: Secrets Manager Compromise Rotation

## Objective
Minimize blast radius when database passwords or API keys are exfiltrated.

## Detection Trigger
- **Sigma Rule**: `aws_secretsmanager_bulk_retrieval.yml`
- **MITRE ATT&CK**: T1555 (Credentials from Password Stores)

## Automated Containment Procedure
1. Correlate anomalous frequency of `GetSecretValue` calls.
2. Trigger automated rotation lambda via `rotate_secret`.
3. Invalidate previous secret version credentials.
4. Notify affected application engineering teams.
