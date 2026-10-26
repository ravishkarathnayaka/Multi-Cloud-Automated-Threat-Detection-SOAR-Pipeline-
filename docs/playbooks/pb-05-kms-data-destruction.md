# Incident Response Playbook 05: KMS Data Destruction Prevention

## Objective
Halt ransomware extortion tactics that attempt to schedule KMS cryptographic key deletion.

## Detection Trigger
- **Sigma Rule**: `aws_kms_key_scheduled_deletion.yml`
- **MITRE ATT&CK**: T1485 (Data Destruction)

## Automated Containment Procedure
1. Intercept `ScheduleKeyDeletion` API calls.
2. Immediately invoke `kms:CancelKeyDeletion` to reset the timer.
3. Re-enable cryptographic operations with `kms:EnableKey`.
4. Trigger credential revocation on the calling IAM principal.
