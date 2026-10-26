# Incident Response Playbook 06: RDS Database Leakage Containment

## Objective
Prevent unauthorized external exposure of relational database backups.

## Detection Trigger
- **Sigma Rule**: `aws_rds_snapshot_publicly_shared.yml`
- **MITRE ATT&CK**: T1530 / T1537 (Transfer Data to Cloud Account)

## Automated Containment Procedure
1. Parse `ModifyDBSnapshotAttribute` events.
2. Verify if `ValuesToAdd` contains `all` or unapproved AWS account IDs.
3. Call `modify_db_snapshot_attribute` with `ValuesToRemove: ['all']`.
4. Restore private access controls and notify DBA team.
