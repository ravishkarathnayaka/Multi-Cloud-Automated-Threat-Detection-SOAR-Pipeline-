# Incident Response Playbook 08: Cryptomining Workload Termination

## Objective
Halt unauthorized cloud computing resource consumption and financial loss.

## Detection Trigger
- **Sigma Rule**: `aws_guardduty_cryptocurrency_mining.yml`
- **MITRE ATT&CK**: T1496 (Resource Hijacking)

## Automated Containment Procedure
1. GuardDuty alerts on DNS queries to known mining pools (e.g., stratum+tcp).
2. Quarantine instance network interfaces immediately.
3. Capture memory and swap disk artifacts for attribution.
4. Terminate unauthorized batch worker instances if auto-scaling loop detected.
