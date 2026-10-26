# Incident Response Playbook 03: EC2 Host Isolation & Forensics

## Objective
Sever command and control channels for compromised virtual machines while capturing digital forensic evidence.

## Detection Trigger
- **Sigma Rule**: `aws_ec2_unusual_outbound_traffic.yml`
- **MITRE ATT&CK**: T1071 (Application Layer Protocol) / T1190 (Exploit Public-Facing App)

## Automated Containment Procedure
1. Identify target instance ID from CloudTrail or GuardDuty event.
2. Retrieve or create zero-ingress / zero-egress `SOAR-Quarantine-SG`.
3. Replace existing instance security groups with the Quarantine SG.
4. Trigger point-in-time forensic EBS snapshots for all attached block devices.
5. Tag instance `SOAR:QuarantineState = Quarantined`.
