# Incident Response Playbook 01: IAM Privilege Escalation

## Objective
Neutralize compromised IAM identities that have been granted administrative privileges (`AdministratorAccess`).

## Detection Trigger
- **Sigma Rule**: `aws_iam_admin_policy_attached.yml`
- **MITRE ATT&CK**: T1098 (Account Manipulation) / T1078.004 (Cloud Accounts)

## Automated Containment Procedure
1. Parse event to extract target IAM username or role.
2. Deactivate all active access keys via `UpdateAccessKey(Status='Inactive')`.
3. Invalidate active STS sessions using `PutUserPolicy` with `DateLessThan` condition.
4. Attach emergency inline `SOAR-DenyAll-Emergency` policy.
5. Dispatch critical alert to SecOps Slack channel.
