# MITRE ATT&CK® Enterprise Cloud Domain Coverage Matrix

This document provides complete mapping between adversary Tactics, Techniques, and Procedures (TTPs), high-fidelity Sigma detection rules, and automated SOAR serverless containment playbooks.

| MITRE Tactic | Technique ID | Technique Name | Detection Rule | Automated Response Playbook | Cloud Platform |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | `aws_root_account_usage_no_mfa.yml` | `revoke_iam_session.py` | AWS |
| **Initial Access** | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing App | `aws_ec2_unusual_outbound_traffic.yml` | `isolate_ec2.py` | AWS |
| **Privilege Escalation** | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | `aws_iam_admin_policy_attached.yml` | `revoke_iam_session.py` | AWS |
| **Privilege Escalation** | [T1098](https://attack.mitre.org/techniques/T1098/) | Entra ID Global Admin Role | `azure_entraid_global_admin_assigned.yml` | `azure_revoke_token.py` | Azure |
| **Privilege Escalation** | [T1098](https://attack.mitre.org/techniques/T1098/) | GCP Service Account Admin | `gcp_iam_service_account_admin.yml` | `gcp_disable_sa_key.py` | GCP |
| **Defense Evasion** | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable CloudTrail | `aws_cloudtrail_logging_disabled.yml` | `alert_dispatcher.py` | AWS |
| **Defense Evasion** | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Delete Flow Logs | `aws_vpc_flow_logs_deleted.yml` | `alert_dispatcher.py` | AWS |
| **Exfiltration** | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | `aws_s3_bucket_public_exposure.yml` | `remediate_s3.py` | AWS |
| **Exfiltration** | [T1530](https://attack.mitre.org/techniques/T1530/) | Azure Blob Public Access | `azure_storage_public_access_enabled.yml` | `azure_enforce_private_storage.py` | Azure |
| **Exfiltration** | [T1530](https://attack.mitre.org/techniques/T1530/) | GCP Cloud Storage allUsers | `gcp_storage_allusers_exposure.yml` | `gcp_remediate_storage.py` | GCP |
| **Credential Access** | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores | `aws_secretsmanager_bulk_retrieval.yml` | `remediate_secrets.py` | AWS |
| **Impact** | [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction (KMS Key) | `aws_kms_key_scheduled_deletion.yml` | `remediate_kms.py` | AWS |
| **Impact** | [T1496](https://attack.mitre.org/techniques/T1496/) | Resource Hijacking: Cryptomining | `aws_guardduty_cryptocurrency_mining.yml` | `isolate_ec2.py` | AWS |
| **Command and Control** | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS Tunneling & C2 Traffic | `aws_route53_dns_tunneling_hijack.yml` | `block_waf_ip.py` | AWS |
