# MITRE ATT&CK® Cloud Matrix Mapping Table

This matrix maps detected cloud threat behaviors to the **MITRE ATT&CK Enterprise Matrix (Cloud Domain)**, outlining corresponding Sigma detection rules, automated SOAR playbooks, specific containment actions, and target Mean Time to Contain (MTTC).

---

## Detection & Response Coverage Matrix

| MITRE Tactic | Technique ID | Technique Name | Sigma Detection Rule | SOAR Playbook Handler | Automated Remediation Action | Target MTTC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Privilege Escalation** | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | `aws_iam_admin_policy_attached.yml` | `revoke_iam_session.py` | Deactivates access keys; attaches inline `DenyAll` emergency policy; invalidates active STS sessions. | `< 3s` |
| **Persistence** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | `aws_iam_admin_policy_attached.yml` | `revoke_iam_session.py` | Attaches inline `DenyAll` policy with `aws:TokenIssueTime` condition to immediately revoke all temporary STS tokens. | `< 3s` |
| **Defense Evasion** | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable Cloud Logs | `aws_cloudtrail_logging_disabled.yml` | `alert_dispatcher.py` | Emits critical incident notification to SecOps; flags AWS account for immediate forensic review. | `< 2s` |
| **Exfiltration** | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | `aws_s3_bucket_public_exposure.yml` | `remediate_s3.py` | Re-enables all 4 S3 Public Access Block settings; purges wildcard public allow statements (`Principal: *`). | `< 4s` |
| **Command & Control** | [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | `aws_ec2_unusual_outbound_traffic.yml` | `isolate_ec2.py` | Swaps active Security Groups to zero-traffic Quarantine SG; triggers point-in-time forensic EBS snapshots. | `< 5s` |
| **Initial Access** | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | `aws_ec2_unusual_outbound_traffic.yml` | `isolate_ec2.py` | Isolates host from VPC network; snapshots EBS volumes; tags instance with `SOAR:QuarantineState=Quarantined`. | `< 5s` |

---

## Detailed Playbook Breakdown

### 1. Account Manipulation & Privilege Escalation ([T1098](https://attack.mitre.org/techniques/T1098/))
* **Detection Trigger**: CloudTrail event `AttachUserPolicy`, `AttachRolePolicy`, or `AttachGroupPolicy` where `policyArn` contains `AdministratorAccess`, or `PutUserPolicy` / `PutRolePolicy` granting administrative privileges.
* **SOAR Handler**: [`revoke_iam_session.py`](file:///f:/Projects/cloud-threat-detection-soar-pipeline/soar_engine/handlers/revoke_iam_session.py)
* **Automated Containment Actions**:
  1. For IAM Users: Calls `iam:UpdateAccessKey` setting status to `Inactive` for all associated keys.
  2. Attaches inline policy `SOAR-DenyAll-Emergency` preventing any further API calls.
  3. For IAM Roles: Sets condition `aws:TokenIssueTime < <current_time>` to invalidate all pre-existing STS sessions.
  4. Tags entity with `SOAR:Remediated=True`.

### 2. Impair Defenses: Disable Cloud Logs ([T1562.001](https://attack.mitre.org/techniques/T1562/001/))
* **Detection Trigger**: CloudTrail event `StopLogging`, `DeleteTrail`, or `UpdateTrail`.
* **SOAR Handler**: [`alert_dispatcher.py`](file:///f:/Projects/cloud-threat-detection-soar-pipeline/soar_engine/handlers/alert_dispatcher.py)
* **Automated Containment Actions**:
  1. Generates `CRITICAL` severity incident payload.
  2. Dispatches Slack Block Kit card to security operations channel.
  3. Records audit log in CloudWatch Logs for post-incident timeline reconstruction.

### 3. Data from Cloud Storage Object ([T1530](https://attack.mitre.org/techniques/T1530/))
* **Detection Trigger**: CloudTrail event `DeletePublicAccessBlock`, `PutBucketAcl`, or `PutBucketPolicy` targeting S3.
* **SOAR Handler**: [`remediate_s3.py`](file:///f:/Projects/cloud-threat-detection-soar-pipeline/soar_engine/handlers/remediate_s3.py)
* **Automated Containment Actions**:
  1. Calls `s3:PutPublicAccessBlock` enforcing:
     - `BlockPublicAcls = True`
     - `IgnorePublicAcls = True`
     - `BlockPublicPolicy = True`
     - `RestrictPublicBuckets = True`
  2. Inspects bucket policy; removes statements where `"Principal": "*"` and `"Effect": "Allow"`.
  3. Applies tags: `SOAR:PublicAccessRemediated=True`, `SOAR:Compliance=StrictPrivate`.

### 4. Application Layer Protocol & Network Intrusion ([T1071](https://attack.mitre.org/techniques/T1071/), [T1190](https://attack.mitre.org/techniques/T1190/))
* **Detection Trigger**: GuardDuty findings or unauthorized `AuthorizeSecurityGroupIngress` with `0.0.0.0/0`.
* **SOAR Handler**: [`isolate_ec2.py`](file:///f:/Projects/cloud-threat-detection-soar-pipeline/soar_engine/handlers/isolate_ec2.py)
* **Automated Containment Actions**:
  1. Queries target instance for attached VPC and existing security group IDs.
  2. Preserves existing security group IDs in tag `SOAR:PreQuarantineSG`.
  3. Replaces active security groups with `soar-quarantine-sg` (0 ingress, 0 egress).
  4. Triggers `ec2:CreateSnapshot` on all attached EBS volumes with tag `SOAR:ForensicEvidence=True`.
  5. Updates instance tags with quarantine timestamp and incident ID.
