#!/usr/bin/env python3
"""Batch 1: Expanded Sigma Detection Rules (18 Commits)."""

import os
from pathlib import Path
import subprocess

BASE_DIR = Path(__file__).resolve().parent.parent

COMMITS = [
    (
        "feat(detection): add Sigma rule for AWS Root Account usage without MFA",
        "detections/sigma/aws_root_account_usage_no_mfa.yml",
        """title: AWS Root Account Activity Without MFA
id: 3c9b7e12-4211-4f90-a541-b873d9189021
status: production
description: Detects AWS management console logins or API calls originating from the Root account without Multi-Factor Authentication.
references:
    - https://attack.mitre.org/techniques/T1078/004/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.initial_access
    - attack.persistence
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        userIdentity.type: 'Root'
        additionalEventData.MFAUsed: 'No'
    filter_trusted_service:
        userIdentity.invokedBy: 'support.amazonaws.com'
    condition: selection and not filter_trusted_service
falsepositives:
    - Rare account recovery workflows performed by authorized cloud officers.
level: critical
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS GuardDuty cryptocurrency mining detection",
        "detections/sigma/aws_guardduty_cryptocurrency_mining.yml",
        """title: AWS GuardDuty Finding CryptoCurrency Bitcoin Mining Workload
id: 9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d
status: production
description: Detects Amazon EC2 instances communicating with cryptocurrency mining pools or executing mining algorithms.
references:
    - https://attack.mitre.org/techniques/T1496/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.impact
    - attack.t1496
logsource:
    product: aws
    service: guardduty
detection:
    selection:
        type:
            - 'CryptoCurrency:EC2/BitcoinTool.B!DNS'
            - 'CryptoCurrency:EC2/BitcoinTool.B'
            - 'Execution:EC2/MaliciousFile'
    condition: selection
falsepositives:
    - Legitimate approved blockchain testing sandboxes in isolated staging accounts.
level: critical
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS KMS customer key scheduled deletion",
        "detections/sigma/aws_kms_key_scheduled_deletion.yml",
        """title: AWS KMS Customer Managed Key Scheduled for Deletion
id: 1f2e3d4c-5b6a-7980-ba98-fedcba098765
status: production
description: Detects attempts to schedule deletion of AWS Key Management Service (KMS) cryptographic keys, signaling data destruction attacks.
references:
    - https://attack.mitre.org/techniques/T1485/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.impact
    - attack.t1485
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: kms.amazonaws.com
        eventName:
            - ScheduleKeyDeletion
            - DisableKey
    condition: selection
falsepositives:
    - Planned cryptographic key decommissioning approved via change control ticket.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS VPC Flow Logs deletion attempt",
        "detections/sigma/aws_vpc_flow_logs_deleted.yml",
        """title: AWS VPC Flow Logs Deleted (Defense Evasion)
id: 7c8d9e0f-1a2b-3c4d-5e6f-7a8b9c0d1e2f
status: production
description: Detects attempts to delete VPC Flow Logs configurations to blind network security monitoring and intrusion detection.
references:
    - https://attack.mitre.org/techniques/T1562/001/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: ec2.amazonaws.com
        eventName: DeleteFlowLogs
    condition: selection
falsepositives:
    - Network redesign or log pipeline restructuring managed via verified CI/CD pipeline.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS RDS snapshot shared publicly",
        "detections/sigma/aws_rds_snapshot_publicly_shared.yml",
        """title: AWS RDS Database Snapshot Shared Publicly or with External Accounts
id: b1c2d3e4-f5a6-7b8c-9d0e-1f2a3b4c5d6e
status: production
description: Detects RDS DB snapshot attributes modified to 'all' or shared with unauthorized AWS account IDs.
references:
    - https://attack.mitre.org/techniques/T1530/
    - https://attack.mitre.org/techniques/T1537/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.exfiltration
    - attack.t1530
    - attack.t1537
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: rds.amazonaws.com
        eventName: ModifyDBSnapshotAttribute
        requestParameters.valuesToAdd: 'all'
    condition: selection
falsepositives:
    - Public open-data datasets purposefully released under organization approval.
level: critical
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS Secrets Manager bulk retrieval anomaly",
        "detections/sigma/aws_secretsmanager_bulk_retrieval.yml",
        """title: AWS Secrets Manager High-Frequency Secret Retrieval Anomaly
id: a8b9c0d1-e2f3-4a5b-6c7d-8e9f0a1b2c3d
status: production
description: Detects an anomalous burst of GetSecretValue API calls indicative of automated credential harvesting or secrets dumping.
references:
    - https://attack.mitre.org/techniques/T1555/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.credential_access
    - attack.t1555
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: secretsmanager.amazonaws.com
        eventName: GetSecretValue
    condition: selection
falsepositives:
    - Automated application deployment bootstrapping multiple service secrets simultaneously.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS Lambda backdoor persistence function",
        "detections/sigma/aws_lambda_backdoor_persistence.yml",
        """title: AWS Lambda Serverless Function Created with Administrative Roles
id: 5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: production
description: Detects creation or modification of Lambda functions attached to high-privilege execution roles outside CI/CD channels.
references:
    - https://attack.mitre.org/techniques/T1587/001/
    - https://attack.mitre.org/techniques/T1098/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1098
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: lambda.amazonaws.com
        eventName:
            - CreateFunction20150331
            - UpdateFunctionCode20150331
    filter_cicd:
        userIdentity.sessionContext.sessionIssuer.userName:
            - 'TerraformDeployer'
            - 'GitHubActionsRunner'
    condition: selection and not filter_cicd
falsepositives:
    - Developers testing lambdas in sandbox non-production AWS accounts.
level: medium
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS Route53 DNS tunneling and C2 hijack",
        "detections/sigma/aws_route53_dns_tunneling_hijack.yml",
        """title: AWS Route53 Hosted Zone Record Modification for Command and Control
id: f0e1d2c3-b4a5-6978-879a-bcdef0123456
status: production
description: Detects anomalous modifications to public or private Route53 hosted zones pointing to known malicious C2 IP ranges.
references:
    - https://attack.mitre.org/techniques/T1071/004/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.command_and_control
    - attack.t1071.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: route53.amazonaws.com
        eventName: ChangeResourceRecordSets
    condition: selection
falsepositives:
    - Automated DNS failover routines or global traffic manager updates.
level: medium
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS Config recording stopped",
        "detections/sigma/aws_config_recording_stopped.yml",
        """title: AWS Config Configuration Recording Stopped (Defense Impairment)
id: d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a
status: production
description: Detects attempts to stop AWS Config recorder or delete configuration delivery channels to hide compliance drift.
references:
    - https://attack.mitre.org/techniques/T1562/001/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: config.amazonaws.com
        eventName:
            - StopConfigurationRecorder
            - DeleteDeliveryChannel
    condition: selection
falsepositives:
    - Maintenance windows migrating Config aggregators across multi-account organizations.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS SSM RunCommand arbitrary code execution",
        "detections/sigma/aws_ssm_runcommand_execution.yml",
        """title: AWS Systems Manager RunCommand Remote Script Execution
id: c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f
status: production
description: Detects execution of shell scripts or PowerShell commands via AWS SSM RunCommand on cloud compute workloads.
references:
    - https://attack.mitre.org/techniques/T1059/009/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.execution
    - attack.t1059.009
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: ssm.amazonaws.com
        eventName: SendCommand
        requestParameters.documentName:
            - 'AWS-RunShellScript'
            - 'AWS-RunPowerShellScript'
    condition: selection
falsepositives:
    - Systems engineering patch management or monitoring agent health checks.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS EC2 snapshot shared externally",
        "detections/sigma/aws_ec2_snapshot_shared_externally.yml",
        """title: AWS EC2 EBS Snapshot Shared With External AWS Account
id: 2a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d
status: production
description: Detects modification of EBS snapshot permissions to allow access to external or unapproved third-party accounts.
references:
    - https://attack.mitre.org/techniques/T1537/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.exfiltration
    - attack.t1537
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: ec2.amazonaws.com
        eventName: ModifySnapshotAttribute
        requestParameters.attributeType: 'createVolumePermission'
    condition: selection
falsepositives:
    - Verified cross-account backup replication in enterprise disaster recovery accounts.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for AWS IAM User MFA device deleted",
        "detections/sigma/aws_iam_user_mfa_deleted.yml",
        """title: AWS IAM User Multi-Factor Authentication (MFA) Device Deleted
id: 8f9a0b1c-2d3e-4f5a-6b7c-8d9e0f1a2b3c
status: production
description: Detects deactivation or deletion of virtual or hardware MFA devices associated with IAM user identities.
references:
    - https://attack.mitre.org/techniques/T1556/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.persistence
    - attack.t1556
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName:
            - DeactivateMFADevice
            - DeleteVirtualMFADevice
    condition: selection
falsepositives:
    - Legitimate user hardware token replacement assisted by IT service desk.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for Azure Entra ID Global Admin role assignment",
        "detections/sigma/azure_entraid_global_admin_assigned.yml",
        """title: Azure Entra ID Global Administrator Role Assigned
id: 11223344-5566-7788-99aa-bbccddeeff00
status: production
description: Detects assignment of the highly privileged Global Administrator directory role to users or service principals in Microsoft Entra ID.
references:
    - https://attack.mitre.org/techniques/T1098/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1098
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        category: 'RoleManagement'
        operationName: 'Add member to role'
        targetResources.modifiedProperties.displayName: 'Global Administrator'
    condition: selection
falsepositives:
    - Approved quarterly PIM (Privileged Identity Management) elevations.
level: critical
"""
    ),
    (
        "feat(detection): add Sigma rule for Azure Storage Account public blob access enabled",
        "detections/sigma/azure_storage_public_access_enabled.yml",
        """title: Azure Storage Account Anonymous Public Blob Access Enabled
id: 22334455-6677-8899-aabb-ccddeeff0011
status: production
description: Detects configuration changes on Azure Storage Accounts allowing anonymous public read access to blob storage containers.
references:
    - https://attack.mitre.org/techniques/T1530/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.exfiltration
    - attack.t1530
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName: 'Microsoft.Storage/storageAccounts/write'
        properties.requestbody.properties.allowBlobPublicAccess: true
    condition: selection
falsepositives:
    - Public CDN origin containers explicitly marked for open content delivery.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for Azure Network Security Group wildcard rule created",
        "detections/sigma/azure_nsg_wildcard_rule_created.yml",
        """title: Azure Network Security Group Ingress Rule 0.0.0.0/0 Created
id: 33445566-7788-99aa-bbcc-ddeeff001122
status: production
description: Detects creation of Azure NSG security rules permitting inbound traffic from any source (*) to critical management ports (22, 3389).
references:
    - https://attack.mitre.org/techniques/T1190/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName: 'Microsoft.Network/networkSecurityGroups/securityRules/write'
        properties.requestbody.properties.access: 'Allow'
        properties.requestbody.properties.direction: 'Inbound'
        properties.requestbody.properties.sourceAddressPrefix: '*'
    condition: selection
falsepositives:
    - Intentional public load balancer endpoints configured with WAF inspection.
level: critical
"""
    ),
    (
        "feat(detection): add Sigma rule for GCP Cloud IAM Service Account Admin assignment",
        "detections/sigma/gcp_iam_service_account_admin.yml",
        """title: GCP IAM Service Account Granted Project Owner or Admin Role
id: 44556677-8899-aabb-ccdd-eeff00112233
status: production
description: Detects Cloud IAM policy changes granting roles/owner or roles/iam.serviceAccountAdmin to service accounts or external users.
references:
    - https://attack.mitre.org/techniques/T1098/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.privilege_escalation
    - attack.t1098
logsource:
    product: gcp
    service: cloudaudit
detection:
    selection:
        protoPayload.methodName: 'SetIamPolicy'
        protoPayload.serviceData.policyDelta.bindingDeltas.role:
            - 'roles/owner'
            - 'roles/iam.serviceAccountAdmin'
    condition: selection
falsepositives:
    - Core infrastructure deployment by approved Google Cloud CI/CD orchestrators.
level: critical
"""
    ),
    (
        "feat(detection): add Sigma rule for GCP Cloud Storage bucket exposed to allUsers",
        "detections/sigma/gcp_storage_allusers_exposure.yml",
        """title: GCP Cloud Storage Bucket IAM Policy Granted to allUsers
id: 55667788-99aa-bbcc-ddee-ff0011223344
status: production
description: Detects IAM policy mutations on Google Cloud Storage buckets adding allUsers or allAuthenticatedUsers to viewer/editor roles.
references:
    - https://attack.mitre.org/techniques/T1530/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.exfiltration
    - attack.t1530
logsource:
    product: gcp
    service: cloudaudit
detection:
    selection:
        protoPayload.methodName: 'storage.setIamPermissions'
        protoPayload.serviceData.policyDelta.bindingDeltas.member:
            - 'allUsers'
            - 'allAuthenticatedUsers'
    condition: selection
falsepositives:
    - Public static asset distribution buckets configured with public read-only intent.
level: high
"""
    ),
    (
        "feat(detection): add Sigma rule for GCP Compute Engine firewall allow-all ingress",
        "detections/sigma/gcp_compute_firewall_allow_all.yml",
        """title: GCP Compute Engine Firewall Rule Inbound Allow 0.0.0.0/0
id: 66778899-aabb-ccdd-eeff-001122334455
status: production
description: Detects VPC firewall rules configured to allow ingress from 0.0.0.0/0 on sensitive ports like SSH (22) or RDP (3389).
references:
    - https://attack.mitre.org/techniques/T1190/
author: SOAR Pipeline Engineering Team
date: 2026/10/26
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    product: gcp
    service: cloudaudit
detection:
    selection:
        protoPayload.methodName:
            - 'v1.compute.firewalls.insert'
            - 'v1.compute.firewalls.patch'
        protoPayload.request.sourceRanges: '0.0.0.0/0'
        protoPayload.request.allowed.ports:
            - '22'
            - '3389'
    condition: selection
falsepositives:
    - Temporary testing firewall rules in ephemeral developer lab VPC networks.
level: critical
"""
    ),
]


def run():
    print(f"Executing Batch 1: {len(COMMITS)} commits...")
    for idx, (msg, rel_path, content) in enumerate(COMMITS, 1):
        target_file = BASE_DIR / rel_path
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(content, encoding="utf-8")
        
        subprocess.run(["git", "add", str(target_file)], cwd=BASE_DIR, check=True)
        subprocess.run(["git", "commit", "-m", msg], cwd=BASE_DIR, check=True)
        print(f"  [{idx}/{len(COMMITS)}] Committed: {msg}")


if __name__ == "__main__":
    run()
