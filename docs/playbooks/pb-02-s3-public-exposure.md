# Incident Response Playbook 02: S3 Public Exposure Hardening

## Objective
Prevent cloud data exfiltration by closing unauthorized public access on S3 storage buckets.

## Detection Trigger
- **Sigma Rule**: `aws_s3_bucket_public_exposure.yml`
- **MITRE ATT&CK**: T1530 (Data from Cloud Storage Object)

## Automated Containment Procedure
1. Intercept `DeletePublicAccessBlock` or `PutBucketPolicy` events.
2. Enforce all four S3 Public Access Block settings:
   - `BlockPublicAcls: True`
   - `IgnorePublicAcls: True`
   - `BlockPublicPolicy: True`
   - `RestrictPublicBuckets: True`
3. Scan and sanitize wildcard allow policies (`Principal: *`).
4. Apply audit tag `SOAR:Remediated = StrictPrivate`.
