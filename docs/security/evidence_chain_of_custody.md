# Digital Forensics & Chain of Custody Guide

## Standard Operating Procedure
When an incident is quarantined by the SOAR pipeline, forensic integrity must be maintained.

1. **Snapshots**: EBS point-in-time snapshots are encrypted and retained under WORM policy.
2. **Hashing**: Evidence logs are hashed using SHA-256 at the moment of containment.
3. **Audit Trails**: CloudTrail and EventBridge audit records are stored in a dedicated Write-Once-Read-Many (WORM) S3 bucket with Object Lock enabled.
