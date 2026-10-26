# Multi-Cloud Automated Threat Detection & SOAR Pipeline

[![CI Pipeline](https://github.com/ravishkarathnayaka/Multi-Cloud-Automated-Threat-Detection-SOAR-Pipeline-/actions/workflows/ci.yml/badge.svg)](https://github.com/ravishkarathnayaka/Multi-Cloud-Automated-Threat-Detection-SOAR-Pipeline-/actions/workflows/ci.yml)
[![Security Scan](https://github.com/ravishkarathnayaka/Multi-Cloud-Automated-Threat-Detection-SOAR-Pipeline-/actions/workflows/security-scan.yml/badge.svg)](https://github.com/ravishkarathnayaka/Multi-Cloud-Automated-Threat-Detection-SOAR-Pipeline-/actions/workflows/security-scan.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Terraform: >=1.5.0](https://img.shields.io/badge/terraform->=1.5.0-623CE4.svg)](https://www.terraform.io/)
[![Coverage: 90%+](https://img.shields.io/badge/coverage-90%25+-brightgreen.svg)](tests/)

A production-grade, modular open-source security engineering project delivering **Automated Threat Detection & Real-Time Incident Response (SOAR)** across multi-cloud environments (AWS, Azure, GCP).

Engineered for **zero-cost local development** using LocalStack and Docker containers, while maintaining 100% architectural parity with live AWS Free Tier environments.

---

## 🌐 Live Web Portal & Interactive SOC Simulator

- **Production URL**: [https://multi-cloud-automated-threat-detect-woad.vercel.app](https://multi-cloud-automated-threat-detect-woad.vercel.app)
- **GitHub Pages**: [https://ravishkarathnayaka.github.io/Multi-Cloud-Automated-Threat-Detection-SOAR-Pipeline-/](https://ravishkarathnayaka.github.io/Multi-Cloud-Automated-Threat-Detection-SOAR-Pipeline-/)

---

## Key Features

- **Dual-Mode Operation**: Seamlessly switch between LocalStack (100% free offline emulation) and AWS Free Tier with a single Terraform variable (`use_localstack = true/false`).
- **Sub-Second Automated Containment**:
  - **EC2 Host Isolation**: Replaces compromised security groups with a zero-ingress/zero-egress quarantine group and captures point-in-time forensic EBS snapshots.
  - **IAM Credential Revocation**: Instantly deactivates active access keys, applies emergency `DenyAll` policies, and uses non-dated `TokenIssueTime` conditions to invalidate all active STS session tokens.
  - **S3 Bucket Hardening**: Re-enforces all 4 S3 Public Access Block settings and strips wildcard (`Principal: *`) allow statements.
  - **KMS Key Deletion Cancellation**: Halts unauthorized cryptographic key scheduled deletions.
  - **Secrets Manager Immediate Rotation**: Rotates compromised database and API secrets on anomaly detection.
- **Multi-Cloud Expansion**: Support for Microsoft Entra ID session revocation, Azure Storage Account isolation, and GCP Cloud Storage IAM remediation.
- **Enterprise Detection Engineering**: Standardized Sigma rules mapped to the MITRE ATT&CK Cloud Matrix with sub-3-second Mean Time to Contain (MTTC).
- **Atomic Red Team Cloud Simulation**: Integrated threat emulation suite in `simulations/atomic_red_team/`.
- **Quality & DevSecOps**: 35+ unit tests passing with Moto mocking framework and automated GitHub Actions CI & Security scanning.
