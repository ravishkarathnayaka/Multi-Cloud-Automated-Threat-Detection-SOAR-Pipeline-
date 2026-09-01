variable "aws_region" {
  description = "AWS region for resource provisioning."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d+$", var.aws_region))
    error_message = "The aws_region value must be a valid AWS region format (e.g., us-east-1, eu-west-1)."
  }
}

variable "environment" {
  description = "Deployment environment identifier."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "use_localstack" {
  description = "Toggle between local LocalStack emulation (zero cost) and live AWS environment."
  type        = bool
  default     = true
}

variable "localstack_endpoint" {
  description = "Endpoint URL for LocalStack service emulation."
  type        = string
  default     = "http://localhost:4566"
}

variable "alert_webhook_url" {
  description = "External webhook URL for Slack / Microsoft Teams incident notifications."
  type        = string
  default     = ""
}

variable "cloudtrail_bucket_prefix" {
  description = "Prefix for the S3 bucket hosting multi-region CloudTrail audit logs."
  type        = string
  default     = "soar-cloudtrail-audit-logs"
}

variable "quarantine_sg_name" {
  description = "Name for the zero-traffic isolation quarantine security group."
  type        = string
  default     = "soar-quarantine-sg"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 180, 365], var.log_retention_days)
    error_message = "Log retention days must match standard CloudWatch retention intervals."
  }
}
