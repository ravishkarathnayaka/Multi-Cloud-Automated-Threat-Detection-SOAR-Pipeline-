output "cloudtrail_arn" {
  description = "ARN of the provisioned multi-region CloudTrail audit trail."
  value       = aws_cloudtrail.soar_trail.arn
}

output "cloudtrail_bucket_name" {
  description = "Name of the secure S3 bucket receiving CloudTrail audit logs."
  value       = aws_s3_bucket.cloudtrail_bucket.id
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch Log Group ingesting real-time CloudTrail security logs."
  value       = aws_cloudwatch_log_group.cloudtrail_log_group.arn
}

output "quarantine_security_group_id" {
  description = "Security Group ID of the zero-traffic quarantine group used for host isolation."
  value       = aws_security_group.quarantine_sg.id
}

output "lambda_isolate_ec2_arn" {
  description = "ARN of the EC2 isolation and forensic snapshot Lambda handler."
  value       = aws_lambda_function.isolate_ec2.arn
}

output "lambda_revoke_iam_arn" {
  description = "ARN of the IAM credential revocation and STS invalidation Lambda handler."
  value       = aws_lambda_function.revoke_iam.arn
}

output "lambda_remediate_s3_arn" {
  description = "ARN of the S3 public access remediation Lambda handler."
  value       = aws_lambda_function.remediate_s3.arn
}

output "lambda_alert_dispatcher_arn" {
  description = "ARN of the alert enrichment and webhook dispatcher Lambda handler."
  value       = aws_lambda_function.alert_dispatcher.arn
}

output "iam_execution_role_arn" {
  description = "ARN of the IAM role utilized by SOAR response automation handlers."
  value       = aws_iam_role.soar_lambda_role.arn
}
