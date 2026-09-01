# Package Python SOAR Engine codebase into ZIP deployment artifact
data "archive_file" "soar_package" {
  type        = "zip"
  source_dir  = "${path.module}/../soar_engine"
  output_path = "${path.module}/soar_package.zip"
  excludes    = ["__pycache__", "*.pyc", ".pytest_cache"]
}

# Dedicated Quarantine Security Group (Zero Ingress, Zero Egress)
resource "aws_security_group" "quarantine_sg" {
  name        = "${var.quarantine_sg_name}-${var.environment}"
  description = "SOAR Automated Quarantine Security Group - Zero Ingress and Zero Egress"

  # Deliberately empty: No ingress and no egress permissions
}

# 1. EC2 Isolation Playbook Lambda
resource "aws_lambda_function" "isolate_ec2" {
  function_name    = "soar-isolate-ec2-${var.environment}"
  filename         = data.archive_file.soar_package.output_path
  source_code_hash = data.archive_file.soar_package.output_base64sha256
  handler          = "soar_engine.handlers.isolate_ec2.lambda_handler"
  runtime          = "python3.11"
  role             = aws_iam_role.soar_lambda_role.arn
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT             = var.environment
      QUARANTINE_SG_ID        = aws_security_group.quarantine_sg.id
      QUARANTINE_SG_NAME      = aws_security_group.quarantine_sg.name
      LOCALSTACK_ENDPOINT_URL = var.use_localstack ? var.localstack_endpoint : ""
      ALERT_WEBHOOK_URL       = var.alert_webhook_url
    }
  }
}

# 2. IAM Revocation Playbook Lambda
resource "aws_lambda_function" "revoke_iam" {
  function_name    = "soar-revoke-iam-${var.environment}"
  filename         = data.archive_file.soar_package.output_path
  source_code_hash = data.archive_file.soar_package.output_base64sha256
  handler          = "soar_engine.handlers.revoke_iam_session.lambda_handler"
  runtime          = "python3.11"
  role             = aws_iam_role.soar_lambda_role.arn
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT             = var.environment
      LOCALSTACK_ENDPOINT_URL = var.use_localstack ? var.localstack_endpoint : ""
      ALERT_WEBHOOK_URL       = var.alert_webhook_url
    }
  }
}

# 3. S3 Public Exposure Remediation Playbook Lambda
resource "aws_lambda_function" "remediate_s3" {
  function_name    = "soar-remediate-s3-${var.environment}"
  filename         = data.archive_file.soar_package.output_path
  source_code_hash = data.archive_file.soar_package.output_base64sha256
  handler          = "soar_engine.handlers.remediate_s3.lambda_handler"
  runtime          = "python3.11"
  role             = aws_iam_role.soar_lambda_role.arn
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT             = var.environment
      LOCALSTACK_ENDPOINT_URL = var.use_localstack ? var.localstack_endpoint : ""
      ALERT_WEBHOOK_URL       = var.alert_webhook_url
    }
  }
}

# 4. Standalone Alert Dispatcher Lambda
resource "aws_lambda_function" "alert_dispatcher" {
  function_name    = "soar-alert-dispatcher-${var.environment}"
  filename         = data.archive_file.soar_package.output_path
  source_code_hash = data.archive_file.soar_package.output_base64sha256
  handler          = "soar_engine.handlers.alert_dispatcher.lambda_handler"
  runtime          = "python3.11"
  role             = aws_iam_role.soar_lambda_role.arn
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT       = var.environment
      ALERT_WEBHOOK_URL = var.alert_webhook_url
    }
  }
}
