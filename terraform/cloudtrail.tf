data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "${var.cloudtrail_bucket_prefix}-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_pab" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_sse" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# CloudWatch Log Group for Real-Time Event Ingestion
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name              = "/aws/cloudtrail/soar-pipeline-${var.environment}"
  retention_in_days = var.log_retention_days
}

# IAM Role allowing CloudTrail to stream events into CloudWatch
resource "aws_iam_role" "cloudtrail_cw_role" {
  name = "soar-cloudtrail-cw-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cw_policy" {
  name = "soar-cloudtrail-cw-policy-${var.environment}"
  role = aws_iam_role.cloudtrail_cw_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
      }
    ]
  })
}

# Multi-Region CloudTrail Trail
resource "aws_cloudtrail" "soar_trail" {
  name                          = "soar-threat-detection-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw_role.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_bucket_policy,
    aws_iam_role_policy.cloudtrail_cw_policy
  ]
}
