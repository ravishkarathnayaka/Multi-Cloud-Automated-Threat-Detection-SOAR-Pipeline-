# Central Lambda Execution Role for SOAR Automation Handlers
resource "aws_iam_role" "soar_lambda_role" {
  name = "soar-lambda-execution-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# CloudWatch Logging Policy
resource "aws_iam_policy" "soar_logging_policy" {
  name        = "soar-logging-policy-${var.environment}"
  description = "Allows SOAR Lambda handlers to stream execution logs to CloudWatch."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# EC2 Containment & Forensics Policy (Least Privilege)
resource "aws_iam_policy" "soar_ec2_containment_policy" {
  name        = "soar-ec2-containment-policy-${var.environment}"
  description = "Grants least privilege rights to isolate EC2 hosts and create forensic snapshots."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2DiscoveryAndTagging"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2SecurityGroupModification"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSecurityGroup",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupEgress"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2ForensicSnapshotting"
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Revocation Policy (Least Privilege)
resource "aws_iam_policy" "soar_iam_revocation_policy" {
  name        = "soar-iam-revocation-policy-${var.environment}"
  description = "Allows SOAR to deactivate credentials and apply emergency DenyAll policies."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMCredentialManagement"
        Effect = "Allow"
        Action = [
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy",
          "iam:GetUserPolicy",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:TagUser",
          "iam:TagRole"
        ]
        Resource = "*"
      }
    ]
  })
}

# S3 Public Access Remediation Policy (Least Privilege)
resource "aws_iam_policy" "soar_s3_remediation_policy" {
  name        = "soar-s3-remediation-policy-${var.environment}"
  description = "Allows SOAR to enforce Public Access Block and sanitize public bucket policies."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3PublicAccessRemediation"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:GetBucketTagging",
          "s3:PutBucketTagging"
        ]
        Resource = "arn:aws:s3:::*"
      }
    ]
  })
}

# Attachments
resource "aws_iam_role_policy_attachment" "attach_logging" {
  role       = aws_iam_role.soar_lambda_role.name
  policy_arn = aws_iam_policy.soar_logging_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_ec2" {
  role       = aws_iam_role.soar_lambda_role.name
  policy_arn = aws_iam_policy.soar_ec2_containment_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_iam" {
  role       = aws_iam_role.soar_lambda_role.name
  policy_arn = aws_iam_policy.soar_iam_revocation_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_s3" {
  role       = aws_iam_role.soar_lambda_role.name
  policy_arn = aws_iam_policy.soar_s3_remediation_policy.arn
}
