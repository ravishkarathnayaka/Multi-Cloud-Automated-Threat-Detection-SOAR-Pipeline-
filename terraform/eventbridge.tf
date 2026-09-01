# ==============================================================================
# Rule 1: IAM Privilege Escalation Detection
# ==============================================================================
resource "aws_cloudwatch_event_rule" "iam_admin_escalation" {
  name        = "soar-detect-iam-admin-escalation-${var.environment}"
  description = "Triggers when administrative policies are attached or created in IAM."

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "target_revoke_iam" {
  rule      = aws_cloudwatch_event_rule.iam_admin_escalation.name
  target_id = "TargetRevokeIamLambda"
  arn       = aws_lambda_function.revoke_iam.arn
}

resource "aws_lambda_permission" "allow_eventbridge_revoke_iam" {
  statement_id  = "AllowExecutionFromEventBridgeIAM"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.revoke_iam.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_admin_escalation.arn
}

# ==============================================================================
# Rule 2: CloudTrail Tampering / Defense Evasion Detection
# ==============================================================================
resource "aws_cloudwatch_event_rule" "cloudtrail_tampering" {
  name        = "soar-detect-cloudtrail-tampering-${var.environment}"
  description = "Triggers when CloudTrail logging is halted or trails are deleted."

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      eventName = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "target_cloudtrail_alert" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_tampering.name
  target_id = "TargetCloudTrailAlertLambda"
  arn       = aws_lambda_function.alert_dispatcher.arn
}

resource "aws_lambda_permission" "allow_eventbridge_cloudtrail_alert" {
  statement_id  = "AllowExecutionFromEventBridgeCloudTrail"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert_dispatcher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail_tampering.arn
}

# ==============================================================================
# Rule 3: S3 Public Exposure Detection
# ==============================================================================
resource "aws_cloudwatch_event_rule" "s3_public_exposure" {
  name        = "soar-detect-s3-public-exposure-${var.environment}"
  description = "Triggers on modifications to S3 Public Access Block or bucket policies."

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeletePublicAccessBlock",
        "PutBucketPublicAccessBlock"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "target_remediate_s3" {
  rule      = aws_cloudwatch_event_rule.s3_public_exposure.name
  target_id = "TargetRemediateS3Lambda"
  arn       = aws_lambda_function.remediate_s3.arn
}

resource "aws_lambda_permission" "allow_eventbridge_remediate_s3" {
  statement_id  = "AllowExecutionFromEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_s3.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_exposure.arn
}

# ==============================================================================
# Rule 4: EC2 Unauthorized Ingress / Compromised Host Detection
# ==============================================================================
resource "aws_cloudwatch_event_rule" "ec2_threat" {
  name        = "soar-detect-ec2-threat-${var.environment}"
  description = "Triggers on unauthorized security group ingress rules or GuardDuty findings."

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName = [
        "AuthorizeSecurityGroupIngress"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "target_isolate_ec2" {
  rule      = aws_cloudwatch_event_rule.ec2_threat.name
  target_id = "TargetIsolateEc2Lambda"
  arn       = aws_lambda_function.isolate_ec2.arn
}

resource "aws_lambda_permission" "allow_eventbridge_isolate_ec2" {
  statement_id  = "AllowExecutionFromEventBridgeEC2"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.isolate_ec2.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ec2_threat.arn
}
