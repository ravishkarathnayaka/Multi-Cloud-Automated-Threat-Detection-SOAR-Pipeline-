# AWS KMS Encryption Key Module

resource "aws_kms_key" "soar_audit_key" {
  description             = "KMS Key for SOAR CloudTrail and Audit Log Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "soar-audit-kms-key"
    Environment = "Production"
  }
}

resource "aws_kms_alias" "soar_audit_key_alias" {
  name          = "alias/soar-audit-key"
  target_key_id = aws_kms_key.soar_audit_key.key_id
}
