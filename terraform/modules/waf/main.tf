# AWS WAFv2 IPSet and Rate-Based Blocking Module

resource "aws_wafv2_ip_set" "soar_blocklist" {
  name               = "soar-malicious-ip-blocklist"
  description        = "Dynamic blocklist managed by SOAR Lambda containment playbooks"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  tags = {
    Environment = "Production"
    ManagedBy   = "SOAR-Pipeline"
  }
}
