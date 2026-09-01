terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region                      = var.aws_region
  s3_use_path_style           = var.use_localstack
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      cloudtrail = var.localstack_endpoint
      cloudwatch = var.localstack_endpoint
      ec2        = var.localstack_endpoint
      events     = var.localstack_endpoint
      iam        = var.localstack_endpoint
      lambda     = var.localstack_endpoint
      logs       = var.localstack_endpoint
      s3         = var.localstack_endpoint
      sns        = var.localstack_endpoint
      sqs        = var.localstack_endpoint
      sts        = var.localstack_endpoint
    }
  }

  default_tags {
    tags = {
      Project     = "Multi-Cloud-Threat-Detection-SOAR"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
