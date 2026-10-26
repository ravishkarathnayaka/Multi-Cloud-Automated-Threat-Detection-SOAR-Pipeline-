"""SOAR Playbook Handlers Package."""

from soar_engine.handlers.alert_dispatcher import lambda_handler as alert_dispatcher_handler
from soar_engine.handlers.block_nacl_egress import lambda_handler as block_nacl_handler
from soar_engine.handlers.block_waf_ip import lambda_handler as block_waf_handler
from soar_engine.handlers.isolate_ec2 import lambda_handler as isolate_ec2_handler
from soar_engine.handlers.quarantine_rds import lambda_handler as quarantine_rds_handler
from soar_engine.handlers.remediate_kms import lambda_handler as remediate_kms_handler
from soar_engine.handlers.remediate_s3 import lambda_handler as remediate_s3_handler
from soar_engine.handlers.remediate_secrets import lambda_handler as remediate_secrets_handler
from soar_engine.handlers.revoke_iam_session import lambda_handler as revoke_iam_handler

__all__ = [
    "isolate_ec2_handler",
    "revoke_iam_handler",
    "remediate_s3_handler",
    "alert_dispatcher_handler",
    "remediate_kms_handler",
    "quarantine_rds_handler",
    "remediate_secrets_handler",
    "block_waf_handler",
    "block_nacl_handler",
]
