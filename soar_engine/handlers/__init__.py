"""SOAR Playbook Handlers Package."""

from soar_engine.handlers.isolate_ec2 import lambda_handler as isolate_ec2_handler
from soar_engine.handlers.revoke_iam_session import lambda_handler as revoke_iam_handler
from soar_engine.handlers.remediate_s3 import lambda_handler as remediate_s3_handler
from soar_engine.handlers.alert_dispatcher import lambda_handler as alert_dispatcher_handler

__all__ = [
    "isolate_ec2_handler",
    "revoke_iam_handler",
    "remediate_s3_handler",
    "alert_dispatcher_handler",
]
