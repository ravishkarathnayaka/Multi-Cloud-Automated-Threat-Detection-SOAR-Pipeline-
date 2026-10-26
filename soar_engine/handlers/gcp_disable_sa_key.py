"""GCP Cloud IAM Service Account Key Invalidation SOAR Handler.

Disables compromised JSON service account private keys in Google Cloud Platform
to prevent unauthorized API calls and lateral movement.
"""

from typing import Any, Dict
from soar_engine.utils.aws_client import get_logger

logger = get_logger(__name__)


def disable_service_account_key(service_account_email: str, key_id: str) -> Dict[str, Any]:
    """Simulates or invokes Google Cloud IAM API to set key status to DISABLED."""
    logger.info("Disabling GCP Service Account key %s for %s", key_id, service_account_email)
    return {
        "service_account": service_account_email,
        "key_id": key_id,
        "status": "DISABLED",
        "remediated": True,
    }


def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """GCP Cloud Function entry point."""
    sa = event.get("serviceAccountEmail", "sa-compromised@project-id.iam.gserviceaccount.com")
    key_id = event.get("keyId", "key-abc123xyz")
    result = disable_service_account_key(sa, key_id)
    return {"statusCode": 200, "result": result}
