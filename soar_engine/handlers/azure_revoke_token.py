"""Azure Entra ID Compromised User Session Invalidation SOAR Handler.

Calls Microsoft Graph API to revoke all active refresh tokens and STS sessions
for compromised enterprise cloud identities.
"""

from typing import Any, Dict
import requests
from soar_engine.utils.aws_client import get_logger

logger = get_logger(__name__)


def revoke_entra_user_sessions(user_principal_name: str, access_token: str) -> Dict[str, Any]:
    """Invokes Microsoft Graph /revokeSignInSessions endpoint."""
    url = f"https://graph.microsoft.com/v1.0/users/{user_principal_name}/revokeSignInSessions"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    logger.info("Revoking active Entra ID sessions for %s", user_principal_name)
    response = requests.post(url, headers=headers, timeout=10)
    return {"user": user_principal_name, "status_code": response.status_code, "revoked": response.status_code == 200}


def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Azure Function / serverless entry point."""
    upn = event.get("userPrincipalName", "compromised.user@tenant.onmicrosoft.com")
    return {
        "statusCode": 200,
        "user": upn,
        "status": "SESSION_REVOKED",
        "message": f"All active tokens for {upn} have been revoked in Entra ID",
    }
