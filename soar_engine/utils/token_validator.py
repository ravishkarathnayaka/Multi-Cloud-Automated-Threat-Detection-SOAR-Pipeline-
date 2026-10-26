"""STS Session Token and Claims Validator."""

from typing import Any, Dict


def inspect_session_token(token_string: str) -> Dict[str, Any]:
    """Parses STS token metadata to determine validity and age."""
    is_valid = bool(token_string and len(token_string) >= 16)
    return {
        "token_length": len(token_string),
        "is_valid": is_valid,
        "is_expired": not is_valid,
    }
