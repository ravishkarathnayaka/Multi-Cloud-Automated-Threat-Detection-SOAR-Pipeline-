"""Cryptographic Log Integrity Hasher."""

import hashlib
from typing import Any, Dict


def compute_evidence_hash(evidence_data: str) -> str:
    """Computes SHA-256 digital fingerprint of incident evidence."""
    return hashlib.sha256(evidence_data.encode("utf-8")).hexdigest()
