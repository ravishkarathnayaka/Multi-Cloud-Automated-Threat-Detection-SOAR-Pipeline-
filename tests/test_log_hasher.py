"""Unit tests for log integrity hasher."""

from soar_engine.utils.log_hasher import compute_evidence_hash


def test_compute_evidence_hash():
    h1 = compute_evidence_hash("evidence_block_1")
    h2 = compute_evidence_hash("evidence_block_1")
    assert len(h1) == 64
    assert h1 == h2
