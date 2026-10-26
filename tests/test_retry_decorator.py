"""Unit tests for retry backoff decorator."""

import pytest
from soar_engine.utils.retry_decorator import retry_with_backoff


def test_retry_success():
    calls = []

    @retry_with_backoff(max_retries=3, base_delay=0.01)
    def test_func():
        calls.append(1)
        if len(calls) < 2:
            raise ValueError("Temporary glitch")
        return "SUCCESS"

    assert test_func() == "SUCCESS"
    assert len(calls) == 2
