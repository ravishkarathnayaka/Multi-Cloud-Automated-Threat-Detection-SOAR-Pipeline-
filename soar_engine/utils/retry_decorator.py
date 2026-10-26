"""Resilient Exponential Backoff Retry Decorator."""

import functools
import time
from typing import Any, Callable


def retry_with_backoff(max_retries: int = 3, base_delay: float = 0.5):
    """Decorator applying exponential backoff to Boto3 client API calls."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            delay = base_delay
            last_err = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    last_err = exc
                    time.sleep(delay)
                    delay *= 2
            raise last_err
        return wrapper
    return decorator
