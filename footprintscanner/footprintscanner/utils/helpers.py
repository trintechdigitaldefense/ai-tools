"""Utility helpers: rate limiting, caching, logging."""

from __future__ import annotations

import logging
import time
from functools import wraps
from threading import Lock
from typing import Any, Callable

logger = logging.getLogger("footprintscanner")


class RateLimiter:
    """Thread-safe token-bucket rate limiter."""

    def __init__(self, max_per_second: float = 1.0):
        self._min_interval = 1.0 / max_per_second
        self._last_call: float = 0.0
        self._lock = Lock()

    def acquire(self):
        """Wait until it's safe to make a request."""
        with self._lock:
            elapsed = time.monotonic() - self._last_call
            if elapsed < self._min_interval:
                sleep_time = self._min_interval - elapsed
                time.sleep(sleep_time)
            self._last_call = time.monotonic()


class Cache:
    """Simple in-memory LRU-ish cache for HTTP responses."""

    def __init__(self, ttl: float = 300.0):
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = Lock()
        self._ttl = ttl

    def get(self, key: str) -> Any | None:
        with self._lock:
            if key in self._store:
                value, timestamp = self._store[key]
                if time.monotonic() - timestamp < self._ttl:
                    return value
                else:
                    del self._store[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._store[key] = (value, time.monotonic())


def rate_limited(limiter: RateLimiter):
    """Decorator: apply rate limiting to a function."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter.acquire()
            return func(*args, **kwargs)

        return wrapper

    return decorator
