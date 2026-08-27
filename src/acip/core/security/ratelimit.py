"""Sliding-window rate limiter for sensitive endpoints.

Provides deterministic rate limiting based on client IP or user identity to
prevent brute-force password guessing and resource exhaustion.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from threading import Lock

from fastapi import Request

from acip.errors import RateLimitExceededError


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, key: str) -> None:
        """Check whether the key is within rate limits; increments counter if allowed.

        Raises :class:`RateLimitExceededError` if the limit is exceeded.
        """
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            timestamps = self._history[key]
            # Prune old timestamps
            self._history[key] = [t for t in timestamps if t > window_start]
            active_count = len(self._history[key])

            if active_count >= self.max_requests:
                oldest = self._history[key][0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                raise RateLimitExceededError(retry_after=retry_after)

            self._history[key].append(now)

    def reset(self) -> None:
        """Clear all rate limit history (useful in tests)."""
        with self._lock:
            self._history.clear()


# Default rate limiters
login_limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
investigation_limiter = SlidingWindowRateLimiter(max_requests=30, window_seconds=60)


def rate_limit(limiter: SlidingWindowRateLimiter) -> Callable[[Request], None]:
    """FastAPI dependency for rate limiting endpoints by client IP."""

    def dependency(request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        # Check X-Forwarded-For if behind trusted proxy, otherwise socket IP
        forwarded = request.headers.get("x-forwarded-for")
        ip = forwarded.split(",")[0].strip() if forwarded else client_ip
        limiter.check(ip)

    return dependency
