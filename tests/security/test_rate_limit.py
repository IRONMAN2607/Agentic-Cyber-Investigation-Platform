from __future__ import annotations

import pytest
from httpx import AsyncClient

from acip.core.security.ratelimit import SlidingWindowRateLimiter, login_limiter


def test_sliding_window_rate_limiter_unit() -> None:
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=2)
    key = "test-client"

    # 3 requests allowed
    limiter.check(key)
    limiter.check(key)
    limiter.check(key)

    # 4th request within window raises
    from acip.core.security.ratelimit import RateLimitExceededError

    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.check(key)

    assert exc_info.value.status_code == 429
    assert exc_info.value.detail["retry_after"] >= 1


async def test_auth_login_rate_limiting(client: AsyncClient) -> None:
    login_limiter.reset()

    # Fire 10 rapid failed login requests (max allowed)
    for _ in range(10):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "wrong-password"},
        )
        assert resp.status_code == 401

    # 11th request receives 429
    resp_blocked = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )
    assert resp_blocked.status_code == 429
    data = resp_blocked.json()
    assert data["code"] == "rate_limit_exceeded"
    assert "retry_after" in data["detail"]

    login_limiter.reset()
