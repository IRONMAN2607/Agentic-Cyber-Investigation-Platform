from __future__ import annotations

import pytest
from httpx import AsyncClient

from acip.core.security.ratelimit import (
    SlidingWindowRateLimiter,
    investigation_limiter,
    login_limiter,
)
from acip.types import Role


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


async def test_investigation_creation_is_rate_limited(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    """The investigation limiter was defined and wired to nothing.

    Login was the only limited endpoint, so an authenticated client could open
    investigations and upload artifacts without bound — the resource-exhaustion
    half of what the limiter exists to prevent. This asserts the limit is
    actually on the create path, not merely importable.
    """
    headers = auth_headers[Role.INVESTIGATOR]
    payload = {"title": "Rate limit probe", "target_type": "log", "target_value": "auth.log"}

    for _ in range(investigation_limiter.max_requests):
        resp = await client.post("/api/v1/investigations", json=payload, headers=headers)
        assert resp.status_code == 201

    blocked = await client.post("/api/v1/investigations", json=payload, headers=headers)
    assert blocked.status_code == 429
    assert blocked.json()["code"] == "rate_limit_exceeded"
    assert "retry_after" in blocked.json()["detail"]
