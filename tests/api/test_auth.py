from __future__ import annotations

from httpx import AsyncClient

from acip.types import Role


async def test_auth_login_success(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin-password-123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"


async def test_auth_login_invalid_password(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "authentication_failed"


async def test_auth_me_endpoint(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # Unauthenticated -> 401
    resp_unauth = await client.get("/api/v1/auth/me")
    assert resp_unauth.status_code == 401

    # Authenticated -> returns user details
    resp_auth = await client.get("/api/v1/auth/me", headers=auth_headers[Role.INVESTIGATOR])
    assert resp_auth.status_code == 200
    data = resp_auth.json()
    assert data["username"] == "test_investigator"
    assert data["role"] == "investigator"
