from __future__ import annotations

from httpx import AsyncClient

from acip.types import Role


async def test_public_capabilities(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/capabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    assert "agents" in data
    assert "planner" in data
    assert "not_implemented" in data
    assert isinstance(data["tools"], list)
    assert isinstance(data["agents"], list)
    assert len(data["not_implemented"]) > 0


async def test_admin_capabilities_access_control(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # Unauthenticated -> 401
    resp_unauth = await client.get("/api/v1/admin/capabilities")
    assert resp_unauth.status_code == 401

    # Viewer -> 403
    resp_viewer = await client.get("/api/v1/admin/capabilities", headers=auth_headers[Role.VIEWER])
    assert resp_viewer.status_code == 403

    # Investigator -> 403
    resp_investigator = await client.get(
        "/api/v1/admin/capabilities", headers=auth_headers[Role.INVESTIGATOR]
    )
    assert resp_investigator.status_code == 403

    # Admin -> 200 with full probe diagnostics
    resp_admin = await client.get("/api/v1/admin/capabilities", headers=auth_headers[Role.ADMIN])
    assert resp_admin.status_code == 200
    data = resp_admin.json()
    assert len(data["tools"]) > 0
    assert "available" in data["tools"][0]
    assert "tier" in data["tools"][0]
