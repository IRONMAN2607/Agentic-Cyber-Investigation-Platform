from __future__ import annotations

from httpx import AsyncClient


async def test_health(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["database"] == "ok"
    assert "version" in data


async def test_capabilities(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/capabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    assert "agents" in data
    assert "planner" in data
    assert "not_implemented" in data
    assert "operating_boundary" in data
