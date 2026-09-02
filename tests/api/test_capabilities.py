from __future__ import annotations

import pytest
from httpx import AsyncClient

from acip.core.limitations import OPERATING_BOUNDARY
from acip.types import Role


async def test_public_capabilities(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/capabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert "environment" in data
    assert "tools" in data
    assert "agents" in data
    assert "planner" in data
    assert "not_implemented" in data
    assert "operating_boundary" in data
    assert isinstance(data["tools"], list)
    assert isinstance(data["agents"], list)
    assert len(data["not_implemented"]) > 0
    assert data["operating_boundary"] == OPERATING_BOUNDARY
    assert "localhost" in data["operating_boundary"].lower()
    assert "one trusted developer" in data["operating_boundary"].lower()
    # When enable_llm_triage is False (default), limitations state no language-model reasoning
    limitation_text = "\n".join(data["not_implemented"]).lower()
    assert "no language-model reasoning" in limitation_text


def test_capabilities_limitations_reflects_active_llm_flag() -> None:
    from acip.config import Settings
    from acip.core.limitations import get_not_implemented

    default_settings = Settings(enable_llm_triage=False)
    default_limits = "\n".join(get_not_implemented(default_settings)).lower()
    assert "no language-model reasoning" in default_limits

    active_settings = Settings(enable_llm_triage=True)
    active_limits = "\n".join(get_not_implemented(active_settings)).lower()
    assert "active for triage classification" in active_limits


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

    # Admin -> 200 with full probe diagnostics and operating boundary
    resp_admin = await client.get("/api/v1/admin/capabilities", headers=auth_headers[Role.ADMIN])
    assert resp_admin.status_code == 200
    data = resp_admin.json()
    assert len(data["tools"]) > 0
    assert "available" in data["tools"][0]
    assert "tier" in data["tools"][0]
    assert "operating_boundary" in data
    assert data["operating_boundary"] == OPERATING_BOUNDARY


def test_cli_capabilities_output(capsys: pytest.CaptureFixture[str]) -> None:
    import json

    from pydantic import SecretStr

    from acip.cli import _capabilities
    from acip.config import Settings

    settings = Settings(environment="test", secret_key=SecretStr("dummy"))
    _capabilities(settings)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["operating_boundary"] == OPERATING_BOUNDARY
    assert "localhost" in payload["operating_boundary"].lower()
    assert payload["environment"] == "test"
