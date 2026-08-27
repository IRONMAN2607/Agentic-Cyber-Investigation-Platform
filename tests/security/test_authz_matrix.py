from __future__ import annotations

import pytest
from httpx import AsyncClient

from acip.types import Role

ENDPOINTS = [
    ("GET", "/api/v1/investigations", Role.VIEWER, 200),
    ("POST", "/api/v1/investigations", Role.VIEWER, 403),
    ("POST", "/api/v1/investigations", Role.INVESTIGATOR, 201),
    ("POST", "/api/v1/investigations", Role.ADMIN, 201),
    ("GET", "/api/v1/admin/capabilities", Role.VIEWER, 403),
    ("GET", "/api/v1/admin/capabilities", Role.INVESTIGATOR, 403),
    ("GET", "/api/v1/admin/capabilities", Role.ADMIN, 200),
]


@pytest.mark.parametrize("method,path,role,expected_status", ENDPOINTS)
async def test_endpoint_role_matrix(
    client: AsyncClient,
    auth_headers: dict[Role, dict[str, str]],
    method: str,
    path: str,
    role: Role,
    expected_status: int,
) -> None:
    headers = auth_headers[role]
    payload = {"title": "Matrix Test", "target_type": "log", "target_value": "auth.log"}
    if method == "GET":
        resp = await client.get(path, headers=headers)
    elif method == "POST":
        resp = await client.post(path, json=payload, headers=headers)
    else:
        raise ValueError(f"unsupported method {method}")
    assert resp.status_code == expected_status
