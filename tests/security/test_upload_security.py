from __future__ import annotations

from httpx import AsyncClient

from acip.types import Role


async def test_upload_path_traversal_sanitized(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # 1. Create investigation
    resp_create = await client.post(
        "/api/v1/investigations",
        json={"title": "Traversal Test", "target_type": "log", "target_value": "auth.log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    inv_id = resp_create.json()["id"]

    # 2. Upload with malicious filename attempting path traversal
    files = {"file": ("../../../../etc/shadow", b"dummy log content", "text/plain")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "linux_auth_log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_upload.status_code == 201
    art_data = resp_upload.json()
    assert art_data["original_filename"] == "shadow"
    assert ".." not in art_data["original_filename"]
    assert "/" not in art_data["original_filename"]


async def test_upload_empty_file_rejected(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    resp_create = await client.post(
        "/api/v1/investigations",
        json={"title": "Empty Test", "target_type": "log", "target_value": "auth.log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    inv_id = resp_create.json()["id"]

    files = {"file": ("empty.log", b"", "text/plain")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "linux_auth_log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_upload.status_code == 422
    assert resp_upload.json()["code"] == "validation_error"
