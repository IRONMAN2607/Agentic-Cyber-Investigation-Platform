from __future__ import annotations

import asyncio
import io
import uuid

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from acip.config import Settings
from acip.types import Role


@pytest.fixture
def investigator_auth(auth_headers: dict[Role, dict[str, str]]) -> dict[str, str]:
    return auth_headers[Role.INVESTIGATOR]


async def test_investigation_full_lifecycle_api(
    client: AsyncClient,
    investigator_auth: dict[str, str],
    settings: Settings,
    app: FastAPI,
) -> None:
    # 1. Create investigation
    create_resp = await client.post(
        "/api/v1/investigations",
        json={"title": "Lifecycle Test", "target_type": "log", "target_value": "auth.log"},
        headers=investigator_auth,
    )
    assert create_resp.status_code == 201
    inv_data = create_resp.json()
    inv_id = inv_data["id"]
    assert inv_data["status"] == "created"

    # 2. Update investigation metadata
    patch_resp = await client.patch(
        f"/api/v1/investigations/{inv_id}",
        json={"title": "Updated Title", "retention_state": "derived_only"},
        headers=investigator_auth,
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["title"] == "Updated Title"
    assert patch_resp.json()["retention_state"] == "derived_only"

    # 3. Check initial progress (0%)
    prog_resp = await client.get(
        f"/api/v1/investigations/{inv_id}/progress",
        headers=investigator_auth,
    )
    assert prog_resp.status_code == 200
    assert prog_resp.json()["percent_complete"] == 0.0

    # 4. Upload artifact
    sample_content = (
        b"Aug 26 00:00:01 host sshd[123]: Failed password for root from 192.168.1.5 port 22 ssh2\n"
    )
    upload_resp = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files={"file": ("auth.log", io.BytesIO(sample_content), "text/plain")},
        data={"kind": "linux_auth_log"},
        headers=investigator_auth,
    )
    assert upload_resp.status_code == 201

    # 5. Start investigation
    start_resp = await client.post(
        f"/api/v1/investigations/{inv_id}/start",
        headers=investigator_auth,
    )
    assert start_resp.status_code == 200
    assert start_resp.json()["accepted"] is True

    # 6. Await execution via runner
    services = app.state.services
    await services.runner.wait_all()

    # 7. Check tasks and final progress
    tasks_resp = await client.get(
        f"/api/v1/investigations/{inv_id}/tasks",
        headers=investigator_auth,
    )
    assert tasks_resp.status_code == 200
    tasks = tasks_resp.json()
    assert len(tasks) >= 3

    final_prog = await client.get(
        f"/api/v1/investigations/{inv_id}/progress",
        headers=investigator_auth,
    )
    assert final_prog.status_code == 200
    assert final_prog.json()["percent_complete"] == 100.0
    assert final_prog.json()["status"] in {"completed", "partial"}

    # 8. Fetch report
    report_resp = await client.get(
        f"/api/v1/investigations/{inv_id}/report",
        headers=investigator_auth,
    )
    assert report_resp.status_code == 200
    assert len(report_resp.json()["content"]) > 0

    # 9. An investigation holding append-only records refuses a plain delete,
    #    and the refusal names what would have been destroyed.
    refused = await client.delete(
        f"/api/v1/investigations/{inv_id}",
        headers=investigator_auth,
    )
    assert refused.status_code == 409
    refusal = refused.json()
    assert refusal["code"] == "conflict"
    assert refusal["detail"]["records"]["evidence"] > 0
    assert refusal["detail"]["retry_with"] == "?purge=true"

    # 10. The explicit purge succeeds.
    del_resp = await client.delete(
        f"/api/v1/investigations/{inv_id}",
        params={"purge": "true"},
        headers=investigator_auth,
    )
    assert del_resp.status_code == 204

    # Verify 404 after deletion
    get_del = await client.get(
        f"/api/v1/investigations/{inv_id}",
        headers=investigator_auth,
    )
    assert get_del.status_code == 404


async def test_investigation_lifecycle_failure_paths(
    client: AsyncClient,
    investigator_auth: dict[str, str],
    app: FastAPI,
) -> None:
    # 1. Non-existent ID returns 404
    missing_id = str(uuid.uuid4())
    resp_404 = await client.get(
        f"/api/v1/investigations/{missing_id}",
        headers=investigator_auth,
    )
    assert resp_404.status_code == 404

    # 2. Blank title returns 422
    resp_422 = await client.post(
        "/api/v1/investigations",
        json={"title": "   ", "target_type": "log", "target_value": "test"},
        headers=investigator_auth,
    )
    assert resp_422.status_code == 422

    # 3. Create valid investigation
    create_resp = await client.post(
        "/api/v1/investigations",
        json={"title": "Conflict Test", "target_type": "log", "target_value": "auth.log"},
        headers=investigator_auth,
    )
    inv_id = create_resp.json()["id"]

    # 4. Starting and then starting again returns 409 Conflict
    await client.post(f"/api/v1/investigations/{inv_id}/start", headers=investigator_auth)
    second_start = await client.post(
        f"/api/v1/investigations/{inv_id}/start", headers=investigator_auth
    )
    assert second_start.status_code == 409

    # Wait for completion
    services = app.state.services
    await services.runner.wait_all()

    # 5. Uploading artifact to completed investigation returns 409 Conflict
    upload_conflict = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files={"file": ("auth.log", io.BytesIO(b"log data"), "text/plain")},
        headers=investigator_auth,
    )
    assert upload_conflict.status_code == 409

    # 6. Cancelling completed investigation returns 409 Conflict
    cancel_conflict = await client.post(
        f"/api/v1/investigations/{inv_id}/cancel",
        headers=investigator_auth,
    )
    assert cancel_conflict.status_code == 409

    # 7. Retrying a completed investigation (if not failed/partial/halted) returns 409 or re-queues if partial
    # Let's test retry on a halted investigation
    inv2 = (
        await client.post(
            "/api/v1/investigations",
            json={"title": "Halt and Retry", "target_type": "log", "target_value": "auth.log"},
            headers=investigator_auth,
        )
    ).json()

    cancel_resp = await client.post(
        f"/api/v1/investigations/{inv2['id']}/cancel",
        headers=investigator_auth,
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "halted"

    # Retry the halted investigation
    retry_resp = await client.post(
        f"/api/v1/investigations/{inv2['id']}/retry",
        headers=investigator_auth,
    )
    assert retry_resp.status_code == 200
    assert retry_resp.json()["accepted"] is True
    await services.runner.wait_all()


async def test_investigation_concurrent_start_requests(
    client: AsyncClient,
    investigator_auth: dict[str, str],
    app: FastAPI,
) -> None:
    """Concurrent start requests elect exactly one starter; the rest receive 409 Conflict."""
    create_resp = await client.post(
        "/api/v1/investigations",
        json={"title": "Concurrent Start Test", "target_type": "log", "target_value": "auth.log"},
        headers=investigator_auth,
    )
    assert create_resp.status_code == 201
    inv_id = create_resp.json()["id"]

    responses = await asyncio.gather(
        *[
            client.post(f"/api/v1/investigations/{inv_id}/start", headers=investigator_auth)
            for _ in range(10)
        ]
    )

    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1
    assert statuses.count(409) == 9

    accepted_resp = next(r.json() for r in responses if r.status_code == 200)
    assert accepted_resp["accepted"] is True

    services = app.state.services
    await services.runner.wait_all()
