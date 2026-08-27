from __future__ import annotations

import asyncio

from httpx import AsyncClient

from acip.types import Role

SAMPLE_LOG = "\n".join(
    [
        "Mar 10 03:11:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.55 port 44120 ssh2",
        "Mar 10 03:11:05 web01 sshd[1235]: Failed password for invalid user root from 203.0.113.55 port 44122 ssh2",
        "Mar 10 03:11:09 web01 sshd[1236]: Failed password for invalid user test from 203.0.113.55 port 44124 ssh2",
        "Mar 10 03:11:12 web01 sshd[1237]: Failed password for deploy from 203.0.113.55 port 44126 ssh2",
        "Mar 10 03:11:15 web01 sshd[1238]: Failed password for deploy from 203.0.113.55 port 44128 ssh2",
        "Mar 10 03:11:20 web01 sshd[1239]: Accepted password for deploy from 203.0.113.55 port 44130 ssh2",
        "Mar 10 03:11:25 web01 sudo[1245]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "",
    ]
)


async def test_investigation_crud_and_lifecycle(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # 1. Viewer cannot create investigation (403)
    resp_viewer_create = await client.post(
        "/api/v1/investigations",
        json={"title": "Unauthorized Inv", "target_type": "log", "target_value": "auth.log"},
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_viewer_create.status_code == 403

    # 2. Investigator creates investigation (201)
    resp_create = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Suspicious Login Analysis",
            "target_type": "log",
            "target_value": "auth.log",
        },
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_create.status_code == 201
    inv_data = resp_create.json()
    inv_id = inv_data["id"]
    assert inv_data["status"] == "created"

    # 3. List investigations (200)
    resp_list = await client.get("/api/v1/investigations", headers=auth_headers[Role.VIEWER])
    assert resp_list.status_code == 200
    assert len(resp_list.json()) >= 1

    # 4. Upload artifact
    files = {"file": ("auth.log", SAMPLE_LOG.encode("utf-8"), "text/plain")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "linux_auth_log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_upload.status_code == 201
    art_data = resp_upload.json()
    assert art_data["original_filename"] == "auth.log"

    # 5. Start investigation
    resp_start = await client.post(
        f"/api/v1/investigations/{inv_id}/start",
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_start.status_code == 200
    assert resp_start.json()["accepted"] is True

    # 6. Poll for completion
    for _ in range(50):
        await asyncio.sleep(0.1)
        resp_detail = await client.get(
            f"/api/v1/investigations/{inv_id}", headers=auth_headers[Role.VIEWER]
        )
        assert resp_detail.status_code == 200
        detail = resp_detail.json()
        if detail["investigation"]["status"] in {"completed", "partial", "failed"}:
            break

    assert detail["investigation"]["status"] == "completed"
    assert len(detail["findings"]) >= 1
    assert detail["report"] is not None

    # 7. Check evidence pagination
    resp_evidence = await client.get(
        f"/api/v1/investigations/{inv_id}/evidence?limit=5&offset=0",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_evidence.status_code == 200
    ev_data = resp_evidence.json()
    assert ev_data["total"] > 0
    assert len(ev_data["items"]) <= 5

    # 8. Fetch report
    resp_report = await client.get(
        f"/api/v1/investigations/{inv_id}/report",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_report.status_code == 200
    report_data = resp_report.json()
    assert "# Investigation Report" in report_data["content"]
    assert "203.0.113.55" in report_data["content"]
