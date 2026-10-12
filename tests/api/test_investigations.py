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

    # 9. Hypotheses endpoint & detail check
    assert "hypotheses" in detail
    resp_hyp = await client.get(
        f"/api/v1/investigations/{inv_id}/hypotheses",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_hyp.status_code == 200
    assert isinstance(resp_hyp.json(), list)

    # 10. Evidence Graph & Timeline endpoints
    resp_graph = await client.get(
        f"/api/v1/investigations/{inv_id}/graph",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_graph.status_code == 200
    assert "entities" in resp_graph.json()
    assert "edges" in resp_graph.json()

    resp_timeline = await client.get(
        f"/api/v1/investigations/{inv_id}/timeline",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_timeline.status_code == 200
    assert "events" in resp_timeline.json()

    # 11. Real-time Events SSE Stream handshake
    resp_events = await client.get(
        f"/api/v1/investigations/{inv_id}/events",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_events.status_code == 200
    assert resp_events.headers["content-type"].startswith("text/event-stream")
    # Verify stream emitted event data
    assert "data: " in resp_events.text


async def test_investigation_creation_all_target_types(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    """Verify that all target types can be created with canonicalization and defanging."""
    targets = [
        ("domain", "evil-attacker.example.com", "evil-attacker.example.com"),
        ("domain", "https://evil-attacker.example.com/login", "evil-attacker.example.com"),
        ("domain", "evil[.]malicious[.]org", "evil.malicious.org"),
        ("url", "https://malicious.example.com/payload.sh", "https://malicious.example.com/payload.sh"),
        ("url", "evil-attacker.example.com/login", "https://evil-attacker.example.com/login"),
        ("url", "hxxps://evil[.]org/malware.exe", "https://evil.org/malware.exe"),
        ("ip", "198.51.100.23", "198.51.100.23"),
        ("ip", "198.51.100[.]23", "198.51.100.23"),
        ("ip", "198.51.100.23:8080", "198.51.100.23"),
        ("hash", "44d88612fea8a8f36de82e1278abb02f", "44d88612fea8a8f36de82e1278abb02f"),
        ("hash", "MD5: 44D88612FEA8A8F36DE82E1278ABB02F", "44d88612fea8a8f36de82e1278abb02f"),
        ("log", "access.log", "access.log"),
        ("pcap", "traffic.pcap", "traffic.pcap"),
        ("file", "suspicious.exe", "suspicious.exe"),
        ("description", "Multiple failed ssh logins followed by root elevation", "Multiple failed ssh logins followed by root elevation"),
    ]

    for target_type, input_val, expected_val in targets:
        resp = await client.post(
            "/api/v1/investigations",
            json={
                "title": f"Test {target_type}: {input_val}",
                "target_type": target_type,
                "target_value": input_val,
            },
            headers=auth_headers[Role.INVESTIGATOR],
        )
        assert resp.status_code == 201, f"Failed for {target_type} with input '{input_val}': {resp.text}"
        data = resp.json()
        assert data["target_type"] == target_type
        assert data["target_value"] == expected_val


async def test_investigation_validation_error_formatting(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    """Verify that validation errors return a descriptive formatted message."""
    resp = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Bad Domain Inv",
            "target_type": "domain",
            "target_value": "ex ample.com",
        },
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp.status_code == 422
    err_body = resp.json()
    assert err_body["code"] == "validation_error"
    assert "domain label" in err_body["message"]
    assert "contains invalid characters" in err_body["message"]

