from __future__ import annotations

import pytest
from httpx import AsyncClient

from acip.types import Role

pytestmark = pytest.mark.asyncio


async def test_upload_pcap_artifact_success(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # 1. Create PCAP investigation
    resp_create = await client.post(
        "/api/v1/investigations",
        json={"title": "PCAP Triage", "target_type": "pcap", "target_value": "traffic.pcap"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_create.status_code == 201
    inv_id = resp_create.json()["id"]

    # 2. Upload valid PCAP
    pcap_bytes = b"\xa1\xb2\xc3\xd4" + b"\x00" * 64
    files = {"file": ("capture.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "pcap"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_upload.status_code == 201
    data = resp_upload.json()
    assert data["kind"] == "pcap"
    assert data["size_bytes"] == len(pcap_bytes)
    assert data["original_filename"] == "capture.pcap"


async def test_upload_pcap_mismatch_rejected(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    resp_create = await client.post(
        "/api/v1/investigations",
        json={"title": "PCAP Mismatch", "target_type": "pcap", "target_value": "traffic.pcap"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    inv_id = resp_create.json()["id"]

    # Plain text uploaded with kind="pcap"
    files = {"file": ("fake.pcap", b"plain text is not a pcap", "text/plain")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "pcap"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_upload.status_code == 422
    assert resp_upload.json()["code"] == "validation_error"
    assert "does not contain valid PCAP" in resp_upload.json()["message"]


async def test_ingest_text_artifact_endpoint(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    resp_create = await client.post(
        "/api/v1/investigations",
        json={"title": "Text Ingest", "target_type": "log", "target_value": "syslog.txt"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    inv_id = resp_create.json()["id"]

    payload = {
        "content": "Oct 11 22:14:15 host sshd[1234]: Accepted publickey for admin from 192.0.2.1",
        "filename": "syslog.txt",
        "declared_kind": "generic_text",
    }
    resp = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts/text",
        json=payload,
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["kind"] == "generic_text"
    assert data["size_bytes"] == len(payload["content"].encode("utf-8"))
    assert data["original_filename"] == "syslog.txt"


async def test_ingest_url_artifact_blocks_ssrf(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    resp_create = await client.post(
        "/api/v1/investigations",
        json={
            "title": "URL SSRF Ingest",
            "target_type": "url",
            "target_value": "http://example.com",
        },
        headers=auth_headers[Role.INVESTIGATOR],
    )
    inv_id = resp_create.json()["id"]

    # Attempting to fetch cloud metadata via /artifacts/url
    payload = {
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "declared_kind": "url_response",
    }
    resp = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts/url",
        json=payload,
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "ssrf_blocked"
    assert "cloud metadata" in resp.json()["message"]
