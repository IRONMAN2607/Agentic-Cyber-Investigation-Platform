from __future__ import annotations

import asyncio

import pytest
from httpx import AsyncClient

from acip.types import InvestigationStatus, Role, Severity

WEB_ATTACK_FIXTURE = "\n".join(
    [
        '203.0.113.80 - - [10/Mar/2026:04:00:01 +0000] "GET /index.html HTTP/1.1" 200 4012 "-" "Mozilla/5.0"',
        '203.0.113.80 - - [10/Mar/2026:04:00:05 +0000] "GET /products.php?id=1%20UNION%20SELECT%20user,pass%20FROM%20users HTTP/1.1" 200 8912 "-" "sqlmap/1.5.2"',
        '203.0.113.80 - - [10/Mar/2026:04:00:10 +0000] "GET /../../etc/passwd HTTP/1.1" 403 280 "-" "Nikto/2.1.6"',
        '203.0.113.80 - - [10/Mar/2026:04:00:15 +0000] "POST /cgi-bin/status?cmd=;%20whoami HTTP/1.1" 500 120 "-" "curl/7.88.1"',
        '203.0.113.80 - - [10/Mar/2026:04:00:20 +0000] "GET /uploads/c99.php HTTP/1.1" 200 15200 "-" "Mozilla/5.0"',
        '203.0.113.80 - - [10/Mar/2026:04:00:25 +0000] "GET /.env HTTP/1.1" 404 180 "-" "gobuster/3.1.0"',
        "",
    ]
)

CLEAN_WEB_FIXTURE = "\n".join(
    [
        '192.168.1.10 - alice [10/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '192.168.1.11 - bob [10/Mar/2026:08:05:00 +0000] "GET /about.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        "",
    ]
)


pytestmark = pytest.mark.parametrize("settings", [False, True], indirect=True)


async def test_web_log_attack_scenario(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # 1. Create investigation
    resp = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Web01 Access Log Incident Investigation",
            "target_type": "log",
            "target_value": "access.log",
        },
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp.status_code == 201
    inv_id = resp.json()["id"]

    # 2. Upload web server log artifact
    files = {"file": ("access.log", WEB_ATTACK_FIXTURE.encode("utf-8"), "text/plain")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "web_server_log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_upload.status_code == 201

    # 3. Start investigation
    resp_start = await client.post(
        f"/api/v1/investigations/{inv_id}/start",
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_start.status_code == 200

    # 4. Wait for completion
    for _ in range(60):
        await asyncio.sleep(0.1)
        resp_detail = await client.get(
            f"/api/v1/investigations/{inv_id}", headers=auth_headers[Role.VIEWER]
        )
        assert resp_detail.status_code == 200
        detail = resp_detail.json()
        if detail["investigation"]["status"] in {
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.FAILED.value,
            InvestigationStatus.PARTIAL.value,
        }:
            break

    assert detail["investigation"]["status"] == InvestigationStatus.COMPLETED.value
    assert detail["investigation"]["severity"] in {Severity.HIGH.value, Severity.CRITICAL.value}
    assert (
        detail["investigation"]["risk_score"] is not None
        and detail["investigation"]["risk_score"] > 20
    )

    # 5. Verify web attack detection rules fired
    findings = detail["findings"]
    assert len(findings) >= 4
    detection_rules = {f["detection_rule"] for f in findings if f["detection_rule"]}
    assert "R-WEB-001" in detection_rules  # SQL injection
    assert "R-WEB-002" in detection_rules  # Path traversal
    assert "R-WEB-003" in detection_rules  # Command injection
    assert "R-WEB-004" in detection_rules  # Web shell
    assert "R-WEB-005" in detection_rules  # Sensitive file recon
    assert "R-WEB-006" in detection_rules  # Scanner detected
    assert "R-WEB-008" in detection_rules  # Successful exploit

    # 6. Verify report contains findings and web access timeline
    resp_report = await client.get(
        f"/api/v1/investigations/{inv_id}/report",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_report.status_code == 200
    report_text = resp_report.json()["content"]
    assert "web_server_log_parser" in report_text
    assert "R-WEB-001" in report_text
    assert "SQL injection" in report_text
    assert "203.0.113.80" in report_text


async def test_clean_web_log_scenario(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # 1. Create clean investigation
    resp = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Clean Web Log Baseline",
            "target_type": "log",
            "target_value": "clean_access.log",
        },
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp.status_code == 201
    inv_id = resp.json()["id"]

    # 2. Upload clean web log
    files = {"file": ("access.log", CLEAN_WEB_FIXTURE.encode("utf-8"), "text/plain")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "web_server_log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_upload.status_code == 201

    # 3. Start investigation
    resp_start = await client.post(
        f"/api/v1/investigations/{inv_id}/start",
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_start.status_code == 200

    for _ in range(60):
        await asyncio.sleep(0.1)
        resp_detail = await client.get(
            f"/api/v1/investigations/{inv_id}", headers=auth_headers[Role.VIEWER]
        )
        assert resp_detail.status_code == 200
        detail = resp_detail.json()
        if detail["investigation"]["status"] in {
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.FAILED.value,
            InvestigationStatus.PARTIAL.value,
        }:
            break

    assert detail["investigation"]["status"] == InvestigationStatus.COMPLETED.value
    # In clean logs, only baseline triage/parsing facts exist; zero threat findings (no R-WEB hits)
    threat_findings = [
        f for f in detail["findings"] if (f["detection_rule"] or "").startswith("R-WEB-")
    ]
    assert len(threat_findings) == 0
    assert detail["investigation"]["severity"] == Severity.INFO.value
    assert detail["investigation"]["risk_score"] <= 5
