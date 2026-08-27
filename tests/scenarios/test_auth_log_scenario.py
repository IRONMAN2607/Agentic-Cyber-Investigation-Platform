from __future__ import annotations

import asyncio

from httpx import AsyncClient

from acip.types import InvestigationStatus, Role, Severity

AUTH_LOG_FIXTURE = "\n".join(
    [
        "Mar 10 03:10:55 web01 sshd[1230]: Invalid user scanner1 from 203.0.113.55 port 44110 ssh2",
        "Mar 10 03:10:58 web01 sshd[1231]: Invalid user scanner2 from 203.0.113.55 port 44112 ssh2",
        "Mar 10 03:11:00 web01 sshd[1232]: Invalid user scanner3 from 203.0.113.55 port 44114 ssh2",
        "Mar 10 03:11:02 web01 sshd[1233]: Failed password for invalid user admin from 203.0.113.55 port 44116 ssh2",
        "Mar 10 03:11:05 web01 sshd[1234]: Failed password for invalid user root from 203.0.113.55 port 44118 ssh2",
        "Mar 10 03:11:08 web01 sshd[1235]: Failed password for invalid user test from 203.0.113.55 port 44120 ssh2",
        "Mar 10 03:11:11 web01 sshd[1236]: Failed password for deploy from 203.0.113.55 port 44122 ssh2",
        "Mar 10 03:11:14 web01 sshd[1237]: Failed password for deploy from 203.0.113.55 port 44124 ssh2",
        "Mar 10 03:11:18 web01 sshd[1238]: Accepted password for deploy from 203.0.113.55 port 44126 ssh2",
        "Mar 10 03:11:22 web01 sudo[1240]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "",
    ]
)

CLEAN_LOG_FIXTURE = "\n".join(
    [
        "Mar 10 08:00:00 web01 sshd[2001]: Accepted password for alice from 192.168.1.50 port 50100 ssh2",
        "Mar 10 08:05:00 web01 sshd[2002]: Accepted publickey for bob from 192.168.1.51 port 50102 ssh2",
        "",
    ]
)


async def test_auth_log_incident_scenario(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # 1. Create investigation
    resp = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Web01 Compromise Investigation",
            "target_type": "log",
            "target_value": "auth.log",
        },
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp.status_code == 201
    inv_id = resp.json()["id"]

    # 2. Upload attack artifact
    files = {"file": ("auth.log", AUTH_LOG_FIXTURE.encode("utf-8"), "text/plain")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "linux_auth_log"},
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

    # Verify findings count and details
    findings = detail["findings"]
    assert len(findings) >= 4
    detection_rules = {f["detection_rule"] for f in findings if f["detection_rule"]}
    assert "R-AUTH-001" in detection_rules  # Brute force
    assert "R-AUTH-003" in detection_rules  # Enumeration
    assert "R-AUTH-004" in detection_rules  # Privilege escalation

    # 5. Fetch report
    resp_report = await client.get(
        f"/api/v1/investigations/{inv_id}/report",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_report.status_code == 200
    report = resp_report.json()
    assert "203.0.113.55" in report["content"]
    assert "deploy" in report["content"]
    assert "Execution Trace" in report["content"]


async def test_clean_log_scenario(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    resp = await client.post(
        "/api/v1/investigations",
        json={"title": "Clean Log Baseline", "target_type": "log", "target_value": "auth.log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    inv_id = resp.json()["id"]

    files = {"file": ("auth.log", CLEAN_LOG_FIXTURE.encode("utf-8"), "text/plain")}
    await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "linux_auth_log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    await client.post(
        f"/api/v1/investigations/{inv_id}/start",
        headers=auth_headers[Role.INVESTIGATOR],
    )

    for _ in range(60):
        await asyncio.sleep(0.1)
        resp_detail = await client.get(
            f"/api/v1/investigations/{inv_id}", headers=auth_headers[Role.VIEWER]
        )
        detail = resp_detail.json()
        if detail["investigation"]["status"] in {
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.FAILED.value,
        }:
            break

    assert detail["investigation"]["status"] == InvestigationStatus.COMPLETED.value
    # In clean logs, only baseline triage/parsing facts exist, zero threat findings (no R-AUTH hits)
    threat_findings = [
        f for f in detail["findings"] if (f["detection_rule"] or "").startswith("R-AUTH-")
    ]
    assert len(threat_findings) == 0
    assert detail["investigation"]["severity"] == Severity.INFO.value
    assert detail["investigation"]["risk_score"] <= 5
