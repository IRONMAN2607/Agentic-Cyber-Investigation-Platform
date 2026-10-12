from __future__ import annotations

import datetime as dt
from uuid import uuid4

from acip.core.detection.web_rules import (
    RULE_COMMAND_INJECTION,
    RULE_ERROR_BURST,
    RULE_MALICIOUS_SCANNER,
    RULE_PATH_TRAVERSAL,
    RULE_SENSITIVE_FILE_RECON,
    RULE_SQL_INJECTION,
    RULE_SUCCESSFUL_EXPLOIT,
    RULE_WEBSHELL_ACCESS,
    WebEventView,
    evaluate_web_rules,
)
from acip.types import Severity


def test_sqli_detection() -> None:
    ev_id = uuid4()
    events = [
        WebEventView(
            evidence_id=ev_id,
            observed_at=dt.datetime(2026, 3, 10, 10, 0, 0, tzinfo=dt.UTC),
            client_ip="203.0.113.10",
            method="GET",
            path="/items",
            query_string="id=1 UNION SELECT 1,2,3",
            status_code=400,
            user_agent="curl/7.88",
            attacks=({"category": "sqli", "field": "query", "match": "UNION SELECT"},),
        )
    ]
    hits = evaluate_web_rules(events)
    assert len(hits) == 1
    assert hits[0].rule_id == RULE_SQL_INJECTION
    assert hits[0].severity == Severity.HIGH
    assert hits[0].evidence_ids == [ev_id]


def test_path_traversal_detection() -> None:
    ev_id = uuid4()
    events = [
        WebEventView(
            evidence_id=ev_id,
            observed_at=dt.datetime(2026, 3, 10, 10, 1, 0, tzinfo=dt.UTC),
            client_ip="203.0.113.10",
            method="GET",
            path="/../../etc/passwd",
            query_string=None,
            status_code=403,
            user_agent="Mozilla/5.0",
            attacks=({"category": "traversal", "field": "path", "match": "../.."},),
        )
    ]
    hits = evaluate_web_rules(events)
    assert len(hits) == 1
    assert hits[0].rule_id == RULE_PATH_TRAVERSAL
    assert hits[0].severity == Severity.HIGH


def test_command_injection_detection() -> None:
    ev_id = uuid4()
    events = [
        WebEventView(
            evidence_id=ev_id,
            observed_at=dt.datetime(2026, 3, 10, 10, 2, 0, tzinfo=dt.UTC),
            client_ip="203.0.113.10",
            method="POST",
            path="/api/exec",
            query_string="cmd=; whoami",
            status_code=500,
            user_agent="python-requests",
            attacks=({"category": "command_injection", "field": "query", "match": "; whoami"},),
        )
    ]
    hits = evaluate_web_rules(events)
    assert any(h.rule_id == RULE_COMMAND_INJECTION for h in hits)
    rce_hit = next(h for h in hits if h.rule_id == RULE_COMMAND_INJECTION)
    assert rce_hit.severity == Severity.CRITICAL


def test_webshell_and_successful_exploit() -> None:
    ev_id = uuid4()
    events = [
        WebEventView(
            evidence_id=ev_id,
            observed_at=dt.datetime(2026, 3, 10, 10, 3, 0, tzinfo=dt.UTC),
            client_ip="203.0.113.20",
            method="GET",
            path="/uploads/c99.php",
            query_string=None,
            status_code=200,  # 200 OK triggers RULE_SUCCESSFUL_EXPLOIT
            user_agent="Mozilla/5.0",
            attacks=({"category": "webshell", "field": "path", "match": "c99.php"},),
        )
    ]
    hits = evaluate_web_rules(events)
    rule_ids = {h.rule_id for h in hits}
    assert RULE_WEBSHELL_ACCESS in rule_ids
    assert RULE_SUCCESSFUL_EXPLOIT in rule_ids

    exploit_hit = next(h for h in hits if h.rule_id == RULE_SUCCESSFUL_EXPLOIT)
    assert exploit_hit.severity == Severity.CRITICAL


def test_scanner_and_recon_detection() -> None:
    ev_id = uuid4()
    events = [
        WebEventView(
            evidence_id=ev_id,
            observed_at=dt.datetime(2026, 3, 10, 10, 4, 0, tzinfo=dt.UTC),
            client_ip="203.0.113.30",
            method="GET",
            path="/.env",
            query_string=None,
            status_code=404,
            user_agent="sqlmap/1.5",
            attacks=(
                {"category": "sensitive_file", "field": "path", "match": ".env"},
                {"category": "scanner", "field": "user_agent", "match": "sqlmap"},
            ),
        )
    ]
    hits = evaluate_web_rules(events)
    rule_ids = {h.rule_id for h in hits}
    assert RULE_SENSITIVE_FILE_RECON in rule_ids
    assert RULE_MALICIOUS_SCANNER in rule_ids


def test_error_burst_detection() -> None:
    base_time = dt.datetime(2026, 3, 10, 10, 0, 0, tzinfo=dt.UTC)
    events = [
        WebEventView(
            evidence_id=uuid4(),
            observed_at=base_time + dt.timedelta(seconds=i * 5),
            client_ip="203.0.113.40",
            method="GET",
            path=f"/probe_{i}",
            query_string=None,
            status_code=404,
            user_agent="gobuster/3.1",
            attacks=(),
        )
        for i in range(12)
    ]
    hits = evaluate_web_rules(events, min_scan_errors=10, scan_window_seconds=120)
    assert any(h.rule_id == RULE_ERROR_BURST for h in hits)


def test_clean_traffic_produces_no_hits() -> None:
    events = [
        WebEventView(
            evidence_id=uuid4(),
            observed_at=dt.datetime(2026, 3, 10, 10, 0, 0, tzinfo=dt.UTC),
            client_ip="192.168.1.50",
            method="GET",
            path="/home",
            query_string="tab=about",
            status_code=200,
            user_agent="Mozilla/5.0 Chrome/120.0",
            attacks=(),
        )
    ]
    hits = evaluate_web_rules(events)
    assert len(hits) == 0
