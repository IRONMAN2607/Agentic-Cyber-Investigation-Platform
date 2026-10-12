from __future__ import annotations

import datetime as dt
from pathlib import Path
from uuid import uuid4

import pytest

from acip.tools.base import ToolContext
from acip.tools.web_log_parser import WebServerLogParser, WebServerLogParserArgs
from acip.types import EntityType, EvidenceKind, SandboxTier, TimeConfidence

COMBINED_SAMPLE = """198.51.100.10 - alice [10/Mar/2026:03:10:55 +0000] "GET /index.php HTTP/1.1" 200 4520 "https://example.com" "Mozilla/5.0"
198.51.100.25 - - [10/Mar/2026:03:11:00 +0000] "GET /products.php?id=1%20UNION%20SELECT%20user,pass%20FROM%20users HTTP/1.1" 200 8912 "-" "sqlmap/1.5.2"
198.51.100.25 - - [10/Mar/2026:03:11:05 +0000] "GET /../../etc/passwd HTTP/1.1" 403 280 "-" "Nikto/2.1.6"
198.51.100.30 - - [10/Mar/2026:03:11:10 +0000] "POST /cgi-bin/test.sh?cmd=;%20whoami HTTP/1.1" 500 120 "-" "curl/7.88.1"
198.51.100.30 - - [10/Mar/2026:03:11:15 +0000] "GET /uploads/c99.php HTTP/1.1" 200 15200 "-" "Mozilla/5.0"
198.51.100.30 - - [10/Mar/2026:03:11:20 +0000] "GET /.env HTTP/1.1" 404 180 "-" "gobuster/3.1.0"
This is a garbage malformed log line that should not match anything
"""

COMMON_SAMPLE = """192.168.1.50 - bob [10/Mar/2026:12:00:00 +0000] "GET /home HTTP/1.0" 200 1234
192.168.1.51 - - [10/Mar/2026:12:01:00 +0000] "POST /api/login HTTP/1.1" 401 532
"""


def test_web_log_parser_probe() -> None:
    parser = WebServerLogParser()
    avail = parser.probe()
    assert avail.name == "web_server_log_parser"
    assert avail.version == "1.0.0"
    assert avail.tier == SandboxTier.T0_IN_PROCESS
    assert avail.available is True


def test_parse_combined_log_format() -> None:
    parser = WebServerLogParser()
    args = WebServerLogParserArgs(max_lines=100, detect_attacks=True)
    result = parser.parse_text(COMBINED_SAMPLE, args)

    assert result.exit_status == 0
    assert result.metrics["lines_total"] == 7
    assert result.metrics["lines_matched"] == 6
    assert result.metrics["lines_unrecognized"] == 1
    assert result.metrics["attacks_detected"] > 0
    assert len(result.warnings) == 1
    assert "1 of 7 line(s) did not match" in result.warnings[0]

    # Verify evidence items
    evidence = result.evidence
    assert len(evidence) == 6

    # 1st line: Clean request
    req1 = evidence[0]
    assert req1.kind == EvidenceKind.WEB_REQUEST
    assert req1.data["client_ip"] == "198.51.100.10"
    assert req1.data["user"] == "alice"
    assert req1.data["method"] == "GET"
    assert req1.data["path"] == "/index.php"
    assert req1.data["status_code"] == 200
    assert req1.time_confidence == TimeConfidence.EXACT
    assert req1.observed_at == dt.datetime(2026, 3, 10, 3, 10, 55, tzinfo=dt.UTC)

    entities = {e.type: e.value for e in req1.entities}
    assert entities[EntityType.IP] == "198.51.100.10"
    assert entities[EntityType.URL] == "/index.php"
    assert entities[EntityType.USER] == "alice"

    # 2nd line: SQL injection attack + sqlmap scanner
    req2 = evidence[1]
    assert req2.kind == EvidenceKind.WEB_ATTACK
    assert req2.data["client_ip"] == "198.51.100.25"
    assert any(a["category"] == "sqli" for a in req2.data["attacks"])
    assert any(a["category"] == "scanner" for a in req2.data["attacks"])

    # 3rd line: Directory traversal + Nikto scanner
    req3 = evidence[2]
    assert req3.kind == EvidenceKind.WEB_ATTACK
    assert any(a["category"] == "traversal" for a in req3.data["attacks"])
    assert any(a["category"] == "scanner" for a in req3.data["attacks"])

    # 4th line: Command injection
    req4 = evidence[3]
    assert req4.kind == EvidenceKind.WEB_ATTACK
    assert any(a["category"] == "command_injection" for a in req4.data["attacks"])

    # 5th line: Web shell access
    req5 = evidence[4]
    assert req5.kind == EvidenceKind.WEB_ATTACK
    assert any(a["category"] == "webshell" for a in req5.data["attacks"])

    # 6th line: Sensitive file reconnaissance + gobuster scanner
    req6 = evidence[5]
    assert req6.kind == EvidenceKind.WEB_ATTACK
    assert any(a["category"] == "sensitive_file" for a in req6.data["attacks"])


def test_parse_common_log_format() -> None:
    parser = WebServerLogParser()
    args = WebServerLogParserArgs(max_lines=100, detect_attacks=False)
    result = parser.parse_text(COMMON_SAMPLE, args)

    assert result.metrics["lines_matched"] == 2
    assert result.metrics["lines_unrecognized"] == 0
    assert len(result.evidence) == 2
    assert result.evidence[0].data["client_ip"] == "192.168.1.50"
    assert result.evidence[0].data["user"] == "bob"
    assert result.evidence[0].data["status_code"] == 200
    assert result.evidence[1].data["status_code"] == 401


def test_max_lines_truncation() -> None:
    parser = WebServerLogParser()
    args = WebServerLogParserArgs(max_lines=2)
    result = parser.parse_text(COMBINED_SAMPLE, args)

    assert result.metrics["truncated"] is True
    assert len(result.evidence) == 2
    assert any("truncated at max_lines=2" in w for w in result.warnings)


def test_lossy_utf8_warning() -> None:
    parser = WebServerLogParser()
    args = WebServerLogParserArgs()
    result = parser.parse_text(COMMON_SAMPLE, args, lossy=True)

    assert any("not valid UTF-8" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_execute_from_artifact(tmp_path: Path) -> None:
    log_file = tmp_path / "access.log"
    log_file.write_text(COMBINED_SAMPLE, encoding="utf-8")

    parser = WebServerLogParser()
    ctx = ToolContext(
        investigation_id=uuid4(),
        artifact_id=uuid4(),
        artifact_path=log_file,
    )
    result = await parser.execute(WebServerLogParserArgs(), ctx)

    assert result.exit_status == 0
    assert result.metrics["lines_matched"] == 6
    assert result.metrics["attacks_detected"] > 0
