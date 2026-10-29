"""Deterministic web server access log parser and attack detection adapter.

Parses Nginx, Apache, and W3C Combined/Common Log Format access logs into
normalised web access events. Evaluates deterministic cybersecurity attack
signatures (SQL injection, path traversal, command injection, web shells,
sensitive file reconnaissance, automated security scanners, and XSS).
"""

from __future__ import annotations

import datetime as dt
import re
import urllib.parse
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from acip.core.evidence.contracts import EntityRef, EvidenceDraft
from acip.errors import ToolError
from acip.logging import get_logger
from acip.tools.base import ToolAdapter, ToolContext, ToolResult
from acip.types import EntityType, EvidenceKind, SandboxTier, TimeConfidence

logger = get_logger(__name__)

# Combined Log Format: IP ident user [timestamp] "request" status bytes "referer" "user_agent"
# Common Log Format (CLF) is the prefix without referer and user_agent.
# Also accommodates syslog/journald/RFC-5424 prefixed lines
# (e.g. "2026-10-14T... host proc[pid]: IP ...")
_LOG_PATTERN = re.compile(
    r"^(?:(?P<syslog_time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<syslog_host>[\w.\-]+)\s+"
    r"(?P<syslog_proc>[\w.\-/]+?)(?:\[(?P<syslog_pid>\d+)\])?:\s+)?"
    r"(?P<ip>[\da-fA-F:.]+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?:\[(?P<time>[^\]]+)\]\s+)?"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r"(?:\s+(?P<extra>.*))?$"
)

_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}

# Attack detection regex signatures
_ATTACK_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (
        "sqli",
        re.compile(
            r"(?i)(?:\bunion\b[\s\+]+select|'[\s\+]*or[\s\+]+['\d]=['\d]|--|/\*|"
            r"information_schema|waitfor[\s\+]+delay|sleep\s*\(\d+\)|benchmark\s*\()",
        ),
    ),
    (
        "traversal",
        re.compile(
            r"(?i)(?:\.\./\.\.|\.\.\\\.\.|/\.\./|\\\.\.\\|/etc/passwd|/etc/shadow|"
            r"\bwin\.ini\b|\bboot\.ini\b|php://filter|php://input)",
        ),
    ),
    (
        "command_injection",
        re.compile(
            r"(?i)(?:;\s*(?:id|whoami|cat\s+/etc|uname|ls\s+-la)|"
            r"\|\s*(?:bash|sh|whoami|id|curl|wget)|\$\((?:id|whoami|cat|uname)\)|"
            r"/bin/(?:sh|bash)|powershell(?:\.exe)?|cmd(?:\.exe)?\s*/c)",
        ),
    ),
    (
        "webshell",
        re.compile(
            r"(?i)\b(?:c99|r57|wso|b374k|alfa|shell|cmd|eval-stdin|fx29)\.(?:php|jsp|asp|aspx)\b",
        ),
    ),
    (
        "sensitive_file",
        re.compile(
            r"(?i)(?:/\.env\b|/\.git(?:/|\b)|/\.svn(?:/|\b)|/wp-config\.php\b|"
            r"/config\.php\.bak\b|/web\.config\b|/database\.yml\b|/id_rsa\b)",
        ),
    ),
    (
        "scanner",
        re.compile(
            r"(?i)\b(?:sqlmap|nikto|dirbuster|gobuster|masscan|nuclei|wpscan|acunetix|nessus|nmap)\b",
        ),
    ),
    (
        "xss",
        re.compile(r"(?i)(?:<script\b|javascript:|onerror\s*=|onload\s*=|alert\s*\()"),
    ),
]

_MAX_RAW_CHARS = 512


class WebServerLogParserArgs(BaseModel):
    """Execution options for web server access log parsing."""

    max_lines: int = Field(default=200_000, ge=1, le=5_000_000)
    detect_attacks: bool = Field(
        default=True, description="Evaluate deterministic web attack signatures."
    )
    min_status_filter: int | None = Field(
        default=None, ge=100, le=599, description="Optional minimum HTTP status code to include."
    )


class WebServerLogParser(ToolAdapter):
    """Parses Apache, Nginx, and W3C web server access logs into structured events."""

    name: ClassVar[str] = "web_server_log_parser"
    version: ClassVar[str] = "1.0.0"
    tier: ClassVar[SandboxTier] = SandboxTier.T0_IN_PROCESS
    args_model: ClassVar[type[BaseModel]] = WebServerLogParserArgs
    description: ClassVar[str] = (
        "Parses Apache, Nginx, and W3C web server access logs and detects web attack vectors."
    )
    requires_artifact: ClassVar[bool] = True

    async def execute(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, WebServerLogParserArgs)
        if ctx.artifact_path is None:
            raise ToolError(f"{self.name} requires an artifact")

        from acip.core.security.files import read_text

        text, lossy = read_text(ctx.artifact_path)
        return self.parse_text(text, args, lossy=lossy)

    def parse_text(
        self,
        text: str,
        args: WebServerLogParserArgs,
        *,
        lossy: bool = False,
    ) -> ToolResult:
        """Parse log text deterministically. Separated from execute for direct testing."""
        warnings: list[str] = []
        if lossy:
            warnings.append("artifact was not valid UTF-8; decoded as latin-1")

        evidence: list[EvidenceDraft] = []
        lines_total = 0
        lines_matched = 0
        unrecognized = 0
        attacks_count = 0
        attacks_by_cat: dict[str, int] = {}
        status_distribution: dict[int, int] = {}
        unique_ips: set[str] = set()
        truncated = False

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            if line_number > args.max_lines:
                truncated = True
                break

            line = raw_line.strip()
            if not line:
                continue
            lines_total += 1

            match = _LOG_PATTERN.match(line)
            if match is None:
                unrecognized += 1
                continue

            lines_matched += 1
            ip = match.group("ip")
            ident = match.group("ident")
            user = match.group("user")
            user_clean = None if user == "-" else user
            time_str = match.group("time") or match.group("syslog_time")
            extra_str = match.group("extra")
            req_str = match.group("request")
            status_code = int(match.group("status"))
            bytes_raw = match.group("bytes")
            bytes_sent = int(bytes_raw) if bytes_raw.isdigit() else None
            referer = match.group("referer")
            user_agent = match.group("user_agent")

            if args.min_status_filter and status_code < args.min_status_filter:
                continue

            unique_ips.add(ip)
            status_distribution[status_code] = status_distribution.get(status_code, 0) + 1

            timestamp, time_confidence = _parse_timestamp(time_str)
            method, path, query_string, protocol = _parse_request(req_str)

            attacks_detected: list[dict[str, str]] = []
            if args.detect_attacks:
                attacks_detected = _detect_attacks(
                    path=path,
                    query_string=query_string,
                    req_str=req_str,
                    user_agent=user_agent or "",
                    extra=extra_str,
                )
                if attacks_detected:
                    attacks_count += len(attacks_detected)
                    for att in attacks_detected:
                        cat = att["category"]
                        attacks_by_cat[cat] = attacks_by_cat.get(cat, 0) + 1

            draft = _build_evidence_draft(
                ip=ip,
                user=user_clean,
                ident=ident,
                timestamp=timestamp,
                time_confidence=time_confidence,
                method=method,
                path=path,
                query_string=query_string,
                protocol=protocol,
                status_code=status_code,
                bytes_sent=bytes_sent,
                referer=referer,
                user_agent=user_agent,
                attacks=attacks_detected,
                raw_line=line[:_MAX_RAW_CHARS],
                line_number=line_number,
            )
            evidence.append(draft)

        if unrecognized:
            warnings.append(
                f"{unrecognized} of {lines_total} line(s) did not match web server log formats"
            )
        if truncated:
            warnings.append(f"log truncated at max_lines={args.max_lines}")

        metrics: dict[str, Any] = {
            "lines_total": lines_total,
            "lines_matched": lines_matched,
            "lines_unrecognized": unrecognized,
            "unique_client_ips": len(unique_ips),
            "attacks_detected": attacks_count,
            "attacks_by_category": attacks_by_cat,
            "status_distribution": status_distribution,
            "truncated": truncated,
        }

        logger.info(
            "web server log parsing completed",
            extra={
                "lines_matched": lines_matched,
                "lines_unrecognized": unrecognized,
                "attacks_count": attacks_count,
            },
        )

        return ToolResult(
            evidence=evidence,
            metrics=metrics,
            warnings=warnings,
            exit_status=0,
        )


def _parse_timestamp(time_str: str | None) -> tuple[dt.datetime | None, TimeConfidence]:
    """Parse Common/Combined Log Format, ISO-8601, or BSD syslog timestamp."""
    if not time_str:
        return None, TimeConfidence.UNKNOWN
    try:
        # Format: 10/Mar/2026:03:10:55 +0000 or 10/Mar/2026:03:10:55
        parts = time_str.split(" ")
        dt_part = parts[0]
        tz_part = parts[1] if len(parts) > 1 else "+0000"

        # dt_part: 10/Mar/2026:03:10:55
        day_str, mon_str, rest = dt_part.split("/", 2)
        year_str, time_hms = rest.split(":", 1)
        h_str, m_str, s_str = time_hms.split(":")

        day = int(day_str)
        month = _MONTHS.get(mon_str, 1)
        year = int(year_str)
        hour = int(h_str)
        minute = int(m_str)
        second = int(s_str)

        # Parse timezone offset e.g. +0000 or -0700
        tz_sign = 1 if tz_part.startswith("+") else -1
        tz_hours = int(tz_part[1:3])
        tz_minutes = int(tz_part[3:5]) if len(tz_part) >= 5 else 0
        tz_offset = dt.timezone(tz_sign * dt.timedelta(hours=tz_hours, minutes=tz_minutes))

        parsed_dt = dt.datetime(year, month, day, hour, minute, second, tzinfo=tz_offset)
        utc_dt = parsed_dt.astimezone(dt.UTC)
        confidence = TimeConfidence.EXACT if len(parts) > 1 else TimeConfidence.DERIVED
        return utc_dt, confidence
    except Exception:
        # Fallback to ISO format if present
        try:
            parsed_iso = dt.datetime.fromisoformat(time_str)
            if parsed_iso.tzinfo is None:
                return parsed_iso.replace(tzinfo=dt.UTC), TimeConfidence.DERIVED
            return parsed_iso.astimezone(dt.UTC), TimeConfidence.EXACT
        except Exception:
            # Fallback to BSD syslog e.g. "Oct 14 22:14:02"
            try:
                b_parts = time_str.split()
                if len(b_parts) == 3 and b_parts[0] in _MONTHS:
                    mon = _MONTHS[b_parts[0]]
                    day = int(b_parts[1])
                    h, m, s = map(int, b_parts[2].split(":"))
                    now = dt.datetime.now(dt.UTC)
                    parsed_bsd = dt.datetime(now.year, mon, day, h, m, s, tzinfo=dt.UTC)
                    return parsed_bsd, TimeConfidence.DERIVED
            except (ValueError, KeyError, IndexError):
                pass
            return None, TimeConfidence.UNKNOWN


def _parse_request(req_str: str) -> tuple[str, str, str | None, str]:
    """Parse HTTP request line: e.g. 'GET /path?query=val HTTP/1.1'."""
    parts = req_str.split()
    if not parts:
        return "UNKNOWN", "", None, ""
    method = parts[0].upper()
    protocol = parts[2] if len(parts) > 2 else "HTTP/1.1"
    target = parts[1] if len(parts) > 1 else ""

    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, None

    return method, path, query, protocol


def _detect_attacks(
    *,
    path: str,
    query_string: str | None,
    req_str: str,
    user_agent: str,
    extra: str | None = None,
) -> list[dict[str, str]]:
    """Evaluate deterministic attack signatures across request components."""
    detected: list[dict[str, str]] = []

    # Check query string (both raw and URL-decoded)
    raw_query = query_string or ""
    decoded_query = urllib.parse.unquote_plus(raw_query)

    # Check path (both raw and decoded)
    decoded_path = urllib.parse.unquote_plus(path)

    search_targets = [
        ("path", path),
        ("decoded_path", decoded_path),
        ("query", raw_query),
        ("decoded_query", decoded_query),
        ("request_line", req_str),
    ]
    if extra:
        search_targets.append(("payload", extra))
        search_targets.append(("decoded_payload", urllib.parse.unquote_plus(extra)))

    for cat, pattern in _ATTACK_SIGNATURES:
        if cat == "scanner":
            if pattern.search(user_agent) or pattern.search(req_str):
                detected.append({"category": cat, "field": "user_agent", "match": user_agent[:64]})
            continue

        for field_name, text in search_targets:
            if not text:
                continue
            m = pattern.search(text)
            if m:
                detected.append({"category": cat, "field": field_name, "match": m.group(0)[:64]})
                break

    return detected


def _build_evidence_draft(
    *,
    ip: str,
    user: str | None,
    ident: str | None,
    timestamp: dt.datetime | None,
    time_confidence: TimeConfidence,
    method: str,
    path: str,
    query_string: str | None,
    protocol: str,
    status_code: int,
    bytes_sent: int | None,
    referer: str | None,
    user_agent: str | None,
    attacks: list[dict[str, str]],
    raw_line: str,
    line_number: int,
) -> EvidenceDraft:
    """Build a typed EvidenceDraft with normalized entity references."""
    entities: list[EntityRef] = [
        EntityRef(type=EntityType.IP, value=ip, role="source"),
    ]
    if path:
        entities.append(EntityRef(type=EntityType.URL, value=path, role="target"))
    if user:
        entities.append(EntityRef(type=EntityType.USER, value=user, role="authenticated"))

    is_attack = len(attacks) > 0
    kind = EvidenceKind.WEB_ATTACK if is_attack else EvidenceKind.WEB_REQUEST

    data: dict[str, Any] = {
        "event_type": "web_attack" if is_attack else "web_request",
        "client_ip": ip,
        "source_ip": ip,  # Aligns with timeline renderer in reporting.py
        "user": user,
        "method": method,
        "path": path,
        "query_string": query_string,
        "protocol": protocol,
        "status_code": status_code,
        "bytes_sent": bytes_sent,
        "referer": referer,
        "user_agent": user_agent,
        "attacks": attacks,
        "raw_line": raw_line,
        "line_number": line_number,
    }

    return EvidenceDraft(
        kind=kind,
        data=data,
        observed_at=timestamp,
        time_confidence=time_confidence,
        entities=entities,
        confidence=1.0,
    )
