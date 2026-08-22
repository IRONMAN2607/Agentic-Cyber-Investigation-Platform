"""Linux authentication log parser.

A deterministic, dependency-free parser for ``/var/log/auth.log`` style records
covering both BSD syslog and ISO-8601 (journald/RFC 5424) timestamp prefixes.
This is a real evidence producer: every emitted event corresponds to a line that
was actually matched, and unmatched lines are counted rather than guessed at.

Timestamp honesty
-----------------
BSD syslog omits the year. When no ``year_hint`` is supplied the parser infers
one and marks the evidence ``TimeConfidence.DERIVED`` so downstream reasoning
cannot treat an inferred date as observed fact.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from acip.core.evidence.contracts import EntityRef, EvidenceDraft
from acip.errors import ToolError
from acip.tools.base import ToolAdapter, ToolContext, ToolResult
from acip.types import EntityType, EvidenceKind, SandboxTier, TimeConfidence

_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}

_SYSLOG_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w.\-]+)\s+(?P<proc>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

_SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[\w.\-]+)\s+(?P<proc>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

# Ordered: the first match wins, so more specific patterns come first.
_MESSAGE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "auth_failure",
        re.compile(
            r"^Failed (?P<method>\w+) for (?P<invalid>invalid user )?(?P<user>\S+) "
            r"from (?P<ip>[\da-fA-F:.]+)(?: port (?P<port>\d+))?"
        ),
    ),
    (
        "auth_success",
        re.compile(
            r"^Accepted (?P<method>\w+) for (?P<user>\S+) "
            r"from (?P<ip>[\da-fA-F:.]+)(?: port (?P<port>\d+))?"
        ),
    ),
    (
        "invalid_user",
        re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[\da-fA-F:.]+)(?: port (?P<port>\d+))?"),
    ),
    (
        "max_auth_attempts",
        re.compile(
            r"^error: maximum authentication attempts exceeded for "
            r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)"
            r"(?: port (?P<port>\d+))?"
        ),
    ),
    (
        "connection_closed",
        re.compile(
            r"^Connection (?:closed|reset) by (?:authenticating user (?P<user>\S+) )?"
            r"(?P<ip>[\da-fA-F:.]+)(?: port (?P<port>\d+))?"
        ),
    ),
    (
        "sudo_command",
        re.compile(
            r"^\s*(?P<user>\S+)\s*:\s*(?:TTY=(?P<tty>\S*)\s*;\s*)?(?:PWD=(?P<pwd>\S*)\s*;\s*)?"
            r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
        ),
    ),
    ("session_opened", re.compile(r"session opened for user (?P<user>[\w.\-]+)")),
    ("session_closed", re.compile(r"session closed for user (?P<user>[\w.\-]+)")),
)

_FAILURE_EVENTS = frozenset({"auth_failure", "invalid_user", "max_auth_attempts"})
_MAX_RAW_CHARS = 512

_EVENT_KINDS: dict[str, EvidenceKind] = {
    "auth_failure": EvidenceKind.AUTH_EVENT,
    "auth_success": EvidenceKind.AUTH_EVENT,
    "invalid_user": EvidenceKind.AUTH_EVENT,
    "max_auth_attempts": EvidenceKind.AUTH_EVENT,
    "connection_closed": EvidenceKind.AUTH_EVENT,
    "sudo_command": EvidenceKind.PRIVILEGE_EVENT,
    "session_opened": EvidenceKind.SESSION_EVENT,
    "session_closed": EvidenceKind.SESSION_EVENT,
}


class AuthLogParserArgs(BaseModel):
    """Parsing options. Note the absence of any path argument."""

    year_hint: int | None = Field(
        default=None,
        ge=1970,
        le=2200,
        description="Calendar year for BSD syslog lines, which omit it.",
    )
    max_lines: int = Field(default=200_000, ge=1, le=5_000_000)


class LinuxAuthLogParser(ToolAdapter):
    """Parses Linux authentication logs into normalised auth events."""

    name: ClassVar[str] = "linux_auth_log_parser"
    version: ClassVar[str] = "1.0.0"
    tier: ClassVar[SandboxTier] = SandboxTier.T0_IN_PROCESS
    args_model: ClassVar[type[BaseModel]] = AuthLogParserArgs
    description: ClassVar[str] = (
        "Parses sshd/sudo/PAM authentication records from Linux auth logs."
    )
    requires_artifact: ClassVar[bool] = True

    async def execute(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, AuthLogParserArgs)
        if ctx.artifact_path is None:
            raise ToolError(f"{self.name} requires an artifact")

        from acip.core.security.files import read_text

        text, lossy = read_text(ctx.artifact_path)
        return self.parse_text(text, args, lossy=lossy)

    def parse_text(
        self, text: str, args: AuthLogParserArgs, *, lossy: bool = False, now: dt.datetime | None = None
    ) -> ToolResult:
        """Parse log text. Separated from :meth:`execute` so it is directly testable."""
        reference_now = now or dt.datetime.now(dt.UTC)
        warnings: list[str] = []
        if lossy:
            warnings.append("artifact was not valid UTF-8; decoded as latin-1")

        evidence: list[EvidenceDraft] = []
        counts: dict[str, int] = {}
        lines_total = 0
        unrecognized = 0
        undated = 0
        truncated = False

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            if line_number > args.max_lines:
                truncated = True
                break
            line = raw_line.strip()
            if not line:
                continue
            lines_total += 1

            prefix = self._match_prefix(line)
            if prefix is None:
                unrecognized += 1
                continue
            host, process, pid, message, timestamp, time_confidence = self._resolve_prefix(
                prefix, args.year_hint, reference_now
            )
            if timestamp is None:
                undated += 1

            parsed = self._match_message(message)
            if parsed is None:
                unrecognized += 1
                continue
            event_type, fields = parsed

            counts[event_type] = counts.get(event_type, 0) + 1
            evidence.append(
                self._build_evidence(
                    event_type=event_type,
                    fields=fields,
                    host=host,
                    process=process,
                    pid=pid,
                    timestamp=timestamp,
                    time_confidence=time_confidence,
                    raw_line=line,
                    line_number=line_number,
                )
            )

        if truncated:
            warnings.append(f"input truncated at max_lines={args.max_lines}")
        if unrecognized:
            warnings.append(f"{unrecognized} line(s) did not match any known pattern")
        if undated:
            warnings.append(f"{undated} line(s) had an unparseable timestamp")

        return ToolResult(
            evidence=evidence,
            metrics={
                "lines_total": lines_total,
                "lines_matched": len(evidence),
                "lines_unrecognized": unrecognized,
                "lines_undated": undated,
                "events_by_type": counts,
                "year_hint_supplied": args.year_hint is not None,
            },
            warnings=warnings,
            exit_status=0,
        )

    # --- Internals ----------------------------------------------------------

    @staticmethod
    def _match_prefix(line: str) -> re.Match[str] | None:
        return _SYSLOG_ISO.match(line) or _SYSLOG_BSD.match(line)

    def _resolve_prefix(
        self, match: re.Match[str], year_hint: int | None, now: dt.datetime
    ) -> tuple[str, str, int | None, str, dt.datetime | None, TimeConfidence]:
        groups = match.groupdict()
        host = groups.get("host") or "unknown"
        process = groups.get("proc") or "unknown"
        pid = int(groups["pid"]) if groups.get("pid") else None
        message = groups.get("msg") or ""

        if "ts" in groups and groups["ts"]:
            timestamp, confidence = self._parse_iso(groups["ts"])
        else:
            timestamp, confidence = self._parse_bsd(
                groups["mon"], groups["day"], groups["time"], year_hint, now
            )
        return host, process, pid, message, timestamp, confidence

    @staticmethod
    def _parse_iso(value: str) -> tuple[dt.datetime | None, TimeConfidence]:
        candidate = value.replace(" ", "T")
        if candidate.endswith("Z"):
            candidate = f"{candidate[:-1]}+00:00"
        try:
            parsed = dt.datetime.fromisoformat(candidate)
        except ValueError:
            return None, TimeConfidence.UNKNOWN
        if parsed.tzinfo is None:
            # No offset in the log: the instant is only known up to the host's
            # timezone, so it is assumed UTC and marked as approximate.
            return parsed.replace(tzinfo=dt.UTC), TimeConfidence.APPROXIMATE
        return parsed.astimezone(dt.UTC), TimeConfidence.EXACT

    @staticmethod
    def _parse_bsd(
        month_name: str, day: str, time_part: str, year_hint: int | None, now: dt.datetime
    ) -> tuple[dt.datetime | None, TimeConfidence]:
        month = _MONTHS.get(month_name)
        if month is None:
            return None, TimeConfidence.UNKNOWN
        hour, minute, second = (int(p) for p in time_part.split(":"))

        def build(year: int) -> dt.datetime | None:
            try:
                return dt.datetime(
                    year, month, int(day), hour, minute, second, tzinfo=dt.UTC
                )
            except ValueError:
                return None  # e.g. 29 Feb in a non-leap year

        if year_hint is not None:
            built = build(year_hint)
            return built, TimeConfidence.EXACT if built else TimeConfidence.UNKNOWN

        # No year in the record. Assume the most recent occurrence at or before
        # now, allowing a day of clock skew before rolling back a year.
        candidate = build(now.year)
        if candidate is None or candidate > now + dt.timedelta(days=1):
            candidate = build(now.year - 1)
        return candidate, TimeConfidence.DERIVED if candidate else TimeConfidence.UNKNOWN

    @staticmethod
    def _match_message(message: str) -> tuple[str, dict[str, Any]] | None:
        for event_type, pattern in _MESSAGE_PATTERNS:
            match = pattern.search(message)
            if match:
                return event_type, match.groupdict()
        return None

    @staticmethod
    def _build_evidence(
        *,
        event_type: str,
        fields: dict[str, Any],
        host: str,
        process: str,
        pid: int | None,
        timestamp: dt.datetime | None,
        time_confidence: TimeConfidence,
        raw_line: str,
        line_number: int,
    ) -> EvidenceDraft:
        user = (fields.get("user") or "").strip() or None
        source_ip = (fields.get("ip") or "").strip() or None
        port = fields.get("port")

        data: dict[str, Any] = {
            "event_type": event_type,
            "outcome": (
                "failure"
                if event_type in _FAILURE_EVENTS
                else "success"
                if event_type in {"auth_success", "sudo_command", "session_opened"}
                else "neutral"
            ),
            "host": host,
            "service": process,
            "pid": pid,
            "user": user,
            "source_ip": source_ip,
            "source_port": int(port) if port else None,
            "auth_method": fields.get("method"),
            "invalid_user": bool(fields.get("invalid")) or event_type == "invalid_user",
            "line_number": line_number,
            "raw": raw_line[:_MAX_RAW_CHARS],
        }
        if event_type == "sudo_command":
            data["target_user"] = fields.get("target_user")
            data["command"] = (fields.get("command") or "")[:_MAX_RAW_CHARS]
            data["tty"] = fields.get("tty")
            data["cwd"] = fields.get("pwd")

        entities = [EntityRef(type=EntityType.HOST, value=host, role="target")]
        if user:
            entities.append(EntityRef(type=EntityType.USER, value=user, role="actor"))
        if source_ip:
            entities.append(EntityRef(type=EntityType.IP, value=source_ip, role="source"))
        if event_type == "sudo_command" and fields.get("target_user"):
            entities.append(
                EntityRef(type=EntityType.USER, value=fields["target_user"], role="target")
            )

        return EvidenceDraft(
            kind=_EVENT_KINDS.get(event_type, EvidenceKind.AUTH_EVENT),
            data={k: v for k, v in data.items() if v is not None},
            observed_at=timestamp,
            time_confidence=time_confidence,
            entities=entities,
            confidence=1.0,
        )
