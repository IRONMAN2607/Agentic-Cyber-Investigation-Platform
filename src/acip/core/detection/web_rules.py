"""Deterministic detection rules for web access logs.

Pure functions over normalised web request events: no database, no LLM, no I/O.
Every rule cites the specific events that caused it to fire, ensuring findings
are strictly grounded in observed evidence.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from acip.types import Severity


@dataclass(frozen=True)
class WebEventView:
    """A parsed web access event, decoupled from the ORM."""

    evidence_id: uuid.UUID
    observed_at: dt.datetime | None
    client_ip: str
    method: str
    path: str
    query_string: str | None
    status_code: int
    user_agent: str | None
    user: str | None = None
    attacks: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class DetectionHit:
    """A web rule firing, citing the evidence that triggered it."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    reasoning: str
    evidence_ids: list[uuid.UUID] = field(default_factory=list)


RULE_SQL_INJECTION = "R-WEB-001"
RULE_PATH_TRAVERSAL = "R-WEB-002"
RULE_COMMAND_INJECTION = "R-WEB-003"
RULE_WEBSHELL_ACCESS = "R-WEB-004"
RULE_SENSITIVE_FILE_RECON = "R-WEB-005"
RULE_MALICIOUS_SCANNER = "R-WEB-006"
RULE_ERROR_BURST = "R-WEB-007"
RULE_SUCCESSFUL_EXPLOIT = "R-WEB-008"

_MAX_CITED_EVENTS = 25


def evaluate_web_rules(
    events: list[WebEventView],
    *,
    min_scan_errors: int = 10,
    scan_window_seconds: int = 300,
) -> list[DetectionHit]:
    """Evaluate deterministic web security detection rules over normalised events.

    Returns hits ordered by descending severity so the most critical security
    events appear first.
    """
    hits: list[DetectionHit] = []

    # 1. Category-specific attack grouping by IP
    attacks_by_cat_and_ip: dict[str, dict[str, list[WebEventView]]] = defaultdict(
        lambda: defaultdict(list)
    )
    successful_exploits: dict[str, list[WebEventView]] = defaultdict(list)

    for event in events:
        for attack in event.attacks:
            cat = attack.get("category", "")
            attacks_by_cat_and_ip[cat][event.client_ip].append(event)
            # HTTP 200/2xx on an attack payload indicates potential success
            if 200 <= event.status_code < 300 and cat in {
                "sqli",
                "traversal",
                "command_injection",
                "webshell",
            }:
                successful_exploits[event.client_ip].append(event)

    # R-WEB-001: SQL Injection
    for ip, evts in attacks_by_cat_and_ip.get("sqli", {}).items():
        hits.append(
            DetectionHit(
                rule_id=RULE_SQL_INJECTION,
                title=f"SQL injection attack attempts from {ip}",
                description=(
                    f"Observed {len(evts)} request(s) from {ip} containing SQL injection "
                    "syntax patterns (e.g. UNION SELECT, boolean tautologies, or comment markers)."
                ),
                severity=Severity.HIGH,
                confidence=0.95,
                reasoning=(
                    "SQL injection syntax was matched in request paths or query parameters. "
                    "This is an inference from deterministic signature matches on web server logs."
                ),
                evidence_ids=_unique_evidence_ids(evts),
            )
        )

    # R-WEB-002: Path Traversal
    for ip, evts in attacks_by_cat_and_ip.get("traversal", {}).items():
        hits.append(
            DetectionHit(
                rule_id=RULE_PATH_TRAVERSAL,
                title=f"Directory traversal / LFI attempts from {ip}",
                description=(
                    f"Observed {len(evts)} request(s) from {ip} attempting directory traversal "
                    "or local file inclusion (e.g. '../..' sequences or system file access)."
                ),
                severity=Severity.HIGH,
                confidence=0.95,
                reasoning=(
                    "Path traversal sequences or attempts to access restricted system files "
                    "were detected in request targets."
                ),
                evidence_ids=_unique_evidence_ids(evts),
            )
        )

    # R-WEB-003: Command Injection
    for ip, evts in attacks_by_cat_and_ip.get("command_injection", {}).items():
        hits.append(
            DetectionHit(
                rule_id=RULE_COMMAND_INJECTION,
                title=f"Remote command injection attempts from {ip}",
                description=(
                    f"Observed {len(evts)} request(s) from {ip} containing OS command execution "
                    "patterns or shell metacharacters."
                ),
                severity=Severity.CRITICAL,
                confidence=0.95,
                reasoning=(
                    "Shell command separators and execution binaries were matched in request "
                    "parameters, indicating an attempt to execute arbitrary commands."
                ),
                evidence_ids=_unique_evidence_ids(evts),
            )
        )

    # R-WEB-004: Web Shell Access
    for ip, evts in attacks_by_cat_and_ip.get("webshell", {}).items():
        hits.append(
            DetectionHit(
                rule_id=RULE_WEBSHELL_ACCESS,
                title=f"Web shell / backdoor access attempts from {ip}",
                description=(
                    f"Observed {len(evts)} request(s) from {ip} targeting known web shell "
                    "or backdoor filenames."
                ),
                severity=Severity.HIGH,
                confidence=0.90,
                reasoning=(
                    "Target paths correspond to signatures of common web shells and backdoors. "
                    "The presence of these requests indicates an attacker probing for pre-existing "
                    "implants or uploading web shells."
                ),
                evidence_ids=_unique_evidence_ids(evts),
            )
        )

    # R-WEB-005: Sensitive File Reconnaissance
    for ip, evts in attacks_by_cat_and_ip.get("sensitive_file", {}).items():
        hits.append(
            DetectionHit(
                rule_id=RULE_SENSITIVE_FILE_RECON,
                title=f"Sensitive file reconnaissance from {ip}",
                description=(
                    f"Observed {len(evts)} request(s) from {ip} targeting sensitive configuration "
                    "files, version control repositories, or backup artifacts."
                ),
                severity=Severity.MEDIUM,
                confidence=0.90,
                reasoning=(
                    "Requests probed for sensitive configuration files (e.g. .env, .git, "
                    "or backups). This represents reconnaissance aimed at credential or "
                    "source code exposure."
                ),
                evidence_ids=_unique_evidence_ids(evts),
            )
        )

    # R-WEB-006: Malicious Security Scanner Identified
    for ip, evts in attacks_by_cat_and_ip.get("scanner", {}).items():
        user_agents = sorted({e.user_agent for e in evts if e.user_agent})
        ua_str = f" ({', '.join(user_agents[:2])})" if user_agents else ""
        hits.append(
            DetectionHit(
                rule_id=RULE_MALICIOUS_SCANNER,
                title=f"Automated security scanner detected from {ip}",
                description=(
                    f"Observed {len(evts)} request(s) from {ip} with User-Agent indicating an "
                    f"automated vulnerability scanner or fuzzing tool{ua_str}."
                ),
                severity=Severity.MEDIUM,
                confidence=0.95,
                reasoning=(
                    "The client User-Agent header matched known automated attack and "
                    "reconnaissance tools (e.g. sqlmap, nikto, dirbuster, gobuster)."
                ),
                evidence_ids=_unique_evidence_ids(evts),
            )
        )

    # R-WEB-007: High HTTP Error Burst (Endpoint scanning / brute force)
    error_bursts = _find_error_bursts(
        events, min_errors=min_scan_errors, window_seconds=scan_window_seconds
    )
    for ip, burst in error_bursts.items():
        hits.append(
            DetectionHit(
                rule_id=RULE_ERROR_BURST,
                title=f"HTTP scanning error burst from {ip}",
                description=(
                    f"Observed {len(burst)} failed HTTP request(s) (4xx/5xx) from {ip} "
                    f"within {scan_window_seconds}s, exceeding threshold of {min_scan_errors}."
                ),
                severity=Severity.LOW,
                confidence=0.85,
                reasoning=(
                    "A rapid burst of client-side HTTP errors from a single source address "
                    "indicates automated URI enumeration, directory brute-forcing, or fuzzing."
                ),
                evidence_ids=_unique_evidence_ids(burst),
            )
        )

    # R-WEB-008: Successful Exploitation Indicator (2xx response on exploit request)
    for ip, evts in successful_exploits.items():
        hits.append(
            DetectionHit(
                rule_id=RULE_SUCCESSFUL_EXPLOIT,
                title=f"Potential successful web exploit execution from {ip}",
                description=(
                    f"Observed {len(evts)} exploit attempt(s) from {ip} returning HTTP 200 (OK), "
                    "indicating that the malicious payload may have been successfully processed."
                ),
                severity=Severity.CRITICAL,
                confidence=0.90,
                reasoning=(
                    "The web server returned HTTP success (2xx) for requests containing explicit "
                    "exploit patterns. In contrast to 4xx rejections, this indicates the server or "
                    "underlying application executed the request."
                ),
                evidence_ids=_unique_evidence_ids(evts),
            )
        )

    # Sort hits: highest severity first, then confidence
    hits.sort(key=lambda hit: (-hit.severity.rank, -hit.confidence, hit.rule_id))
    return hits


def _unique_evidence_ids(events: list[WebEventView]) -> list[uuid.UUID]:
    """Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS."""
    seen: set[uuid.UUID] = set()
    result: list[uuid.UUID] = []
    for evt in events:
        if evt.evidence_id not in seen:
            seen.add(evt.evidence_id)
            result.append(evt.evidence_id)
            if len(result) >= _MAX_CITED_EVENTS:
                break
    return result


def _find_error_bursts(
    events: list[WebEventView],
    *,
    min_errors: int,
    window_seconds: int,
) -> dict[str, list[WebEventView]]:
    """Group 4xx/5xx error responses into bursts per IP."""
    by_ip: dict[str, list[WebEventView]] = defaultdict(list)
    for evt in events:
        if evt.status_code >= 400:
            by_ip[evt.client_ip].append(evt)

    bursts: dict[str, list[WebEventView]] = {}
    window = dt.timedelta(seconds=window_seconds)

    for ip, errs in by_ip.items():
        dated = [e for e in errs if e.observed_at is not None]
        if len(dated) < min_errors:
            if len(errs) >= min_errors:
                bursts[ip] = errs[:min_errors]
            continue

        dated.sort(key=lambda e: e.observed_at)  # type: ignore[arg-type,return-value]
        for i in range(len(dated)):
            start_time = dated[i].observed_at
            assert start_time is not None
            current_window = [
                e for e in dated[i:] if e.observed_at and e.observed_at - start_time <= window
            ]
            if len(current_window) >= min_errors:
                bursts[ip] = current_window
                break

    return bursts
