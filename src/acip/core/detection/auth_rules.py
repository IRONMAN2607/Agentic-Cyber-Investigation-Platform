"""Deterministic detection rules.

These are pure functions over normalised events: no database, no LLM, no I/O.
That matters for three reasons — they are unit-testable in isolation, they give
identical output for identical input (so evaluation results are reproducible),
and they form Baseline A in the experimental design (spec s21).

Every rule cites the specific events that caused it to fire, so the resulting
finding is grounded in evidence rather than in a summary of evidence.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from acip.types import Severity


@dataclass(frozen=True)
class AuthEventView:
    """A parsed authentication event, decoupled from the ORM."""

    evidence_id: uuid.UUID
    event_type: str
    observed_at: dt.datetime | None
    outcome: str = "neutral"
    user: str | None = None
    source_ip: str | None = None
    host: str | None = None
    target_user: str | None = None
    command: str | None = None
    invalid_user: bool = False


@dataclass(frozen=True)
class DetectionHit:
    """A rule firing, with the evidence that triggered it."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    reasoning: str
    evidence_ids: list[uuid.UUID] = field(default_factory=list)


FAILURE_TYPES = frozenset({"auth_failure", "invalid_user", "max_auth_attempts"})

RULE_BRUTEFORCE = "R-AUTH-001"
RULE_SUCCESS_AFTER_BRUTEFORCE = "R-AUTH-002"
RULE_USER_ENUMERATION = "R-AUTH-003"
RULE_PRIVILEGE_ESCALATION = "R-AUTH-004"

# How long after a burst of failures a success is still considered related.
_SUCCESS_CORRELATION_SECONDS = 3600
_ENUMERATION_MIN_USERS = 3
_MAX_CITED_EVENTS = 25


def evaluate_auth_rules(
    events: list[AuthEventView],
    *,
    min_failures: int = 5,
    window_seconds: int = 300,
) -> list[DetectionHit]:
    """Evaluate all authentication rules over ``events``.

    Returns hits ordered by descending severity so the most serious result is
    first regardless of rule evaluation order.
    """
    hits: list[DetectionHit] = []

    bursts = _find_failure_bursts(events, min_failures=min_failures, window_seconds=window_seconds)
    compromised: dict[str, DetectionHit] = {}

    for source_ip, burst in bursts.items():
        hits.append(
            DetectionHit(
                rule_id=RULE_BRUTEFORCE,
                title=f"Authentication brute-force attempts from {source_ip}",
                description=(
                    f"{len(burst)} failed authentication attempts originated from {source_ip} "
                    f"within {window_seconds} seconds, exceeding the configured threshold of "
                    f"{min_failures}."
                ),
                severity=Severity.MEDIUM,
                confidence=0.9,
                reasoning=(
                    "A count of failed authentication events from a single source address "
                    "within a bounded time window exceeded the configured threshold. The "
                    "count is derived directly from parsed log events; the characterisation "
                    "as brute force is an inference from that count."
                ),
                evidence_ids=[event.evidence_id for event in burst[:_MAX_CITED_EVENTS]],
            )
        )

    for source_ip, burst in bursts.items():
        success = _first_success_after(events, source_ip, burst)
        if success is None:
            continue
        hit = DetectionHit(
            rule_id=RULE_SUCCESS_AFTER_BRUTEFORCE,
            title=(f"Successful authentication from {source_ip} following failed attempts"),
            description=(
                f"User '{success.user}' authenticated successfully from {source_ip} after "
                f"{len(burst)} failed attempts from the same address. This pattern is "
                "consistent with a successful credential-guessing attack, but a legitimate "
                "user recovering from mistyped credentials produces the same pattern."
            ),
            severity=Severity.HIGH,
            confidence=0.75,
            reasoning=(
                "Failed attempts and a subsequent success share a source address and fall "
                "within the correlation window. Both observations are facts from parsed "
                "logs; the causal link between them is an inference and has at least one "
                "benign explanation that the available evidence cannot exclude."
            ),
            evidence_ids=[event.evidence_id for event in burst[:_MAX_CITED_EVENTS]]
            + [success.evidence_id],
        )
        hits.append(hit)
        if success.user:
            compromised[success.user] = hit

    hits.extend(_evaluate_user_enumeration(events))
    hits.extend(_evaluate_privilege_escalation(events, compromised))

    return sorted(hits, key=lambda hit: (-hit.severity.rank, hit.rule_id))


def _find_failure_bursts(
    events: list[AuthEventView], *, min_failures: int, window_seconds: int
) -> dict[str, list[AuthEventView]]:
    """Group failures by source address and return those forming a dense burst.

    Events without a timestamp cannot be placed in a window and are excluded;
    the caller reports them as an evidence gap rather than assuming an order.
    """
    by_ip: dict[str, list[AuthEventView]] = defaultdict(list)
    for event in events:
        if event.event_type in FAILURE_TYPES and event.source_ip and event.observed_at:
            by_ip[event.source_ip].append(event)

    bursts: dict[str, list[AuthEventView]] = {}
    window = dt.timedelta(seconds=window_seconds)

    for source_ip, failures in by_ip.items():
        ordered = sorted(failures, key=lambda event: event.observed_at)  # type: ignore[arg-type,return-value]
        start = 0
        best: list[AuthEventView] = []
        for end in range(len(ordered)):
            while ordered[end].observed_at - ordered[start].observed_at > window:  # type: ignore[operator]
                start += 1
            span = ordered[start : end + 1]
            if len(span) >= min_failures and len(span) > len(best):
                best = span
        if best:
            bursts[source_ip] = best
    return bursts


def _first_success_after(
    events: list[AuthEventView], source_ip: str, burst: list[AuthEventView]
) -> AuthEventView | None:
    """Earliest successful authentication from ``source_ip`` related to ``burst``."""
    burst_events_with_time = [e for e in burst if e.observed_at is not None]
    if not burst_events_with_time:
        return None
    burst_start = min(
        event.observed_at for event in burst_events_with_time if event.observed_at is not None
    )
    deadline = max(
        event.observed_at for event in burst_events_with_time if event.observed_at is not None
    ) + dt.timedelta(seconds=_SUCCESS_CORRELATION_SECONDS)
    candidates = [
        event
        for event in events
        if event.event_type == "auth_success"
        and event.source_ip == source_ip
        and event.observed_at is not None
        and burst_start <= event.observed_at <= deadline
    ]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda event: event.observed_at or dt.datetime.max.replace(tzinfo=dt.UTC),
    )


def _evaluate_user_enumeration(events: list[AuthEventView]) -> list[DetectionHit]:
    """Many distinct non-existent usernames from one address suggests enumeration."""
    by_ip: dict[str, dict[str, AuthEventView]] = defaultdict(dict)
    for event in events:
        if event.invalid_user and event.source_ip and event.user:
            by_ip[event.source_ip].setdefault(event.user, event)

    hits: list[DetectionHit] = []
    for source_ip, users in by_ip.items():
        if len(users) < _ENUMERATION_MIN_USERS:
            continue
        sample = sorted(users)[:10]
        hits.append(
            DetectionHit(
                rule_id=RULE_USER_ENUMERATION,
                title=f"Username enumeration from {source_ip}",
                description=(
                    f"Authentication was attempted against {len(users)} distinct non-existent "
                    f"usernames from {source_ip}, including: {', '.join(sample)}."
                ),
                severity=Severity.MEDIUM,
                confidence=0.85,
                reasoning=(
                    "The number of distinct usernames rejected as non-existent from a single "
                    "source address exceeds the enumeration threshold. Automated scanning "
                    "produces this pattern; so does a misconfigured client, though rarely "
                    "across this many distinct names."
                ),
                evidence_ids=[
                    event.evidence_id for event in list(users.values())[:_MAX_CITED_EVENTS]
                ],
            )
        )
    return hits


def _evaluate_privilege_escalation(
    events: list[AuthEventView], compromised: dict[str, DetectionHit]
) -> list[DetectionHit]:
    """Root-level sudo by a user whose session followed a suspicious login."""
    hits: list[DetectionHit] = []
    for event in events:
        if event.event_type != "sudo_command" or not event.user:
            continue
        if (event.target_user or "").lower() != "root":
            continue
        related = compromised.get(event.user)
        if related is None:
            continue
        hits.append(
            DetectionHit(
                rule_id=RULE_PRIVILEGE_ESCALATION,
                title=f"Root command execution by '{event.user}' after suspicious login",
                description=(
                    f"User '{event.user}' executed a command as root via sudo "
                    f"({(event.command or 'unknown command')[:120]}) after authenticating "
                    "from an address that had produced repeated failed attempts."
                ),
                severity=Severity.HIGH,
                confidence=0.7,
                reasoning=(
                    "Chains two prior observations: a successful login correlated with failed "
                    "attempts, and a subsequent root-level sudo invocation by the same "
                    "account. Each link is evidence-backed; the interpretation as attacker "
                    "privilege escalation remains an inference, since the account may "
                    "legitimately hold sudo rights."
                ),
                evidence_ids=[event.evidence_id, *related.evidence_ids[-1:]],
            )
        )
    return hits
