"""Log analysis agent.

Parses authentication logs with a deterministic tool, then evaluates the
detection rules in :mod:`acip.core.detection.auth_rules` over the resulting
events.

The division of labour is deliberate: the tool states what happened (FACT), the
rules state what the pattern suggests (INFERENCE). Events that could not be
placed on a timeline are reported as a gap rather than silently dropped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.core.detection.auth_rules import AuthEventView, DetectionHit, evaluate_auth_rules
from acip.core.evidence.contracts import FindingDraft
from acip.db.models import Evidence
from acip.logging import get_logger
from acip.tools.auth_log_parser import LinuxAuthLogParser
from acip.types import (
    AgentCapability,
    ArtifactKind,
    AssertionClass,
    EvidenceKind,
    RunStatus,
    Severity,
)

logger = get_logger(__name__)

_EVENT_KINDS = frozenset(
    {
        EvidenceKind.AUTH_EVENT.value,
        EvidenceKind.PRIVILEGE_EVENT.value,
        EvidenceKind.SESSION_EVENT.value,
    }
)
_MAX_CITED = 25


class LogAnalysisAgent(Agent):
    """Parses authentication logs and applies deterministic detection rules."""

    name: ClassVar[str] = "log_analysis"
    version: ClassVar[str] = "1.0.0"
    capability: ClassVar[AgentCapability] = AgentCapability.LOG_ANALYSIS
    description: ClassVar[str] = (
        "Parses Linux authentication logs and evaluates deterministic detection rules."
    )

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        candidates = ctx.artifacts_of_kind(ArtifactKind.LINUX_AUTH_LOG.value)
        if not candidates:
            # The declared kind is client-supplied and therefore untrusted; fall
            # back to attempting every artifact and let the parser decide.
            candidates = list(ctx.artifacts)

        if not candidates:
            return await self._no_input(ctx)

        created: list[Evidence] = []
        parse_metrics: list[dict[str, Any]] = []
        warnings: list[str] = []

        for artifact in candidates:
            invocation = await ctx.tools.run(
                LinuxAuthLogParser.name,
                {"year_hint": inputs.get("year_hint")},
                agent_run_id=ctx.agent_run_id,
                artifact_id=artifact.id,
                artifact_path=Path(artifact.storage_path),
            )
            created.extend(invocation.evidence)
            warnings.extend(invocation.result.warnings)
            parse_metrics.append({"artifact": artifact.display_id, **invocation.result.metrics})

        matched_total = sum(int(m.get("lines_matched", 0)) for m in parse_metrics)
        if matched_total == 0:
            return await self._nothing_recognised(ctx, parse_metrics, warnings)

        events, undated = await self._load_events(ctx)
        hits = evaluate_auth_rules(
            events,
            min_failures=ctx.settings.bruteforce_min_failures,
            window_seconds=ctx.settings.bruteforce_window_seconds,
        )

        finding_ids = [await self._record_parse_fact(ctx, created, parse_metrics)]
        for hit in hits:
            finding_ids.append(await self._record_hit(ctx, hit))
        if undated:
            finding_ids.append(await self._record_undated_gap(ctx, undated))

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=(
                f"Parsed {matched_total} authentication event(s) from {len(candidates)} "
                f"artifact(s); {len(hits)} detection rule(s) fired."
            ),
            evidence_ids=[str(row.id) for row in created],
            finding_ids=finding_ids,
            metrics={
                "artifacts_parsed": len(candidates),
                "events_parsed": matched_total,
                "events_undated": undated,
                "rules_fired": [hit.rule_id for hit in hits],
                "per_artifact": parse_metrics,
                "warnings": warnings,
            },
            next_actions=(["Correlate source addresses with network telemetry"] if hits else []),
            errors=[],
        )

    # --- Evidence loading ---------------------------------------------------

    async def _load_events(self, ctx: AgentContext) -> tuple[list[AuthEventView], int]:
        """Project stored evidence into the rule engine's view type."""
        rows = await ctx.store.list_evidence(limit=100_000)
        events: list[AuthEventView] = []
        undated = 0
        for row in rows:
            if row.kind not in _EVENT_KINDS:
                continue
            if row.observed_at is None:
                undated += 1
            data = row.data or {}
            events.append(
                AuthEventView(
                    evidence_id=row.id,
                    event_type=str(data.get("event_type", "unknown")),
                    observed_at=row.observed_at,
                    outcome=str(data.get("outcome", "neutral")),
                    user=data.get("user"),
                    source_ip=data.get("source_ip"),
                    host=data.get("host"),
                    target_user=data.get("target_user"),
                    command=data.get("command"),
                    invalid_user=bool(data.get("invalid_user", False)),
                )
            )
        return events, undated

    # --- Finding recording --------------------------------------------------

    async def _record_parse_fact(
        self, ctx: AgentContext, created: list[Evidence], parse_metrics: list[dict[str, Any]]
    ) -> str:
        totals: dict[str, int] = {}
        for metrics in parse_metrics:
            for event_type, count in (metrics.get("events_by_type") or {}).items():
                totals[event_type] = totals.get(event_type, 0) + int(count)
        breakdown = ", ".join(f"{count} {name}" for name, count in sorted(totals.items()))

        finding = await ctx.store.add_finding(
            FindingDraft(
                title=f"{sum(totals.values())} authentication event(s) parsed from logs",
                description=(
                    f"Deterministic parsing produced: {breakdown}. Each event corresponds to a "
                    "specific log line, retained on the evidence record."
                ),
                assertion_class=AssertionClass.FACT,
                severity=Severity.INFO,
                confidence=1.0,
                evidence_ids=[row.id for row in created[:_MAX_CITED]],
                detection_rule="log_analysis.parse_summary",
            ),
            agent_run_id=ctx.agent_run_id,
        )
        return str(finding.id)

    async def _record_hit(self, ctx: AgentContext, hit: DetectionHit) -> str:
        finding = await ctx.store.add_finding(
            FindingDraft(
                title=hit.title,
                description=hit.description,
                assertion_class=AssertionClass.INFERENCE,
                severity=hit.severity,
                confidence=hit.confidence,
                evidence_ids=hit.evidence_ids,
                reasoning=hit.reasoning,
                detection_rule=hit.rule_id,
            ),
            agent_run_id=ctx.agent_run_id,
        )
        return str(finding.id)

    async def _record_undated_gap(self, ctx: AgentContext, undated: int) -> str:
        finding = await ctx.store.add_finding(
            FindingDraft(
                title=f"{undated} event(s) could not be placed on the timeline",
                description=(
                    f"{undated} parsed event(s) had an unusable timestamp and were excluded "
                    "from time-window correlation. Rules depending on ordering did not see them."
                ),
                assertion_class=AssertionClass.UNKNOWN,
                severity=Severity.INFO,
                confidence=1.0,
                reasoning=(
                    "Timestamps are required for windowed correlation. Supplying the log's "
                    "calendar year, or a source with explicit offsets, would close this gap."
                ),
            ),
            agent_run_id=ctx.agent_run_id,
        )
        return str(finding.id)

    async def _no_input(self, ctx: AgentContext) -> AgentResult:
        finding = await ctx.store.add_finding(
            FindingDraft(
                title="No log artifact was available for analysis",
                description=(
                    "Log analysis was scheduled but no artifact was submitted, so no "
                    "authentication events could be examined."
                ),
                assertion_class=AssertionClass.UNKNOWN,
                severity=Severity.INFO,
                confidence=1.0,
                reasoning="Resolving this requires submitting a log artifact.",
            ),
            agent_run_id=ctx.agent_run_id,
        )
        return AgentResult(
            status=RunStatus.SKIPPED,
            summary="No log artifact available.",
            finding_ids=[str(finding.id)],
            metrics={"artifacts_parsed": 0},
        )

    async def _nothing_recognised(
        self, ctx: AgentContext, parse_metrics: list[dict[str, Any]], warnings: list[str]
    ) -> AgentResult:
        finding = await ctx.store.add_finding(
            FindingDraft(
                title="Submitted artifact(s) contained no recognisable authentication records",
                description=(
                    "The parser ran over every submitted artifact and matched no known "
                    "sshd, sudo or PAM record format. No authentication conclusions can be "
                    "drawn from this submission."
                ),
                assertion_class=AssertionClass.UNKNOWN,
                severity=Severity.INFO,
                confidence=1.0,
                reasoning=(
                    "This bounds only what the current parser supports (Linux auth logs in "
                    "BSD syslog or ISO-8601 form). Windows Event Log and SIEM export support "
                    "is scheduled for a later phase."
                ),
            ),
            agent_run_id=ctx.agent_run_id,
        )
        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary="No recognisable authentication records found.",
            finding_ids=[str(finding.id)],
            metrics={"per_artifact": parse_metrics, "events_parsed": 0, "warnings": warnings},
            errors=[],
        )
