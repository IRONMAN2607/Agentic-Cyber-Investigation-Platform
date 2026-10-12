"""Log analysis agent.

Parses authentication logs and web server access logs using deterministic tool
adapters, then evaluates detection rules in :mod:`acip.core.detection.auth_rules`
and :mod:`acip.core.detection.web_rules` over the resulting events.

The division of labour is deliberate: tool adapters state what happened (FACT),
the detection rules state what the pattern indicates (INFERENCE). Events that
could not be placed on a timeline or were truncated are reported as gaps rather
than silently dropped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.core.detection.auth_rules import (
    AuthEventView,
    evaluate_auth_rules,
)
from acip.core.detection.auth_rules import (
    DetectionHit as AuthDetectionHit,
)
from acip.core.detection.web_rules import (
    DetectionHit as WebDetectionHit,
)
from acip.core.detection.web_rules import (
    WebEventView,
    evaluate_web_rules,
)
from acip.core.evidence.contracts import FindingDraft
from acip.db.models import Evidence
from acip.logging import get_logger
from acip.tools.auth_log_parser import LinuxAuthLogParser
from acip.tools.web_log_parser import WebServerLogParser
from acip.types import (
    AgentCapability,
    ArtifactKind,
    AssertionClass,
    EvidenceKind,
    RunStatus,
    Severity,
)

logger = get_logger(__name__)

_AUTH_EVENT_KINDS = frozenset(
    {
        EvidenceKind.AUTH_EVENT.value,
        EvidenceKind.PRIVILEGE_EVENT.value,
        EvidenceKind.SESSION_EVENT.value,
    }
)
_WEB_EVENT_KINDS = frozenset(
    {
        EvidenceKind.WEB_REQUEST.value,
        EvidenceKind.WEB_ATTACK.value,
    }
)
_MAX_CITED = 25


class LogAnalysisAgent(Agent):
    """Parses authentication and web access logs and applies deterministic detection rules."""

    name: ClassVar[str] = "log_analysis"
    version: ClassVar[str] = "1.1.0"
    capability: ClassVar[AgentCapability] = AgentCapability.LOG_ANALYSIS
    description: ClassVar[str] = (
        "Parses Linux authentication and web server access logs and evaluates "
        "deterministic detection rules."
    )

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        auth_candidates = list(ctx.artifacts_of_kind(ArtifactKind.LINUX_AUTH_LOG.value))
        web_candidates = list(ctx.artifacts_of_kind(ArtifactKind.WEB_SERVER_LOG.value))
        other_candidates = [
            a for a in ctx.artifacts if a not in auth_candidates and a not in web_candidates
        ]

        if not auth_candidates and not web_candidates and not other_candidates:
            return await self._no_input(ctx)

        created_auth: list[Evidence] = []
        created_web: list[Evidence] = []
        auth_metrics: list[dict[str, Any]] = []
        web_metrics: list[dict[str, Any]] = []
        warnings: list[str] = []

        # 1. Parse declared auth logs (with fallback to web parser if 0 lines matched)
        for artifact in auth_candidates:
            art_path = Path(artifact.storage_path)
            inv = await ctx.tools.run(
                LinuxAuthLogParser.name,
                {"year_hint": inputs.get("year_hint")},
                agent_run_id=ctx.agent_run_id,
                artifact_id=artifact.id,
                artifact_path=art_path,
            )
            if inv.result.metrics.get("lines_matched", 0) > 0:
                created_auth.extend(inv.evidence)
                warnings.extend(inv.result.warnings)
                auth_metrics.append({"artifact": artifact.display_id, **inv.result.metrics})
            else:
                inv_web = await ctx.tools.run(
                    WebServerLogParser.name,
                    {},
                    agent_run_id=ctx.agent_run_id,
                    artifact_id=artifact.id,
                    artifact_path=art_path,
                )
                if inv_web.result.metrics.get("lines_matched", 0) > 0:
                    created_web.extend(inv_web.evidence)
                    warnings.extend(inv_web.result.warnings)
                    web_metrics.append({"artifact": artifact.display_id, **inv_web.result.metrics})
                else:
                    warnings.extend(inv.result.warnings)
                    auth_metrics.append({"artifact": artifact.display_id, **inv.result.metrics})

        # 2. Parse declared web server logs (with fallback to auth parser if 0 lines matched)
        for artifact in web_candidates:
            art_path = Path(artifact.storage_path)
            inv = await ctx.tools.run(
                WebServerLogParser.name,
                {},
                agent_run_id=ctx.agent_run_id,
                artifact_id=artifact.id,
                artifact_path=art_path,
            )
            if inv.result.metrics.get("lines_matched", 0) > 0:
                created_web.extend(inv.evidence)
                warnings.extend(inv.result.warnings)
                web_metrics.append({"artifact": artifact.display_id, **inv.result.metrics})
            else:
                inv_auth = await ctx.tools.run(
                    LinuxAuthLogParser.name,
                    {"year_hint": inputs.get("year_hint")},
                    agent_run_id=ctx.agent_run_id,
                    artifact_id=artifact.id,
                    artifact_path=art_path,
                )
                if inv_auth.result.metrics.get("lines_matched", 0) > 0:
                    created_auth.extend(inv_auth.evidence)
                    warnings.extend(inv_auth.result.warnings)
                    auth_metrics.append(
                        {"artifact": artifact.display_id, **inv_auth.result.metrics}
                    )
                else:
                    warnings.extend(inv.result.warnings)
                    web_metrics.append({"artifact": artifact.display_id, **inv.result.metrics})

        # 3. For generic / unknown artifacts, attempt auth first, then web if no auth matches
        for artifact in other_candidates:
            art_path = Path(artifact.storage_path)
            inv_auth = await ctx.tools.run(
                LinuxAuthLogParser.name,
                {"year_hint": inputs.get("year_hint")},
                agent_run_id=ctx.agent_run_id,
                artifact_id=artifact.id,
                artifact_path=art_path,
            )
            if inv_auth.result.metrics.get("lines_matched", 0) > 0:
                created_auth.extend(inv_auth.evidence)
                warnings.extend(inv_auth.result.warnings)
                auth_metrics.append({"artifact": artifact.display_id, **inv_auth.result.metrics})
            else:
                inv_web = await ctx.tools.run(
                    WebServerLogParser.name,
                    {},
                    agent_run_id=ctx.agent_run_id,
                    artifact_id=artifact.id,
                    artifact_path=art_path,
                )
                if inv_web.result.metrics.get("lines_matched", 0) > 0:
                    created_web.extend(inv_web.evidence)
                    warnings.extend(inv_web.result.warnings)
                    web_metrics.append({"artifact": artifact.display_id, **inv_web.result.metrics})
                else:
                    warnings.extend(inv_auth.result.warnings)
                    auth_metrics.append(
                        {"artifact": artifact.display_id, **inv_auth.result.metrics}
                    )

        matched_auth = sum(int(m.get("lines_matched", 0)) for m in auth_metrics)
        matched_web = sum(int(m.get("lines_matched", 0)) for m in web_metrics)
        matched_total = matched_auth + matched_web

        if matched_total == 0:
            return await self._nothing_recognised(ctx, auth_metrics + web_metrics, warnings)

        finding_ids: list[str] = []
        rules_fired: list[str] = []
        events_undated = 0
        events_truncated = False

        # 4. Evaluate authentication rules if auth evidence exists
        if matched_auth > 0:
            auth_events, a_undated, a_trunc = await self._load_auth_events(ctx)
            events_undated += a_undated
            events_truncated = events_truncated or a_trunc
            auth_hits = evaluate_auth_rules(
                auth_events,
                min_failures=ctx.settings.bruteforce_min_failures,
                window_seconds=ctx.settings.bruteforce_window_seconds,
            )
            finding_ids.append(await self._record_parse_fact(ctx, created_auth, auth_metrics))
            for hit in auth_hits:
                rules_fired.append(hit.rule_id)
                finding_ids.append(await self._record_hit(ctx, hit))

        # 5. Evaluate web detection rules if web evidence exists
        if matched_web > 0:
            web_events, w_undated, w_trunc = await self._load_web_events(ctx)
            events_undated += w_undated
            events_truncated = events_truncated or w_trunc
            web_hits = evaluate_web_rules(web_events)
            finding_ids.append(await self._record_web_parse_fact(ctx, created_web, web_metrics))
            for w_hit in web_hits:
                rules_fired.append(w_hit.rule_id)
                finding_ids.append(await self._record_web_hit(ctx, w_hit))

        if events_undated:
            finding_ids.append(await self._record_undated_gap(ctx, events_undated))
        if events_truncated:
            finding_ids.append(await self._record_truncation_gap(ctx, matched_total))

        summary_parts: list[str] = []
        if matched_auth:
            summary_parts.append(f"{matched_auth} auth event(s)")
        if matched_web:
            summary_parts.append(f"{matched_web} web access event(s)")

        summary = (
            f"Parsed {' and '.join(summary_parts)} from {len(ctx.artifacts)} artifact(s); "
            f"{len(rules_fired)} detection rule(s) fired."
        )

        all_created = created_auth + created_web
        next_actions: list[str] = []
        if any(r.startswith("R-AUTH") for r in rules_fired):
            next_actions.append("Correlate source addresses with network telemetry")
        if any(r.startswith("R-WEB") for r in rules_fired):
            next_actions.append(
                "Block attacking source IPs and inspect web server compromise status"
            )

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=summary,
            evidence_ids=[str(row.id) for row in all_created],
            finding_ids=finding_ids,
            metrics={
                "artifacts_parsed": len(ctx.artifacts),
                "events_parsed": matched_total,
                "auth_events_parsed": matched_auth,
                "web_events_parsed": matched_web,
                "events_undated": events_undated,
                "events_truncated": events_truncated,
                "rules_fired": rules_fired,
                "auth_metrics": auth_metrics,
                "web_metrics": web_metrics,
                "warnings": warnings,
            },
            next_actions=next_actions,
            errors=[],
        )

    # --- Evidence loading ---------------------------------------------------

    async def _load_auth_events(self, ctx: AgentContext) -> tuple[list[AuthEventView], int, bool]:
        """Project stored auth evidence into the rule engine's view type."""
        rows, truncated = await ctx.store.all_evidence(
            cap=ctx.settings.max_evidence_per_investigation, kinds=_AUTH_EVENT_KINDS
        )
        events: list[AuthEventView] = []
        undated = 0
        for row in rows:
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
        return events, undated, truncated

    async def _load_web_events(self, ctx: AgentContext) -> tuple[list[WebEventView], int, bool]:
        """Project stored web evidence into the web rule engine's view type."""
        rows, truncated = await ctx.store.all_evidence(
            cap=ctx.settings.max_evidence_per_investigation, kinds=_WEB_EVENT_KINDS
        )
        events: list[WebEventView] = []
        undated = 0
        for row in rows:
            if row.observed_at is None:
                undated += 1
            data = row.data or {}
            raw_attacks = data.get("attacks") or []
            attacks_tuple = tuple(raw_attacks) if isinstance(raw_attacks, list) else ()
            events.append(
                WebEventView(
                    evidence_id=row.id,
                    observed_at=row.observed_at,
                    client_ip=str(data.get("client_ip") or "unknown"),
                    method=str(data.get("method") or "GET"),
                    path=str(data.get("path") or "/"),
                    query_string=data.get("query_string"),
                    status_code=int(data.get("status_code", 200)),
                    user_agent=data.get("user_agent"),
                    user=data.get("user"),
                    attacks=attacks_tuple,
                )
            )
        return events, undated, truncated

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

    async def _record_web_parse_fact(
        self, ctx: AgentContext, created: list[Evidence], web_metrics: list[dict[str, Any]]
    ) -> str:
        total_matched = sum(int(m.get("lines_matched", 0)) for m in web_metrics)
        total_attacks = sum(int(m.get("attacks_detected", 0)) for m in web_metrics)

        finding = await ctx.store.add_finding(
            FindingDraft(
                title=f"{total_matched} web access event(s) parsed from logs",
                description=(
                    f"Deterministic parsing extracted {total_matched} HTTP request record(s) and "
                    f"identified {total_attacks} attack pattern match(es). Each event is retained "
                    "on the immutable evidence record."
                ),
                assertion_class=AssertionClass.FACT,
                severity=Severity.INFO,
                confidence=1.0,
                evidence_ids=[row.id for row in created[:_MAX_CITED]],
                detection_rule="log_analysis.web_parse_summary",
            ),
            agent_run_id=ctx.agent_run_id,
        )
        return str(finding.id)

    async def _record_hit(self, ctx: AgentContext, hit: AuthDetectionHit) -> str:
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

    async def _record_web_hit(self, ctx: AgentContext, hit: WebDetectionHit) -> str:
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

    async def _record_truncation_gap(self, ctx: AgentContext, examined: int) -> str:
        finding = await ctx.store.add_finding(
            FindingDraft(
                title="Detection ran over a truncated evidence set",
                description=(
                    f"The evidence quota bounded this read at {examined} event(s). Events "
                    "beyond the cap were not evaluated, so the absence of a detection in "
                    "this investigation is not evidence that nothing occurred."
                ),
                assertion_class=AssertionClass.UNKNOWN,
                severity=Severity.INFO,
                confidence=1.0,
                reasoning=(
                    "Reads are bounded so query cost stays predictable. Raising "
                    "ACIP_MAX_EVIDENCE_PER_INVESTIGATION, or narrowing the submitted "
                    "log to the window of interest, would close this gap."
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
                    "authentication or web access events could be examined."
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
                title="Submitted artifact(s) contained no recognisable log records",
                description=(
                    "The parsers ran over every submitted artifact and matched no known "
                    "authentication or web server access log format. No log conclusions "
                    "can be drawn from this submission."
                ),
                assertion_class=AssertionClass.UNKNOWN,
                severity=Severity.INFO,
                confidence=1.0,
                reasoning=(
                    "This bounds what the current parsers support (Linux auth logs and "
                    "Nginx/Apache/W3C web access logs). Other formats (e.g. Windows EVTX, PCAP) "
                    "require their respective tools."
                ),
            ),
            agent_run_id=ctx.agent_run_id,
        )
        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary="No recognisable log records found.",
            finding_ids=[str(finding.id)],
            metrics={"per_artifact": parse_metrics, "events_parsed": 0, "warnings": warnings},
            errors=[],
        )
