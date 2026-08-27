"""Report agent.

Renders a deterministic Markdown investigation report from stored data, and
computes the investigation-level risk roll-up.

There is no language model in this path. The narrative is a template over facts
already in the database, and the report says so explicitly — a reader must never
be left to infer that a model wrote a conclusion, or that enrichment happened
when it did not.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, ClassVar

import sqlalchemy as sa

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.core import risk as risk_module
from acip.core.limitations import NOT_IMPLEMENTED
from acip.db.models import AgentRun, Evidence, Finding, Report, ToolRun
from acip.logging import get_logger
from acip.types import AgentCapability, AssertionClass, EvidenceKind, RunStatus, Severity

logger = get_logger(__name__)

_MAX_TIMELINE_ROWS = 100
_MAX_IOC_ROWS = 50

_ASSERTION_LABEL = {
    AssertionClass.FACT: "FACT",
    AssertionClass.INFERENCE: "INFERENCE",
    AssertionClass.HYPOTHESIS: "HYPOTHESIS",
    AssertionClass.UNKNOWN: "UNKNOWN",
}


class ReportAgent(Agent):
    """Produces the investigation report and the risk roll-up."""

    name: ClassVar[str] = "reporting"
    version: ClassVar[str] = "1.0.0"
    capability: ClassVar[AgentCapability] = AgentCapability.REPORTING
    description: ClassVar[str] = "Renders a deterministic Markdown investigation report."

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        findings = await ctx.store.list_findings()
        evidence = await ctx.store.list_evidence(limit=100_000)
        agent_runs = await self._agent_runs(ctx)
        tool_runs = await self._tool_runs(ctx)

        assessment = risk_module.assess(findings)
        investigation = ctx.investigation
        investigation.severity = assessment.severity.value
        investigation.confidence = assessment.confidence
        investigation.risk_score = assessment.risk_score

        content = self._render(
            ctx=ctx,
            findings=findings,
            evidence=evidence,
            agent_runs=agent_runs,
            tool_runs=tool_runs,
            assessment=assessment,
        )

        report = Report(
            investigation_id=investigation.id,
            fmt="markdown",
            content=content,
            agent_run_id=ctx.agent_run_id,
        )
        ctx.session.add(report)
        await ctx.session.flush()

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=(
                f"Report generated: {len(findings)} finding(s), severity "
                f"{assessment.severity.value}, risk {assessment.risk_score}/100."
            ),
            metrics={
                "report_id": str(report.id),
                "characters": len(content),
                "findings": len(findings),
                "evidence": len(evidence),
                "severity": assessment.severity.value,
                "risk_score": assessment.risk_score,
                "confidence": assessment.confidence,
            },
        )

    async def _agent_runs(self, ctx: AgentContext) -> list[AgentRun]:
        return list(
            (
                await ctx.session.scalars(
                    sa.select(AgentRun)
                    .where(AgentRun.investigation_id == ctx.investigation.id)
                    .order_by(AgentRun.started_at)
                )
            ).all()
        )

    async def _tool_runs(self, ctx: AgentContext) -> list[ToolRun]:
        return list(
            (
                await ctx.session.scalars(
                    sa.select(ToolRun)
                    .where(ToolRun.investigation_id == ctx.investigation.id)
                    .order_by(ToolRun.started_at)
                )
            ).all()
        )

    # --- Rendering ----------------------------------------------------------

    def _render(
        self,
        *,
        ctx: AgentContext,
        findings: list[Finding],
        evidence: list[Evidence],
        agent_runs: list[AgentRun],
        tool_runs: list[ToolRun],
        assessment: risk_module.RiskAssessment,
    ) -> str:
        inv = ctx.investigation
        now = dt.datetime.now(dt.UTC)
        lines: list[str] = []
        add = lines.append

        add(f"# Investigation Report — {inv.display_id}")
        add("")
        add(f"**Title:** {_cell(inv.title)}")
        add(f"**Target:** `{_cell(inv.target_value)}` ({inv.target_type})")
        add(f"**Generated:** {now.isoformat()}")
        add(
            f"**Severity:** {assessment.severity.value.upper()} · "
            f"**Risk:** {assessment.risk_score}/100 · "
            f"**Confidence:** {assessment.confidence:.2f}"
        )
        add("")
        add(
            "> Every conclusion below is labelled with its epistemic status: "
            "**FACT** (observed directly by a deterministic tool), **INFERENCE** "
            "(derived from facts by a stated rule), **HYPOTHESIS** (candidate "
            "explanation, not yet tested) or **UNKNOWN** (a recorded gap). "
            "Narrative text is template-generated; no language model contributed "
            "to this report."
        )
        add("")

        self._section_summary(add, inv, findings, assessment)
        self._section_scope(add, ctx, evidence)
        self._section_findings(add, findings)
        self._section_timeline(add, evidence)
        self._section_indicators(add, evidence)
        self._section_evidence(add, evidence)
        self._section_risk(add, assessment)
        self._section_trace(add, agent_runs, tool_runs)
        self._section_limitations(add, findings)

        return "\n".join(lines).rstrip() + "\n"

    def _section_summary(
        self,
        add: Any,
        inv: Any,
        findings: list[Finding],
        assessment: risk_module.RiskAssessment,
    ) -> None:
        by_class: dict[str, int] = {}
        for finding in findings:
            by_class[finding.assertion_class] = by_class.get(finding.assertion_class, 0) + 1
        actionable = [
            finding
            for finding in findings
            if finding.severity_enum.rank >= Severity.MEDIUM.rank
            and finding.assertion_class_enum is not AssertionClass.UNKNOWN
        ]

        add("## 1. Executive Summary")
        add("")
        if actionable:
            add(
                f"The investigation produced {len(findings)} finding(s), of which "
                f"{len(actionable)} are at MEDIUM severity or above. The highest-severity "
                f"assessment is **{assessment.severity.value.upper()}**."
            )
            add("")
            for finding in sorted(actionable, key=lambda f: -f.severity_enum.rank)[:5]:
                add(
                    f"- **{finding.severity.upper()}** "
                    f"[{_ASSERTION_LABEL[finding.assertion_class_enum]}] "
                    f"{_cell(finding.title)}"
                )
        else:
            add(
                f"The investigation produced {len(findings)} finding(s), none at MEDIUM "
                "severity or above. No malicious activity was established from the "
                "available evidence. This is not a statement that none occurred — see "
                "section 9."
            )
        add("")
        if by_class:
            add(
                "Finding breakdown by epistemic status: "
                + ", ".join(f"{count} {name.upper()}" for name, count in sorted(by_class.items()))
                + "."
            )
            add("")

    def _section_scope(self, add: Any, ctx: AgentContext, evidence: list[Evidence]) -> None:
        add("## 2. Scope and Inputs")
        add("")
        add(f"- Investigation: `{ctx.investigation.display_id}`")
        add(f"- Created: {ctx.investigation.created_at.isoformat()}")
        add(f"- Evidence items collected: {len(evidence)}")
        add(f"- Artifacts submitted: {len(ctx.artifacts)}")
        add("")
        if ctx.artifacts:
            add("| Artifact | Declared kind | Size (bytes) | SHA-256 |")
            add("| --- | --- | --- | --- |")
            for artifact in ctx.artifacts:
                add(
                    f"| `{artifact.display_id}` | {artifact.kind} | {artifact.size_bytes} "
                    f"| `{artifact.sha256}` |"
                )
            add("")
            add(
                "Artifacts are stored content-addressed by SHA-256; the digest above is the "
                "integrity anchor for everything derived from them."
            )
            add("")

    def _section_findings(self, add: Any, findings: list[Finding]) -> None:
        add("## 3. Findings")
        add("")
        if not findings:
            add("No findings were recorded.")
            add("")
            return

        for finding in sorted(findings, key=lambda f: -f.severity_enum.rank):
            label = _ASSERTION_LABEL[finding.assertion_class_enum]
            add(f"### [{finding.severity.upper()}] {_cell(finding.title)}")
            add("")
            add(
                f"- **Status:** {label} · **Confidence:** {finding.confidence:.2f}"
                + (f" · **Rule:** `{finding.detection_rule}`" if finding.detection_rule else "")
            )
            add(f"- **Finding id:** `{finding.display_id}`")
            add("")
            add(_cell(finding.description))
            add("")
            if finding.reasoning:
                add(f"**Reasoning.** {_cell(finding.reasoning)}")
                add("")
            if finding.evidence_ids:
                citations = ", ".join(
                    f"`EVD-{eid[:8].upper()}`" for eid in finding.evidence_ids[:12]
                )
                extra = (
                    f" (+{len(finding.evidence_ids) - 12} more)"
                    if len(finding.evidence_ids) > 12
                    else ""
                )
                add(f"**Supporting evidence.** {citations}{extra}")
            else:
                add("**Supporting evidence.** None cited — this finding records a gap.")
            add("")

    def _section_timeline(self, add: Any, evidence: list[Evidence]) -> None:
        add("## 4. Timeline")
        add("")
        dated = [row for row in evidence if row.observed_at is not None]
        if not dated:
            add("No evidence carried a usable timestamp, so no timeline could be constructed.")
            add("")
            return

        dated.sort(key=lambda row: row.observed_at)  # type: ignore[arg-type,return-value]
        add(f"{len(dated)} dated event(s). Times are UTC.")
        add("")
        add("| Time (UTC) | Precision | Event | Actor | Source | Evidence |")
        add("| --- | --- | --- | --- | --- | --- |")
        for row in dated[:_MAX_TIMELINE_ROWS]:
            data = row.data or {}
            add(
                f"| {row.observed_at.isoformat() if row.observed_at else '-'} "
                f"| {row.time_confidence} "
                f"| {_cell(str(data.get('event_type', row.kind)))} "
                f"| {_cell(str(data.get('user') or '-'))} "
                f"| {_cell(str(data.get('source_ip') or '-'))} "
                f"| `{row.display_id}` |"
            )
        if len(dated) > _MAX_TIMELINE_ROWS:
            add(f"| … | | {len(dated) - _MAX_TIMELINE_ROWS} further event(s) omitted | | | |")
        add("")
        add(
            "`derived` precision means the calendar year was inferred because the log "
            "format omits it; `approximate` means no timezone offset was present and UTC "
            "was assumed."
        )
        add("")

    def _section_indicators(self, add: Any, evidence: list[Evidence]) -> None:
        add("## 5. Indicators of Compromise")
        add("")
        iocs = [row for row in evidence if row.kind == EvidenceKind.IOC.value]
        if not iocs:
            add("No indicators were extracted.")
            add("")
            return

        add("| Type | Value | Scope | Occurrences | Evidence |")
        add("| --- | --- | --- | --- | --- |")
        for row in iocs[:_MAX_IOC_ROWS]:
            data = row.data or {}
            add(
                f"| {_cell(str(data.get('ioc_type', '-')))} "
                f"| `{_cell(str(data.get('value', '-')))}` "
                f"| {_cell(str(data.get('scope', '-')))} "
                f"| {data.get('occurrences', 1)} "
                f"| `{row.display_id}` |"
            )
        if len(iocs) > _MAX_IOC_ROWS:
            add(f"| … | {len(iocs) - _MAX_IOC_ROWS} further indicator(s) omitted | | | |")
        add("")
        add(
            "No reputation or attribution data was retrieved for these values; they are "
            "observations of presence only."
        )
        add("")

    def _section_evidence(self, add: Any, evidence: list[Evidence]) -> None:
        add("## 6. Evidence Inventory")
        add("")
        by_kind: dict[str, int] = {}
        by_tool: dict[str, int] = {}
        for row in evidence:
            by_kind[row.kind] = by_kind.get(row.kind, 0) + 1
            by_tool[row.source_tool] = by_tool.get(row.source_tool, 0) + 1

        add(f"Total evidence items: {len(evidence)}")
        add("")
        add("| Kind | Count |")
        add("| --- | --- |")
        for kind, count in sorted(by_kind.items()):
            add(f"| {kind} | {count} |")
        add("")
        add("| Producing tool | Count |")
        add("| --- | --- |")
        for tool, count in sorted(by_tool.items()):
            add(f"| `{tool}` | {count} |")
        add("")

    def _section_risk(self, add: Any, assessment: risk_module.RiskAssessment) -> None:
        add("## 7. Risk Assessment")
        add("")
        add(f"- **Severity:** {assessment.severity.value.upper()}")
        add(f"- **Risk score:** {assessment.risk_score}/100")
        add(f"- **Confidence:** {assessment.confidence:.2f}")
        add("")
        add(f"**How this was computed.** {assessment.rationale}")
        add("")

    def _section_trace(
        self, add: Any, agent_runs: list[AgentRun], tool_runs: list[ToolRun]
    ) -> None:
        add("## 8. Execution Trace")
        add("")
        add("Every agent and tool invocation performed for this investigation.")
        add("")
        add("| Agent | Version | Status | Duration (ms) | Why it ran |")
        add("| --- | --- | --- | --- | --- |")
        for a_run in agent_runs:
            add(
                f"| `{a_run.agent_name}` | {a_run.agent_version} | {a_run.status} "
                f"| {a_run.duration_ms if a_run.duration_ms is not None else '-'} "
                f"| {_cell(a_run.rationale or '-')} |"
            )
        add("")
        add("| Tool | Version | Tier | Status | Duration (ms) | Evidence |")
        add("| --- | --- | --- | --- | --- | --- |")
        for t_run in tool_runs:
            add(
                f"| `{t_run.tool_name}` | {t_run.tool_version} | {t_run.sandbox_tier} "
                f"| {t_run.status} | {t_run.duration_ms if t_run.duration_ms is not None else '-'} "
                f"| {t_run.evidence_count} |"
            )
        add("")
        failed = [f_run for f_run in tool_runs if f_run.status == RunStatus.FAILED.value]
        if failed:
            add("**Failed tool invocations.**")
            add("")
            for f_run in failed:
                add(f"- `{f_run.tool_name}`: {_cell(f_run.error or 'unknown error')}")
            add("")

    def _section_limitations(self, add: Any, findings: list[Finding]) -> None:
        add("## 9. Limitations and Unknowns")
        add("")
        add("**Recorded evidence gaps.**")
        add("")
        gaps = [
            finding
            for finding in findings
            if finding.assertion_class_enum is AssertionClass.UNKNOWN
        ]
        if gaps:
            for finding in gaps:
                add(f"- {_cell(finding.title)}")
        else:
            add("- None recorded.")
        add("")
        add("**Capabilities absent from this deployment.**")
        add("")
        for limitation in NOT_IMPLEMENTED:
            add(f"- {limitation}")
        add("")
        add(
            "Conclusions are bounded by the above. Absence of a finding in an area listed "
            "here is not evidence that nothing occurred there."
        )
        add("")


def _cell(value: str) -> str:
    """Make text safe for a Markdown table cell and single-line contexts."""
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()
