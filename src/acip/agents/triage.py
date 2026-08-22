"""Triage agent.

Extracts and inventories indicators from the investigation target and every
submitted artifact, then records what is *not* known about them.

Indicator extraction is delegated to a deterministic tool rather than a model:
this is the part of triage where ground truth exists, so it should be
measurable. The agent's own contribution is aggregation and gap identification.
"""

from __future__ import annotations

from typing import Any, ClassVar

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.core.evidence.contracts import FindingDraft
from acip.db.models import Evidence
from acip.logging import get_logger
from acip.tools.ioc_extractor import IOCExtractor
from acip.types import AgentCapability, AssertionClass, RunStatus, Severity, TargetType

logger = get_logger(__name__)

# Target types whose value is itself an indicator worth scanning.
_SCANNABLE_TARGETS = frozenset(
    {TargetType.URL, TargetType.IP, TargetType.DOMAIN, TargetType.HASH, TargetType.DESCRIPTION}
)
_MAX_CITED = 10


class TriageAgent(Agent):
    """Classifies the submission and inventories its indicators."""

    name: ClassVar[str] = "triage"
    version: ClassVar[str] = "1.0.0"
    capability: ClassVar[AgentCapability] = AgentCapability.TRIAGE
    description: ClassVar[str] = (
        "Extracts indicators from the target and artifacts, and records what is unknown."
    )

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        collected: list[Evidence] = []
        warnings: list[str] = []
        metrics: dict[str, Any] = {"sources_scanned": 0}

        if ctx.investigation.target_type_enum in _SCANNABLE_TARGETS:
            invocation = await ctx.tools.run(
                IOCExtractor.name,
                {"text": ctx.investigation.target_value},
                agent_run_id=ctx.agent_run_id,
            )
            collected.extend(invocation.evidence)
            warnings.extend(invocation.result.warnings)
            metrics["sources_scanned"] += 1

        for artifact in ctx.artifacts:
            invocation = await ctx.tools.run(
                IOCExtractor.name,
                {},
                agent_run_id=ctx.agent_run_id,
                artifact_id=artifact.id,
                artifact_path=_path(artifact),
            )
            collected.extend(invocation.evidence)
            warnings.extend(invocation.result.warnings)
            metrics["sources_scanned"] += 1

        by_type: dict[str, int] = {}
        global_indicators: list[Evidence] = []
        for row in collected:
            ioc_type = str(row.data.get("ioc_type", "unknown"))
            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
            if row.data.get("scope", "global") == "global":
                global_indicators.append(row)

        metrics["indicators_total"] = len(collected)
        metrics["indicators_by_type"] = by_type
        metrics["externally_routable"] = len(global_indicators)

        findings = await self._record_findings(ctx, collected, global_indicators, by_type)

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=(
                f"Extracted {len(collected)} distinct indicator(s) across "
                f"{metrics['sources_scanned']} source(s)."
            ),
            evidence_ids=[str(row.id) for row in collected],
            finding_ids=findings,
            metrics=metrics,
            next_actions=(
                ["Enrich externally-routable indicators with threat intelligence"]
                if global_indicators
                else []
            ),
            errors=[],
        )

    async def _record_findings(
        self,
        ctx: AgentContext,
        collected: list[Evidence],
        global_indicators: list[Evidence],
        by_type: dict[str, int],
    ) -> list[str]:
        findings: list[str] = []

        if collected:
            breakdown = ", ".join(f"{count} {name}" for name, count in sorted(by_type.items()))
            finding = await ctx.store.add_finding(
                FindingDraft(
                    title=f"{len(collected)} indicator(s) extracted from submitted evidence",
                    description=(
                        f"Deterministic extraction over {len(collected)} distinct indicator(s) "
                        f"({breakdown}). Values were validated after matching: addresses were "
                        "parsed, hashes length-checked, and domain candidates filtered against "
                        "a file-extension denylist."
                    ),
                    assertion_class=AssertionClass.FACT,
                    severity=Severity.INFO,
                    confidence=1.0,
                    evidence_ids=[row.id for row in collected[:_MAX_CITED]],
                    detection_rule="triage.ioc_inventory",
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding.id))
        else:
            finding = await ctx.store.add_finding(
                FindingDraft(
                    title="No indicators could be extracted from the submitted evidence",
                    description=(
                        "Extraction ran successfully but matched no addresses, domains, URLs, "
                        "hashes or email addresses. The submission may contain no indicators, "
                        "or may be in a format this deployment cannot yet parse."
                    ),
                    assertion_class=AssertionClass.UNKNOWN,
                    severity=Severity.INFO,
                    confidence=1.0,
                    reasoning=(
                        "Absence of a match is not evidence of absence of indicators; it "
                        "bounds only what the current extractor covers."
                    ),
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding.id))

        # The reputation gap is recorded explicitly rather than left implicit, so
        # the report cannot read as though enrichment had been performed.
        if global_indicators:
            finding = await ctx.store.add_finding(
                FindingDraft(
                    title=(
                        f"Reputation of {len(global_indicators)} externally-routable "
                        "indicator(s) is unknown"
                    ),
                    description=(
                        "No threat-intelligence source is configured in this deployment, so "
                        "no reputation, prevalence or attribution data was retrieved for the "
                        "externally-routable indicators. Their presence alone carries no "
                        "verdict."
                    ),
                    assertion_class=AssertionClass.UNKNOWN,
                    severity=Severity.INFO,
                    confidence=1.0,
                    evidence_ids=[row.id for row in global_indicators[:_MAX_CITED]],
                    reasoning=(
                        "Resolving this gap requires a threat-intelligence lookup, which is "
                        "introduced in Phase 4. Until then the indicators remain unclassified."
                    ),
                ),
                agent_run_id=ctx.agent_run_id,
            )
            findings.append(str(finding.id))

        return findings


def _path(artifact: Any) -> Any:
    from pathlib import Path

    return Path(artifact.storage_path)
