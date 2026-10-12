"""MITRE ATT&CK Mapping Agent.

Maps deterministic detection findings from triage, authentication, and web log
analysis agents to verified MITRE ATT&CK Enterprise tactics and techniques.
Strictly enforces Invariant G7: no uncataloged or hallucinated techniques can be cited.
"""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.core.detection.mitre import (
    ATTACK_CATALOG_VERSION,
    AttackTechnique,
    map_rule_to_technique,
)
from acip.core.evidence.contracts import FindingDraft
from acip.types import AgentCapability, AssertionClass, RunStatus, Severity


class MitreMappingAgent(Agent):
    """Deterministic MITRE ATT&CK mapping agent."""

    name: ClassVar[str] = "mitre"
    version: ClassVar[str] = "0.1.0"
    capability: ClassVar[AgentCapability] = AgentCapability.MITRE_MAPPING

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        # Load all findings created in this investigation so far
        findings = await ctx.store.list_findings()

        mapped_findings: list[str] = []
        techniques_mapped: set[str] = set()
        seen_rules: set[str] = set()

        for finding in findings:
            rule_id = finding.detection_rule
            if not rule_id or rule_id in seen_rules:
                continue

            tech: AttackTechnique | None = map_rule_to_technique(rule_id)
            if tech is None:
                continue

            seen_rules.add(rule_id)
            techniques_mapped.add(tech.id)

            # Invariant G7 holds mechanically because map_rule_to_technique
            # looks up only within the static ATTACK_CATALOG.
            # Cite the underlying evidence IDs from the rule finding
            evidence_uuids = [uuid.UUID(eid) for eid in finding.evidence_ids]

            mapped_finding = await ctx.store.add_finding(
                FindingDraft(
                    title=f"MITRE ATT&CK {tech.id}: {tech.name} ({tech.tactic})",
                    description=(
                        f"Detection rule '{rule_id}' corresponds to MITRE ATT&CK technique "
                        f"{tech.id} ({tech.name}) under tactic '{tech.tactic}'. "
                        f"{tech.description}"
                    ),
                    assertion_class=AssertionClass.INFERENCE,
                    severity=Severity(finding.severity),
                    confidence=finding.confidence,
                    evidence_ids=evidence_uuids,
                    reasoning=(
                        f"Mapped deterministically from detection rule {rule_id} to technique "
                        f"{tech.id} using ATT&CK catalog version {ATTACK_CATALOG_VERSION}."
                    ),
                    detection_rule="mitre.mapping",
                ),
                agent_run_id=ctx.agent_run_id,
            )
            mapped_findings.append(str(mapped_finding.id))

        summary = (
            f"Mapped {len(mapped_findings)} ATT&CK technique(s) across "
            f"{len(seen_rules)} triggered detection rule(s)."
            if mapped_findings
            else "No detection rules qualified for MITRE ATT&CK mapping."
        )

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=summary,
            finding_ids=mapped_findings,
            metrics={
                "catalog_version": ATTACK_CATALOG_VERSION,
                "rules_evaluated": len(findings),
                "rules_mapped": len(seen_rules),
                "techniques": sorted(techniques_mapped),
            },
            next_actions=[],
            errors=[],
        )
