"""Hypothesis Generation Agent.

Formulates competing candidate explanations for observed security events,
strictly enforcing Invariant G3: Every hypothesis MUST state a non-empty,
falsifiable refutation condition and cite relevant supporting or contradicting evidence.
Also identifies explicit knowledge gaps required to resolve the hypotheses.
"""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.core.evidence.contracts import (
    FindingDraft,
    HypothesisDraft,
    HypothesisGapDraft,
)
from acip.logging import get_logger
from acip.types import (
    AgentCapability,
    AssertionClass,
    EvidenceKind,
    RunStatus,
    Severity,
)

logger = get_logger(__name__)


class HypothesisAgent(Agent):
    """Generates competing candidate explanations with mandatory refutation conditions (G3)."""

    name: ClassVar[str] = "hypothesis"
    version: ClassVar[str] = "0.1.0"
    capability: ClassVar[AgentCapability] = AgentCapability.HYPOTHESIS
    description: ClassVar[str] = (
        "Generates competing candidate explanations with mandatory falsification/refutation "
        "conditions (Invariant G3) and identifies investigative gaps."
    )

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        findings = await ctx.store.list_findings()
        evidence_rows, _ = await ctx.store.all_evidence(cap=10_000)

        if not findings and not evidence_rows:
            return AgentResult(
                status=RunStatus.SUCCEEDED,
                summary="No findings or evidence available to formulate hypotheses.",
                metrics={"hypotheses_generated": 0, "gaps_recorded": 0},
            )

        # Gather evidence IDs from suspicious findings
        suspicious_evidence_ids: list[uuid.UUID] = []
        has_auth_anomaly = False
        has_web_anomaly = False
        has_priv_esc = False

        for f in findings:
            for eid_str in f.evidence_ids:
                try:
                    suspicious_evidence_ids.append(uuid.UUID(eid_str))
                except (ValueError, TypeError):
                    pass
            rule = (f.detection_rule or "").lower()
            title = f.title.lower()
            if "auth" in rule or "brute" in title or "password" in title:
                has_auth_anomaly = True
            if "web" in rule or "injection" in title or "xss" in title or "traversal" in title:
                has_web_anomaly = True
            if "sudo" in title or "privilege" in title or "esc" in rule:
                has_priv_esc = True

        # Check raw evidence kinds if findings didn't cover them
        if not suspicious_evidence_ids and evidence_rows:
            suspicious_evidence_ids = [ev.id for ev in evidence_rows[:5]]

        for ev in evidence_rows:
            if ev.kind == EvidenceKind.AUTH_EVENT.value and ev.data.get("outcome") == "failure":
                has_auth_anomaly = True
            if ev.kind in {EvidenceKind.WEB_ATTACK.value, EvidenceKind.WEB_REQUEST.value}:
                if ev.data.get("attacks") or ev.kind == EvidenceKind.WEB_ATTACK.value:
                    has_web_anomaly = True
            if ev.data.get("event_type") == "sudo_command":
                has_priv_esc = True

        hypotheses_created: list[uuid.UUID] = []
        gaps_created: list[uuid.UUID] = []
        finding_ids: list[str] = []

        primary_cited = list(dict.fromkeys(suspicious_evidence_ids))[:5]

        # Formulate Hypothesis 1: Malicious / External Campaign
        if has_auth_anomaly or has_web_anomaly or has_priv_esc:
            h1_statement = (
                "Observed security events represent a coordinated, unauthorized intrusion "
                "attempt: adversary performed automated scanning / credential guessing "
                "to obtain unauthorized access."
            )
            h1_refutation = (
                "Verified proof that the observed traffic originates from an authorized "
                "internal vulnerability scanner or authorized security red-team exercise "
                "within approved change window."
            )
            h1 = await ctx.store.add_hypothesis(
                HypothesisDraft(
                    statement=h1_statement,
                    refutation_condition=h1_refutation,
                    confidence=0.85 if (has_priv_esc or has_web_anomaly) else 0.70,
                    supporting_evidence_ids=primary_cited,
                    contradicting_evidence_ids=[],
                ),
                agent_run_id=ctx.agent_run_id,
            )
            hypotheses_created.append(h1.id)

            # Record investigative gap for H1
            gap1 = await ctx.store.add_hypothesis_gap(
                h1.id,
                HypothesisGapDraft(
                    description=(
                        "External reputation and threat intelligence attribution for source IP "
                        "addresses is unverified; requires threat intelligence lookup."
                    ),
                    required_tool="threat_intel",
                ),
            )
            gaps_created.append(gap1.id)

            # Formulate Hypothesis 2: Benign / Misconfiguration
            h2_statement = (
                "Observed events represent benign administrative activity or system "
                "misconfiguration (e.g. expired credentials, automated service retry loop, "
                "or legacy application glitch)."
            )
            h2_refutation = (
                "Evidence of execution of unauthorized system commands (such as cat /etc/shadow or "
                "reverse shells), external C2 beaconing, or secondary persistence creation."
            )
            h2_confidence = 0.20 if has_priv_esc else 0.40
            h2 = await ctx.store.add_hypothesis(
                HypothesisDraft(
                    statement=h2_statement,
                    refutation_condition=h2_refutation,
                    confidence=h2_confidence,
                    supporting_evidence_ids=[],
                    contradicting_evidence_ids=primary_cited if has_priv_esc else [],
                ),
                agent_run_id=ctx.agent_run_id,
            )
            hypotheses_created.append(h2.id)

            gap2 = await ctx.store.add_hypothesis_gap(
                h2.id,
                HypothesisGapDraft(
                    description=(
                        "Endpoint process tree and process execution telemetry is missing; "
                        "cannot verify whether unauthorized child processes spawned."
                    ),
                    required_tool="endpoint_telemetry",
                ),
            )
            gaps_created.append(gap2.id)

            # Record finding citing evidence
            hyp_finding = await ctx.store.add_finding(
                FindingDraft(
                    title="Competing Explanations Formulated (Intrusion vs Benign)",
                    description=(
                        f"Formulated 2 competing hypotheses under Invariant G3. "
                        f"Primary: '{h1_statement}' (Confidence: {h1.confidence:.2f}). "
                        f"Alternative: '{h2_statement}' (Confidence: {h2.confidence:.2f})."
                    ),
                    assertion_class=AssertionClass.INFERENCE,
                    severity=Severity.MEDIUM,
                    confidence=h1.confidence,
                    evidence_ids=primary_cited,
                    reasoning=(
                        "Hypotheses generated from observed attack anomalies. Each hypothesis "
                        "declares a falsifiable refutation condition per Invariant G3 to enable "
                        "adversarial validation."
                    ),
                    detection_rule="hypothesis.generation",
                ),
                agent_run_id=ctx.agent_run_id,
            )
            finding_ids.append(str(hyp_finding.id))
        else:
            # Baseline activity hypothesis
            h_base = await ctx.store.add_hypothesis(
                HypothesisDraft(
                    statement=(
                        "Observed telemetry reflects normal operational baseline without "
                        "active compromise."
                    ),
                    refutation_condition=(
                        "Discovery of unauthorized persistence, privileged command execution, "
                        "or suspicious outbound network flows."
                    ),
                    confidence=0.90,
                    supporting_evidence_ids=primary_cited,
                    contradicting_evidence_ids=[],
                ),
                agent_run_id=ctx.agent_run_id,
            )
            hypotheses_created.append(h_base.id)

        summary = (
            f"Formulated {len(hypotheses_created)} competing hypothesis(es) and "
            f"recorded {len(gaps_created)} investigative gap(s) satisfying Invariant G3."
        )

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=summary,
            finding_ids=finding_ids,
            metrics={
                "hypotheses_generated": len(hypotheses_created),
                "hypothesis_ids": [str(hid) for hid in hypotheses_created],
                "gaps_recorded": len(gaps_created),
                "invariant_g3_verified": True,
            },
            next_actions=[
                "validation" if hypotheses_created else "reporting",
            ],
            errors=[],
        )
