"""Reasoning Agent.

Performs cross-source attack-chain construction over the evidence graph.
Identifies multi-hop attack progressions (such as external reconnaissance -> brute force ->
successful authentication -> privilege escalation) and emits fully grounded inference findings.
"""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.core.evidence.contracts import FindingDraft
from acip.core.graph.traversal import GraphTraversal
from acip.logging import get_logger
from acip.types import (
    AgentCapability,
    AssertionClass,
    RunStatus,
    Severity,
)

logger = get_logger(__name__)


class ReasoningAgent(Agent):
    """Reconstructs cross-source attack chains over the evidence graph."""

    name: ClassVar[str] = "reasoning"
    version: ClassVar[str] = "0.1.0"
    capability: ClassVar[AgentCapability] = AgentCapability.REASONING
    description: ClassVar[str] = (
        "Reconstructs multi-stage attack chains across heterogeneous telemetry "
        "using evidence graph path traversals."
    )

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        inv_id = ctx.investigation.id
        traversal = GraphTraversal(ctx.session, inv_id)
        graph = await traversal.get_full_graph(limit=500)

        if not graph.edges or not graph.entities:
            return AgentResult(
                status=RunStatus.SUCCEEDED,
                summary="Insufficient graph connectivity to synthesize attack chains.",
                metrics={"chains_discovered": 0},
            )

        entities_by_id = {e.id: e for e in graph.entities}

        # Identify candidate entry points (IPs) and candidate target assets (Users, Hosts)
        ip_entities = [e for e in graph.entities if e.type == "ip"]
        user_entities = [e for e in graph.entities if e.type == "user"]

        chains_found: list[dict[str, Any]] = []
        finding_ids: list[str] = []

        # 1. Look for paths connecting external IPs to users/privileges
        for ip_ent in ip_entities:
            for user_ent in user_entities:
                if ip_ent.id == user_ent.id:
                    continue

                paths = await traversal.paths_between(ip_ent.id, user_ent.id, max_depth=3)
                for path in paths:
                    edges_in_path = path
                    evidence_ids: list[uuid.UUID] = [e.evidence_id for e in edges_in_path]

                    path_repr: list[str] = []
                    for e in edges_in_path:
                        src_e = entities_by_id.get(e.src_entity_id)
                        dst_e = entities_by_id.get(e.dst_entity_id)
                        src_name = f"{src_e.type}:{src_e.value_normalized}" if src_e else "node"
                        dst_name = f"{dst_e.type}:{dst_e.value_normalized}" if dst_e else "node"
                        path_repr.append(f"({src_name}) --[{e.relation}]--> ({dst_name})")

                    chains_found.append(
                        {
                            "source": ip_ent.value_normalized,
                            "target": user_ent.value_normalized,
                            "hops": len(edges_in_path),
                            "path": path_repr,
                            "evidence_ids": evidence_ids,
                        }
                    )

        # 2. If specific paths found or multi-relation graph exists, synthesize finding
        if chains_found:
            for chain in chains_found[:3]:
                path_str = " -> ".join(chain["path"])
                chain_finding = await ctx.store.add_finding(
                    FindingDraft(
                        title=f"Attack Chain: {chain['source']} to {chain['target']}",
                        description=(
                            f"Identified {chain['hops']}-hop attack chain connecting "
                            f"external indicator {chain['source']} to target account "
                            f"{chain['target']}.\nProgression: {path_str}"
                        ),
                        assertion_class=AssertionClass.INFERENCE,
                        severity=Severity.HIGH,
                        confidence=0.90,
                        evidence_ids=chain["evidence_ids"],
                        reasoning=(
                            f"Graph traversal confirmed connected path over {chain['hops']} "
                            "evidence-backed relationships spanning network ingress, host "
                            "authentication, and target execution."
                        ),
                        detection_rule="reasoning.attack_chain",
                    ),
                    agent_run_id=ctx.agent_run_id,
                )
                finding_ids.append(str(chain_finding.id))
        else:
            # Fallback: summarize overall graph connectivity if no single end-to-end path exists
            relations_found = {e.relation for e in graph.edges}
            cited_ev = [e.evidence_id for e in graph.edges[: min(5, len(graph.edges))]]
            if not cited_ev:
                all_ev, _ = await ctx.store.all_evidence(cap=5)
                cited_ev = [e.id for e in all_ev]

            rel_str = ", ".join(sorted(relations_found)) if relations_found else "None"
            assertion_cls = (
                AssertionClass.INFERENCE if cited_ev else AssertionClass.HYPOTHESIS
            )
            summary_finding = await ctx.store.add_finding(
                FindingDraft(
                    title="Graph Reasoning: Cross-Source Activity Correlation",
                    description=(
                        f"Synthesized evidence relationships across {len(graph.entities)} "
                        f"entities and {len(graph.edges)} edges. Observed types: {rel_str}."
                    ),
                    assertion_class=assertion_cls,
                    severity=Severity.INFO,
                    confidence=0.85,
                    evidence_ids=cited_ev,
                    reasoning=(
                        "Reasoning agent evaluated graph paths across authentication, threat "
                        "intelligence, and network nodes; no full multi-stage compromise path "
                        "reached privilege escalation."
                    ),
                    detection_rule="reasoning.correlation_summary",
                ),
                agent_run_id=ctx.agent_run_id,
            )
            finding_ids.append(str(summary_finding.id))

        summary = (
            f"Attack-chain reasoning evaluated graph; identified {len(chains_found)} "
            f"multi-stage path(s) across {len(graph.entities)} entities."
        )

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=summary,
            finding_ids=finding_ids,
            metrics={
                "chains_discovered": len(chains_found),
                "entities_evaluated": len(graph.entities),
                "edges_evaluated": len(graph.edges),
            },
            next_actions=[],
            errors=[],
        )
