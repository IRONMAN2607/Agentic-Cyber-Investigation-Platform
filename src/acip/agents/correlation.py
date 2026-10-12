"""Evidence graph correlation and entity resolution agent.

Performs Tier 1 canonical entity resolution and derives evidence-backed relational
edges across heterogeneous telemetry sources (authentication logs, web access logs,
PCAP network flows, DNS queries, and threat intelligence).

Enforces Invariant G0-G2: Every relationship edge is backed by an immutable
evidence row. No silent merges or synthetic ungrounded links are permitted.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any, ClassVar

import sqlalchemy as sa

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.core.evidence.contracts import (
    EntityRef,
    FindingDraft,
    normalize_entity_value,
)
from acip.db.models import Entity, EntityEdge, Evidence, FindingEvidence
from acip.logging import get_logger
from acip.types import (
    AgentCapability,
    AssertionClass,
    EntityType,
    EvidenceKind,
    EvidenceRole,
    RunStatus,
    Severity,
)

logger = get_logger(__name__)


class CorrelationAgent(Agent):
    """Deterministic evidence graph correlation and entity resolution agent."""

    name: ClassVar[str] = "correlation"
    version: ClassVar[str] = "0.1.0"
    capability: ClassVar[AgentCapability] = AgentCapability.CORRELATION
    description: ClassVar[str] = (
        "Builds canonical evidence graph, resolves entities deterministically, "
        "and derives evidence-backed relational edges."
    )

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        inv_id = ctx.investigation.id

        # 1. Fetch all evidence collected for this investigation up to the cap
        evidence_rows, truncated = await ctx.store.all_evidence(cap=10_000)

        # 2. Pre-load existing entities and edges for idempotency
        existing_ent_stmt = sa.select(Entity).where(Entity.investigation_id == inv_id)
        existing_ents = list((await ctx.session.scalars(existing_ent_stmt)).all())
        entities_by_key: dict[tuple[str, str], Entity] = {
            (e.type, e.value_normalized): e for e in existing_ents
        }

        existing_edges_stmt = sa.select(EntityEdge).where(EntityEdge.investigation_id == inv_id)
        existing_edges = list((await ctx.session.scalars(existing_edges_stmt)).all())
        existing_edge_keys: set[tuple[uuid.UUID, uuid.UUID, str, uuid.UUID]] = {
            (e.src_entity_id, e.dst_entity_id, e.relation, e.evidence_id) for e in existing_edges
        }

        # 3. Resolve and upsert canonical entities across all evidence
        new_entities_count = 0
        for ev in evidence_rows:
            extracted_refs = self._extract_entity_refs(ev)
            for ref in extracted_refs:
                norm_val = normalize_entity_value(ref.type, ref.value)
                key = (ref.type.value, norm_val)

                if key in entities_by_key:
                    ent = entities_by_key[key]
                    ent.observation_count += 1
                    if ev.observed_at is not None:
                        if ent.first_seen_at is None or ev.observed_at < ent.first_seen_at:
                            ent.first_seen_at = ev.observed_at
                        if ent.last_seen_at is None or ev.observed_at > ent.last_seen_at:
                            ent.last_seen_at = ev.observed_at
                else:
                    ent = Entity(
                        investigation_id=inv_id,
                        type=ref.type.value,
                        value_normalized=norm_val,
                        value_raw_first_seen=ref.value,
                        first_seen_at=ev.observed_at,
                        last_seen_at=ev.observed_at,
                        observation_count=1,
                    )
                    ctx.session.add(ent)
                    entities_by_key[key] = ent
                    new_entities_count += 1

        # Flush to ensure all entities have database-assigned IDs
        await ctx.session.flush()

        # 4. Construct evidence-backed relational edges
        new_edges_count = 0
        relations_by_type: dict[str, int] = defaultdict(int)

        for ev in evidence_rows:
            derived_edges = self._derive_edges_for_evidence(ev, entities_by_key)
            for src_id, dst_id, relation in derived_edges:
                edge_key = (src_id, dst_id, relation, ev.id)
                if edge_key in existing_edge_keys:
                    continue

                edge = EntityEdge(
                    investigation_id=inv_id,
                    src_entity_id=src_id,
                    dst_entity_id=dst_id,
                    relation=relation,
                    evidence_id=ev.id,
                    observed_at=ev.observed_at,
                    confidence=ev.confidence,
                )
                ctx.session.add(edge)
                existing_edge_keys.add(edge_key)
                new_edges_count += 1
                relations_by_type[relation] += 1

        await ctx.session.flush()

        # 5. Ensure FindingEvidence citations exist for all findings
        findings = await ctx.store.list_findings()
        fe_stmt = sa.select(FindingEvidence).where(
            FindingEvidence.finding_id.in_([f.id for f in findings]) if findings else sa.false()
        )
        existing_fe_keys = {
            (fe.finding_id, fe.evidence_id, fe.role)
            for fe in (await ctx.session.scalars(fe_stmt)).all()
        }

        for finding in findings:
            for eid_str in finding.evidence_ids:
                try:
                    eid = uuid.UUID(eid_str)
                except (ValueError, TypeError):
                    continue
                fe_key = (finding.id, eid, EvidenceRole.SUPPORTS.value)
                if fe_key not in existing_fe_keys:
                    ctx.session.add(
                        FindingEvidence(
                            finding_id=finding.id,
                            evidence_id=eid,
                            role=EvidenceRole.SUPPORTS.value,
                        )
                    )
                    existing_fe_keys.add(fe_key)

        await ctx.session.flush()

        # 6. Formulate correlation findings if meaningful patterns emerge
        finding_ids: list[str] = []
        if len(evidence_rows) > 0 and (len(entities_by_key) > 0 or new_edges_count > 0):
            # Find high-centrality or multi-event indicators
            top_entities = sorted(
                entities_by_key.values(),
                key=lambda e: e.observation_count,
                reverse=True,
            )[:5]

            entity_summary = ", ".join(
                f"{e.type}:{e.value_normalized} ({e.observation_count}x)" for e in top_entities
            )

            # Pick cited evidence from top entities or first evidence items
            cited_ev_ids = [ev.id for ev in evidence_rows[: min(5, len(evidence_rows))]]

            corr_finding = await ctx.store.add_finding(
                FindingDraft(
                    title="Cross-Source Evidence Graph Correlation",
                    description=(
                        f"Resolved {len(entities_by_key)} canonical entities and "
                        f"{len(existing_edge_keys)} relational edges across {len(evidence_rows)} "
                        f"evidence observations. Key correlated entities: {entity_summary}."
                    ),
                    assertion_class=AssertionClass.INFERENCE,
                    severity=Severity.INFO,
                    confidence=1.0,
                    evidence_ids=cited_ev_ids,
                    reasoning=(
                        f"Deterministic graph correlation derived {new_edges_count} new edge(s) "
                        f"connecting entities across authentication, network, and web telemetry."
                    ),
                    detection_rule="correlation.graph_construction",
                ),
                agent_run_id=ctx.agent_run_id,
            )
            finding_ids.append(str(corr_finding.id))

        summary = (
            f"Evidence graph correlation resolved {len(entities_by_key)} entities "
            f"({new_entities_count} new) and {len(existing_edge_keys)} edges "
            f"({new_edges_count} new) across {len(evidence_rows)} evidence observations."
        )

        return AgentResult(
            status=RunStatus.SUCCEEDED,
            summary=summary,
            finding_ids=finding_ids,
            metrics={
                "total_entities": len(entities_by_key),
                "new_entities": new_entities_count,
                "total_edges": len(existing_edge_keys),
                "new_edges": new_edges_count,
                "relations_by_type": dict(relations_by_type),
                "truncated": truncated,
            },
            next_actions=[],
            errors=[],
        )

    # --- Helper methods ------------------------------------------------------

    def _extract_entity_refs(self, ev: Evidence) -> list[EntityRef]:
        """Extract all typed EntityRef instances from an evidence row."""
        refs: list[EntityRef] = []
        seen: set[tuple[EntityType, str]] = set()

        raw_entities = ev.entities or {}
        raw_list: list[dict[str, Any]] = []
        if isinstance(raw_entities, dict):
            raw_list = raw_entities.get("refs", [])
        elif isinstance(raw_entities, list):
            raw_list = raw_entities

        for item in raw_list:
            if not isinstance(item, dict):
                continue
            etype_str = item.get("type")
            val = str(item.get("value") or "").strip()
            role = item.get("role")
            if not etype_str or not val:
                continue
            try:
                etype = EntityType(etype_str)
            except ValueError:
                continue

            pair = (etype, val)
            if pair not in seen:
                seen.add(pair)
                refs.append(EntityRef(type=etype, value=val, role=role))

        # Also inspect ev.data for standard entity attributes if not already captured
        data = ev.data or {}
        candidates: list[tuple[EntityType, str, str | None]] = []

        if data.get("host"):
            candidates.append((EntityType.HOST, str(data["host"]), "target"))
        if data.get("target_host"):
            candidates.append((EntityType.HOST, str(data["target_host"]), "target"))
        if data.get("user"):
            candidates.append((EntityType.USER, str(data["user"]), "actor"))
        if data.get("target_user"):
            candidates.append((EntityType.USER, str(data["target_user"]), "target"))
        if data.get("source_ip"):
            candidates.append((EntityType.IP, str(data["source_ip"]), "source"))
        if data.get("client_ip"):
            candidates.append((EntityType.IP, str(data["client_ip"]), "source"))
        if data.get("src_ip"):
            candidates.append((EntityType.IP, str(data["src_ip"]), "source"))
        if data.get("dst_ip"):
            candidates.append((EntityType.IP, str(data["dst_ip"]), "target"))
        if data.get("query") and ev.kind == EvidenceKind.DNS_QUERY.value:
            candidates.append((EntityType.DOMAIN, str(data["query"]), "query"))
        if (
            data.get("answers")
            and isinstance(data["answers"], list)
            and ev.kind == EvidenceKind.DNS_QUERY.value
        ):
            for ans in data["answers"]:
                candidates.append((EntityType.IP, str(ans), "resolved_ip"))
        if data.get("path") and ev.kind in {
            EvidenceKind.WEB_REQUEST.value,
            EvidenceKind.WEB_ATTACK.value,
        }:
            candidates.append((EntityType.URL, str(data["path"]), "target"))

        for etype, val, role in candidates:
            v_clean = val.strip()
            if not v_clean:
                continue
            pair = (etype, v_clean)
            if pair not in seen:
                seen.add(pair)
                refs.append(EntityRef(type=etype, value=v_clean, role=role))

        return refs

    def _derive_edges_for_evidence(
        self,
        ev: Evidence,
        entities_by_key: dict[tuple[str, str], Entity],
    ) -> list[tuple[uuid.UUID, uuid.UUID, str]]:
        """Derive directed, typed relationship edges backed by this evidence row."""
        derived: list[tuple[uuid.UUID, uuid.UUID, str]] = []
        data = ev.data or {}
        kind = ev.kind

        def get_ent_id(etype: EntityType, raw_val: str | None) -> uuid.UUID | None:
            if not raw_val:
                return None
            norm = normalize_entity_value(etype, raw_val)
            ent = entities_by_key.get((etype.value, norm))
            return ent.id if ent else None

        # 1. Authentication events
        if kind == EvidenceKind.AUTH_EVENT.value:
            user_id = get_ent_id(EntityType.USER, data.get("user"))
            host_id = get_ent_id(EntityType.HOST, data.get("host"))
            src_ip_id = get_ent_id(EntityType.IP, data.get("source_ip"))
            tgt_user_id = get_ent_id(EntityType.USER, data.get("target_user"))
            src_port = data.get("source_port")
            port_id = get_ent_id(EntityType.PORT, str(src_port)) if src_port else None

            outcome = data.get("outcome", "neutral")
            if user_id and host_id:
                if outcome == "failure":
                    derived.append((user_id, host_id, "FAILED_AUTH_TO"))
                elif outcome == "success":
                    derived.append((user_id, host_id, "AUTHENTICATED_TO"))

            if src_ip_id and host_id:
                derived.append((src_ip_id, host_id, "CONNECTED_FROM"))

            if user_id and tgt_user_id and user_id != tgt_user_id:
                derived.append((user_id, tgt_user_id, "ASSOCIATED_WITH"))

            if src_ip_id and port_id:
                derived.append((src_ip_id, port_id, "CONNECTED_TO_PORT"))

        # 2. Web server access and attack events
        elif kind in {EvidenceKind.WEB_REQUEST.value, EvidenceKind.WEB_ATTACK.value}:
            client_ip_id = get_ent_id(EntityType.IP, data.get("client_ip") or data.get("source_ip"))
            host_id = get_ent_id(EntityType.HOST, data.get("host"))
            path_id = get_ent_id(EntityType.URL, data.get("path"))
            user_id = get_ent_id(EntityType.USER, data.get("user"))

            if client_ip_id and host_id:
                derived.append((client_ip_id, host_id, "CONNECTED_FROM"))

            if client_ip_id and path_id:
                derived.append((client_ip_id, path_id, "CONTACTED"))

            if user_id and host_id:
                derived.append((user_id, host_id, "AUTHENTICATED_TO"))

        # 3. Network flows
        elif kind == EvidenceKind.NETWORK_FLOW.value:
            src_ip_id = get_ent_id(EntityType.IP, data.get("src_ip"))
            dst_ip_id = get_ent_id(EntityType.IP, data.get("dst_ip"))
            dst_port = data.get("dst_port")
            port_id = get_ent_id(EntityType.PORT, str(dst_port)) if dst_port else None

            if src_ip_id and dst_ip_id:
                derived.append((src_ip_id, dst_ip_id, "CONTACTED"))

            if dst_ip_id and port_id:
                derived.append((dst_ip_id, port_id, "LISTENS_ON"))

        # 4. DNS queries
        elif kind == EvidenceKind.DNS_QUERY.value:
            client_ip_id = get_ent_id(EntityType.IP, data.get("client_ip"))
            domain_id = get_ent_id(EntityType.DOMAIN, data.get("query"))

            if client_ip_id and domain_id:
                derived.append((client_ip_id, domain_id, "CONTACTED"))

            answers = data.get("answers", [])
            if isinstance(answers, list) and domain_id:
                for ans_ip in answers:
                    ans_ip_id = get_ent_id(EntityType.IP, str(ans_ip))
                    if ans_ip_id:
                        derived.append((domain_id, ans_ip_id, "RESOLVES_TO"))

        # 5. Threat Intelligence
        elif kind == EvidenceKind.THREAT_INTEL.value:
            indicator_val = data.get("query")
            indicator_type_str = data.get("entity_type")
            if indicator_val and indicator_type_str:
                try:
                    ind_type = EntityType(indicator_type_str)
                    ind_id = get_ent_id(ind_type, str(indicator_val))
                    for tag in data.get("tags", []):
                        tag_id = get_ent_id(EntityType.MALWARE, str(tag))
                        if ind_id and tag_id:
                            derived.append((ind_id, tag_id, "ASSOCIATED_WITH"))
                except ValueError:
                    pass

        # 6. Fallback: If no edges were formed yet and exactly two entities exist on the event
        if not derived:
            event_refs = self._extract_entity_refs(ev)
            if len(event_refs) == 2:
                id1 = get_ent_id(event_refs[0].type, event_refs[0].value)
                id2 = get_ent_id(event_refs[1].type, event_refs[1].value)
                if id1 and id2 and id1 != id2:
                    derived.append((id1, id2, "ASSOCIATED_WITH"))

        return derived
