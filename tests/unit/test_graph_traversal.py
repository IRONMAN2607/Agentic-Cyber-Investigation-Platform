from __future__ import annotations

import datetime as dt

import pytest
import sqlalchemy as sa

from acip.core.graph.traversal import GraphTraversal
from acip.db.models import (
    Entity,
    EntityEdge,
    Evidence,
    Finding,
    FindingEvidence,
    Investigation,
    User,
)
from acip.db.session import Database
from acip.types import EvidenceKind, EvidenceRole, Severity


@pytest.mark.asyncio
async def test_graph_traversal_neighbours_and_cycles(database: Database) -> None:
    """Test cycle-safe BFS neighbor discovery and depth bounding."""
    async with database.session() as session:
        user = await session.scalar(sa.select(User))
        assert user is not None

        inv = Investigation(
            title="Graph Traversal Test",
            target_type="log",
            target_value="test.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        # Create dummy evidence row for provenance
        ev = Evidence(
            investigation_id=inv.id,
            kind=EvidenceKind.AUTH_EVENT.value,
            source_tool="test_tool",
            content_hash="hash12345678",
            entities={"refs": [{"type": "ip", "value": "192.168.1.1"}]},
        )
        session.add(ev)
        await session.flush()

        # Create 3 entities forming a triangle/cycle: A -> B -> C -> A
        ent_a = Entity(
            investigation_id=inv.id,
            type="ip",
            value_normalized="10.0.0.1",
            value_raw_first_seen="10.0.0.1",
        )
        ent_b = Entity(
            investigation_id=inv.id,
            type="host",
            value_normalized="srv1",
            value_raw_first_seen="srv1",
        )
        ent_c = Entity(
            investigation_id=inv.id,
            type="user",
            value_normalized="admin",
            value_raw_first_seen="admin",
        )
        session.add_all([ent_a, ent_b, ent_c])
        await session.flush()

        edge_ab = EntityEdge(
            investigation_id=inv.id,
            src_entity_id=ent_a.id,
            dst_entity_id=ent_b.id,
            relation="CONNECTED_FROM",
            evidence_id=ev.id,
        )
        edge_bc = EntityEdge(
            investigation_id=inv.id,
            src_entity_id=ent_b.id,
            dst_entity_id=ent_c.id,
            relation="AUTHENTICATED_TO",
            evidence_id=ev.id,
        )
        edge_ca = EntityEdge(
            investigation_id=inv.id,
            src_entity_id=ent_c.id,
            dst_entity_id=ent_a.id,
            relation="ASSOCIATED_WITH",
            evidence_id=ev.id,
        )
        session.add_all([edge_ab, edge_bc, edge_ca])
        await session.flush()

        traversal = GraphTraversal(session, inv.id)

        # Depth 1 from A: should find B and C (via incoming edge CA or outgoing AB)
        subgraph = await traversal.neighbours(ent_a.id, max_depth=1)
        found_entity_ids = {e.id for e in subgraph.entities}
        assert ent_a.id in found_entity_ids
        assert len(subgraph.edges) >= 2

        # Full graph
        full_graph = await traversal.get_full_graph()
        assert len(full_graph.entities) == 3
        assert len(full_graph.edges) == 3
        assert not full_graph.truncated

        # Path between A and C
        paths = await traversal.paths_between(ent_a.id, ent_c.id)
        assert len(paths) >= 1
        path_relations = [e.relation for e in paths[0]]
        assert path_relations == ["CONNECTED_FROM", "AUTHENTICATED_TO"]


@pytest.mark.asyncio
async def test_graph_traversal_finding_subgraph_and_timeline(database: Database) -> None:
    """Test subgraph extraction for findings and chronological timeline generation."""
    async with database.session() as session:
        user = await session.scalar(sa.select(User))
        assert user is not None

        inv = Investigation(
            title="Finding Subgraph & Timeline Test",
            target_type="log",
            target_value="test.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        t0 = dt.datetime(2026, 10, 1, 10, 0, 0, tzinfo=dt.UTC)
        t1 = dt.datetime(2026, 10, 1, 10, 5, 0, tzinfo=dt.UTC)

        ev1 = Evidence(
            investigation_id=inv.id,
            kind=EvidenceKind.WEB_REQUEST.value,
            source_tool="web_parser",
            observed_at=t0,
            content_hash="hash_t0",
            data={"summary": "GET /login HTTP/1.1 200"},
            entities={"refs": [{"type": "ip", "value": "192.168.1.50", "role": "source"}]},
        )
        ev2 = Evidence(
            investigation_id=inv.id,
            kind=EvidenceKind.AUTH_EVENT.value,
            source_tool="auth_parser",
            observed_at=t1,
            content_hash="hash_t1",
            data={"summary": "Failed password for root from 192.168.1.50"},
            entities={"refs": [{"type": "user", "value": "root", "role": "actor"}]},
        )
        session.add_all([ev1, ev2])
        await session.flush()

        ent_ip = Entity(
            investigation_id=inv.id,
            type="ip",
            value_normalized="192.168.1.50",
            value_raw_first_seen="192.168.1.50",
        )
        ent_user = Entity(
            investigation_id=inv.id,
            type="user",
            value_normalized="root",
            value_raw_first_seen="root",
        )
        session.add_all([ent_ip, ent_user])
        await session.flush()

        edge = EntityEdge(
            investigation_id=inv.id,
            src_entity_id=ent_ip.id,
            dst_entity_id=ent_user.id,
            relation="ASSOCIATED_WITH",
            evidence_id=ev2.id,
        )
        session.add(edge)
        await session.flush()

        # Create finding citing ev2
        finding = Finding(
            investigation_id=inv.id,
            title="Suspicious SSH Activity",
            description="Failed logins for root",
            assertion_class="inference",
            severity=Severity.HIGH.value,
            confidence=0.9,
            evidence_ids=[str(ev2.id)],
            reasoning="Repeated failure pattern observed",
        )
        session.add(finding)
        await session.flush()

        session.add(
            FindingEvidence(
                finding_id=finding.id,
                evidence_id=ev2.id,
                role=EvidenceRole.SUPPORTS.value,
            )
        )
        await session.flush()

        traversal = GraphTraversal(session, inv.id)

        # 1. Timeline
        timeline = await traversal.timeline()
        assert len(timeline) == 2
        assert timeline[0].observed_at == t0
        assert timeline[1].observed_at == t1
        assert timeline[0].source_tool == "web_parser"
        assert timeline[1].source_tool == "auth_parser"
        assert len(timeline[0].entities) == 1
        assert timeline[0].entities[0]["value"] == "192.168.1.50"

        # 2. Subgraph for finding
        subgraph = await traversal.subgraph_for_finding(finding.id)
        assert len(subgraph.edges) == 1
        assert subgraph.edges[0].relation == "ASSOCIATED_WITH"
        assert len(subgraph.entities) == 2
