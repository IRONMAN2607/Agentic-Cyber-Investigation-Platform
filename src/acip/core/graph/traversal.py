"""Evidence graph traversal engine.

Confined to this module per docs/evidence-graph.md. Every traversal is
depth-bounded and result-capped to prevent unbounded recursion or denial of service.
Provides neighbour queries, path finding between entities, finding subgraphs,
and chronological event timelines.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from acip.db.models import Entity, EntityEdge, Evidence, Finding, FindingEvidence
from acip.logging import get_logger

logger = get_logger(__name__)

DEFAULT_MAX_DEPTH = 3
ABSOLUTE_MAX_DEPTH = 6
DEFAULT_RESULT_CAP = 250
ABSOLUTE_RESULT_CAP = 1000


@dataclass(frozen=True, slots=True)
class GraphSubgraph:
    """A bounded subgraph of nodes and evidence-backed edges."""

    investigation_id: uuid.UUID
    entities: list[Entity]
    edges: list[EntityEdge]
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": str(self.investigation_id),
            "entities": [
                {
                    "id": str(e.id),
                    "investigation_id": str(e.investigation_id),
                    "type": e.type,
                    "value_normalized": e.value_normalized,
                    "value_raw_first_seen": e.value_raw_first_seen,
                    "first_seen_at": e.first_seen_at.isoformat() if e.first_seen_at else None,
                    "last_seen_at": e.last_seen_at.isoformat() if e.last_seen_at else None,
                    "observation_count": e.observation_count,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in self.entities
            ],
            "edges": [
                {
                    "id": str(edge.id),
                    "investigation_id": str(edge.investigation_id),
                    "src_entity_id": str(edge.src_entity_id),
                    "dst_entity_id": str(edge.dst_entity_id),
                    "relation": edge.relation,
                    "evidence_id": str(edge.evidence_id),
                    "observed_at": edge.observed_at.isoformat() if edge.observed_at else None,
                    "confidence": edge.confidence,
                    "created_at": edge.created_at.isoformat() if edge.created_at else None,
                }
                for edge in self.edges
            ],
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    """An ordered timeline observation with provenance."""

    evidence_id: uuid.UUID
    observed_at: dt.datetime | None
    source_tool: str
    kind: str
    time_confidence: str
    summary: str
    entities: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": str(self.evidence_id),
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "source_tool": self.source_tool,
            "kind": self.kind,
            "time_confidence": self.time_confidence,
            "summary": self.summary,
            "entities": self.entities,
        }


class GraphTraversal:
    """Bounded, cycle-safe traversal engine over relational evidence graphs."""

    def __init__(self, session: AsyncSession, investigation_id: uuid.UUID) -> None:
        self._session = session
        self._investigation_id = investigation_id

    async def get_full_graph(
        self,
        *,
        limit: int = DEFAULT_RESULT_CAP,
    ) -> GraphSubgraph:
        """Fetch the full evidence graph for this investigation, capped to limit."""
        cap = min(limit, ABSOLUTE_RESULT_CAP)

        edges_stmt = (
            sa.select(EntityEdge)
            .where(EntityEdge.investigation_id == self._investigation_id)
            .order_by(EntityEdge.created_at)
            .limit(cap + 1)
        )
        edge_rows = (await self._session.scalars(edges_stmt)).all()
        truncated = len(edge_rows) > cap
        edges = list(edge_rows[:cap])

        entity_ids: set[uuid.UUID] = set()
        for e in edges:
            entity_ids.add(e.src_entity_id)
            entity_ids.add(e.dst_entity_id)

        entities: list[Entity] = []
        if entity_ids:
            ent_stmt = sa.select(Entity).where(
                Entity.investigation_id == self._investigation_id,
                Entity.id.in_(entity_ids),
            )
            entities = list((await self._session.scalars(ent_stmt)).all())
        else:
            # If no edges exist, still load isolated entities up to cap
            all_ent_stmt = (
                sa.select(Entity)
                .where(Entity.investigation_id == self._investigation_id)
                .limit(cap)
            )
            entities = list((await self._session.scalars(all_ent_stmt)).all())

        return GraphSubgraph(
            investigation_id=self._investigation_id,
            entities=entities,
            edges=edges,
            truncated=truncated,
        )

    async def neighbours(
        self,
        start_entity_id: uuid.UUID,
        *,
        max_depth: int = DEFAULT_MAX_DEPTH,
        limit: int = DEFAULT_RESULT_CAP,
    ) -> GraphSubgraph:
        """Find entities and edges within max_depth hops of start_entity_id.

        Cycle-safe and bounded by max_depth and limit.
        """
        depth_bound = min(max_depth, ABSOLUTE_MAX_DEPTH)
        cap = min(limit, ABSOLUTE_RESULT_CAP)

        visited_entities: set[uuid.UUID] = {start_entity_id}
        collected_edges: list[EntityEdge] = []
        queue: deque[tuple[uuid.UUID, int]] = deque([(start_entity_id, 0)])

        while queue and len(collected_edges) < cap:
            curr_id, curr_depth = queue.popleft()
            if curr_depth >= depth_bound:
                continue

            # Query outbound and inbound edges from curr_id
            stmt = sa.select(EntityEdge).where(
                EntityEdge.investigation_id == self._investigation_id,
                sa.or_(
                    EntityEdge.src_entity_id == curr_id,
                    EntityEdge.dst_entity_id == curr_id,
                ),
            )
            adjacent_edges = (await self._session.scalars(stmt)).all()

            for edge in adjacent_edges:
                if edge not in collected_edges:
                    collected_edges.append(edge)
                    if len(collected_edges) >= cap:
                        break

                neighbour_id = (
                    edge.dst_entity_id if edge.src_entity_id == curr_id else edge.src_entity_id
                )
                if neighbour_id not in visited_entities:
                    visited_entities.add(neighbour_id)
                    queue.append((neighbour_id, curr_depth + 1))

        # Fetch full Entity records for all visited entities
        ent_stmt = sa.select(Entity).where(
            Entity.investigation_id == self._investigation_id,
            Entity.id.in_(visited_entities),
        )
        entities = list((await self._session.scalars(ent_stmt)).all())

        return GraphSubgraph(
            investigation_id=self._investigation_id,
            entities=entities,
            edges=collected_edges,
            truncated=len(collected_edges) >= cap,
        )

    async def paths_between(
        self,
        src_entity_id: uuid.UUID,
        dst_entity_id: uuid.UUID,
        *,
        max_depth: int = 4,
        limit: int = 25,
    ) -> list[list[EntityEdge]]:
        """Find all distinct paths connecting src_entity_id to dst_entity_id."""
        if src_entity_id == dst_entity_id:
            return []

        depth_bound = min(max_depth, ABSOLUTE_MAX_DEPTH)
        cap = min(limit, 50)

        # BFS path enumeration with cycle avoidance
        paths: list[list[EntityEdge]] = []
        queue: deque[tuple[uuid.UUID, list[EntityEdge], set[uuid.UUID]]] = deque(
            [(src_entity_id, [], {src_entity_id})]
        )

        while queue and len(paths) < cap:
            curr_id, current_path, visited = queue.popleft()
            if len(current_path) >= depth_bound:
                continue

            stmt = sa.select(EntityEdge).where(
                EntityEdge.investigation_id == self._investigation_id,
                EntityEdge.src_entity_id == curr_id,
            )
            out_edges = (await self._session.scalars(stmt)).all()

            for edge in out_edges:
                next_id = edge.dst_entity_id
                if next_id == dst_entity_id:
                    paths.append([*current_path, edge])
                    if len(paths) >= cap:
                        break
                elif next_id not in visited:
                    queue.append((next_id, [*current_path, edge], visited | {next_id}))

        return paths

    async def subgraph_for_finding(
        self,
        finding_id: uuid.UUID,
        *,
        limit: int = DEFAULT_RESULT_CAP,
    ) -> GraphSubgraph:
        """Extract the evidence graph connected to a specific finding's cited evidence."""
        # Find citations via FindingEvidence or direct finding.evidence_ids
        fe_stmt = sa.select(FindingEvidence).where(FindingEvidence.finding_id == finding_id)
        fe_rows = (await self._session.scalars(fe_stmt)).all()
        cited_evidence_ids = {row.evidence_id for row in fe_rows}

        if not cited_evidence_ids:
            finding = await self._session.get(Finding, finding_id)
            if finding and finding.evidence_ids:
                for eid in finding.evidence_ids:
                    try:
                        cited_evidence_ids.add(uuid.UUID(str(eid)))
                    except (ValueError, TypeError):
                        pass

        if not cited_evidence_ids:
            return GraphSubgraph(
                investigation_id=self._investigation_id,
                entities=[],
                edges=[],
                truncated=False,
            )

        # Fetch edges backed by the cited evidence
        edge_stmt = (
            sa.select(EntityEdge)
            .where(
                EntityEdge.investigation_id == self._investigation_id,
                EntityEdge.evidence_id.in_(cited_evidence_ids),
            )
            .limit(limit)
        )
        edges = list((await self._session.scalars(edge_stmt)).all())

        entity_ids = {e.src_entity_id for e in edges} | {e.dst_entity_id for e in edges}
        entities: list[Entity] = []
        if entity_ids:
            ent_stmt = sa.select(Entity).where(
                Entity.investigation_id == self._investigation_id,
                Entity.id.in_(entity_ids),
            )
            entities = list((await self._session.scalars(ent_stmt)).all())

        return GraphSubgraph(
            investigation_id=self._investigation_id,
            entities=entities,
            edges=edges,
            truncated=len(edges) >= limit,
        )

    async def timeline(
        self,
        *,
        limit: int = 200,
    ) -> list[TimelineEvent]:
        """Construct a chronologically ordered event timeline over stored evidence."""
        stmt = (
            sa.select(Evidence)
            .where(Evidence.investigation_id == self._investigation_id)
            .order_by(
                sa.nulls_last(Evidence.observed_at.asc()),
                Evidence.collected_at.asc(),
            )
            .limit(min(limit, 1000))
        )
        evidence_rows = (await self._session.scalars(stmt)).all()

        timeline_items: list[TimelineEvent] = []
        for ev in evidence_rows:
            data = ev.data or {}
            summary = (
                str(data.get("message"))
                or str(data.get("summary"))
                or f"{ev.kind} observed via {ev.source_tool}"
            )
            raw_entities = ev.entities or {}
            entity_list: list[dict[str, Any]] = []
            if isinstance(raw_entities, dict):
                entity_list = raw_entities.get("refs", [])
            elif isinstance(raw_entities, list):
                entity_list = raw_entities

            timeline_items.append(
                TimelineEvent(
                    evidence_id=ev.id,
                    observed_at=ev.observed_at,
                    source_tool=ev.source_tool,
                    kind=ev.kind,
                    time_confidence=ev.time_confidence,
                    summary=summary,
                    entities=entity_list,
                )
            )

        return timeline_items
