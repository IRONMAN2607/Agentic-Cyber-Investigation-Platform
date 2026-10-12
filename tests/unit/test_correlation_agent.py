from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.base import AgentContext
from acip.agents.correlation import CorrelationAgent
from acip.config import Settings
from acip.core.evidence.contracts import EvidenceDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AgentRun, Entity, EntityEdge, Investigation, ToolRun, User
from acip.db.session import Database
from acip.tools.registry import build_default_registry
from acip.tools.runner import ToolRunner
from acip.types import EvidenceKind, RunStatus


@pytest.mark.asyncio
async def test_correlation_agent_extracts_entities_and_builds_edges(
    database: Database, tmp_path: Path
) -> None:
    settings = Settings(
        environment="test",
        database_url=database.url,
        artifact_dir=tmp_path,
        secret_key=SecretStr("test-secret-at-least-32-bytes-long-hs256"),
    )

    async with database.session() as session:
        user = await session.scalar(sa.select(User))
        assert user is not None

        inv = Investigation(
            title="Correlation Agent Test",
            target_type="log",
            target_value="test.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t-corr",
            agent_name="correlation",
            agent_version="0.1.0",
            status=RunStatus.RUNNING.value,
        )
        session.add(agent_run)
        await session.flush()

        tool_run = ToolRun(
            investigation_id=inv.id,
            tool_name="test_tool",
            tool_version="0.1.0",
            sandbox_tier="t0_in_process",
            args={},
            status=RunStatus.SUCCEEDED.value,
        )
        session.add(tool_run)
        await session.flush()

        store = EvidenceStore(session, inv.id)

        # 1. Add authentications (one success, one failure)
        t0 = dt.datetime(2026, 10, 1, 12, 0, 0, tzinfo=dt.UTC)
        ev_auth1 = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={
                "event_type": "auth_success",
                "outcome": "success",
                "user": "alice",
                "host": "srv01.corp",
                "source_ip": "192.168.1.100",
            },
            observed_at=t0,
        )
        ev_auth2 = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={
                "event_type": "auth_failure",
                "outcome": "failure",
                "user": "alice",
                "host": "srv01.corp",
                "source_ip": "192.168.1.100",
            },
            observed_at=t0 + dt.timedelta(minutes=1),
        )

        # 2. Add web request from same IP to URL
        ev_web = EvidenceDraft(
            kind=EvidenceKind.WEB_REQUEST,
            data={
                "event_type": "web_request",
                "client_ip": "192.168.1.100",
                "host": "web01.corp",
                "path": "/api/v1/data",
            },
            observed_at=t0 + dt.timedelta(minutes=2),
        )

        # 3. Add DNS query resolving domain to IP
        ev_dns = EvidenceDraft(
            kind=EvidenceKind.DNS_QUERY,
            data={
                "client_ip": "192.168.1.100",
                "query": "malicious.test.",
                "answers": ["198.51.100.25"],
            },
            observed_at=t0 + dt.timedelta(minutes=3),
        )

        await store.add_evidence(
            [ev_auth1, ev_auth2, ev_web, ev_dns],
            source_tool="test_tool",
            tool_run_id=tool_run.id,
        )

        tools = ToolRunner(
            session=session,
            investigation_id=inv.id,
            registry=build_default_registry(),
            store=store,
            artifact_root=tmp_path,
        )

        ctx = AgentContext(
            investigation=inv,
            artifacts=[],
            session=session,
            store=store,
            tools=tools,
            settings=settings,
            agent_run_id=agent_run.id,
        )

        agent = CorrelationAgent()
        result = await agent.run(ctx, {})

        assert result.status == RunStatus.SUCCEEDED
        assert result.metrics["total_entities"] >= 5
        assert result.metrics["total_edges"] >= 4
        assert len(result.finding_ids) == 1

        # Check DB Entities
        entities = list(
            (
                await session.scalars(sa.select(Entity).where(Entity.investigation_id == inv.id))
            ).all()
        )
        ent_values = {e.value_normalized for e in entities}
        assert "alice" in ent_values
        assert "srv01.corp" in ent_values
        assert "192.168.1.100" in ent_values
        assert "malicious.test" in ent_values  # Trailing dot stripped
        assert "198.51.100.25" in ent_values

        # Check DB Edges
        edges = list(
            (
                await session.scalars(
                    sa.select(EntityEdge).where(EntityEdge.investigation_id == inv.id)
                )
            ).all()
        )
        relations = {e.relation for e in edges}
        assert "AUTHENTICATED_TO" in relations
        assert "FAILED_AUTH_TO" in relations
        assert "CONNECTED_FROM" in relations
        assert "RESOLVES_TO" in relations

        # Verify idempotency: running a second time should not duplicate records
        result_2 = await agent.run(ctx, {})
        assert result_2.status == RunStatus.SUCCEEDED
        assert result_2.metrics["new_entities"] == 0
        assert result_2.metrics["new_edges"] == 0

        entities_count_2 = await session.scalar(
            sa.select(sa.func.count(Entity.id)).where(Entity.investigation_id == inv.id)
        )
        assert entities_count_2 == len(entities)

        edges_count_2 = await session.scalar(
            sa.select(sa.func.count(EntityEdge.id)).where(EntityEdge.investigation_id == inv.id)
        )
        assert edges_count_2 == len(edges)
