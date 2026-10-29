from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.base import AgentContext
from acip.agents.reasoning import ReasoningAgent
from acip.config import Settings
from acip.core.evidence.contracts import EvidenceDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AgentRun, Entity, EntityEdge, Finding, Investigation, ToolRun, User
from acip.db.session import Database
from acip.tools.registry import build_default_registry
from acip.tools.runner import ToolRunner
from acip.types import AssertionClass, EvidenceKind, RunStatus, Severity


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "initial_outcome",
    ["failure", "success"],
)
async def test_reasoning_agent_discovers_attack_chains_over_graph(
    database: Database, tmp_path: Path, initial_outcome: str
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
            title="Attack Chain Reasoning Test",
            target_type="log",
            target_value="test.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t-reasoning",
            agent_name="reasoning",
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

        # Ingest genuine tool evidence
        t0 = dt.datetime(2026, 10, 1, 12, 0, 0, tzinfo=dt.UTC)
        ev1 = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={
                "outcome": initial_outcome,
                "source_ip": "198.51.100.44",
                "user": "alice",
                "host": "srv1",
            },
            observed_at=t0,
        )
        ev2 = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={
                "outcome": "success",
                "source_ip": "198.51.100.44",
                "user": "alice",
                "host": "srv1",
            },
            observed_at=t0 + dt.timedelta(minutes=1),
        )
        created_evs = await store.add_evidence(
            [ev1, ev2],
            source_tool="test_tool",
            tool_run_id=tool_run.id,
        )

        # Construct entities and edge path: IP -> HOST -> USER
        ent_ip = Entity(
            investigation_id=inv.id,
            type="ip",
            value_normalized="198.51.100.44",
            value_raw_first_seen="198.51.100.44",
        )
        ent_host = Entity(
            investigation_id=inv.id,
            type="host",
            value_normalized="srv1",
            value_raw_first_seen="srv1",
        )
        ent_user = Entity(
            investigation_id=inv.id,
            type="user",
            value_normalized="alice",
            value_raw_first_seen="alice",
        )
        session.add_all([ent_ip, ent_host, ent_user])
        await session.flush()

        edge1 = EntityEdge(
            investigation_id=inv.id,
            src_entity_id=ent_ip.id,
            dst_entity_id=ent_host.id,
            relation="CONNECTED_FROM",
            evidence_id=created_evs[0].id,
        )
        edge2 = EntityEdge(
            investigation_id=inv.id,
            src_entity_id=ent_host.id,
            dst_entity_id=ent_user.id,
            relation="AUTHENTICATED_TO",
            evidence_id=created_evs[1].id,
        )
        session.add_all([edge1, edge2])
        await session.flush()

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

        agent = ReasoningAgent()
        result = await agent.run(ctx, {})

        assert result.status == RunStatus.SUCCEEDED
        if initial_outcome == "success":
            assert result.metrics["chains_discovered"] == 0
            all_findings = await store.list_findings()
            assert all(f.severity == Severity.INFO.value for f in all_findings)
            return

        assert result.metrics["chains_discovered"] >= 1
        assert len(result.finding_ids) >= 1

        # Check DB finding
        findings = list(
            (
                await session.scalars(
                    sa.select(Finding).where(
                        Finding.investigation_id == inv.id,
                        Finding.detection_rule == "reasoning.attack_chain",
                    )
                )
            ).all()
        )
        assert len(findings) >= 1
        chain_finding = findings[0]
        assert "Attack Chain" in chain_finding.title
        assert chain_finding.assertion_class == AssertionClass.INFERENCE.value
        assert str(created_evs[0].id) in chain_finding.evidence_ids
        assert str(created_evs[1].id) in chain_finding.evidence_ids
