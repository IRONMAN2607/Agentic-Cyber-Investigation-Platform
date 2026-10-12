from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.base import AgentContext
from acip.agents.hypothesis import HypothesisAgent
from acip.config import Settings
from acip.core.evidence.contracts import EvidenceDraft, HypothesisDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AgentRun, Hypothesis, HypothesisGap, Investigation, ToolRun, User
from acip.db.session import Database
from acip.tools.registry import build_default_registry
from acip.tools.runner import ToolRunner
from acip.types import EvidenceKind, RunStatus


@pytest.mark.asyncio
async def test_hypothesis_agent_generates_competing_hypotheses_with_g3(
    database: Database, tmp_path: Path
) -> None:
    """HypothesisAgent generates competing hypotheses enforcing Invariant G3."""
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
            title="Hypothesis Test Investigation",
            target_type="log",
            target_value="test.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t-hypo",
            agent_name="hypothesis",
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

        # Ingest authentication brute force and sudo privilege escalation evidence
        t0 = dt.datetime(2026, 10, 1, 10, 0, 0, tzinfo=dt.UTC)
        ev_brute = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={"outcome": "failure", "user": "admin", "host": "web01"},
            observed_at=t0,
        )
        ev_sudo = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={"event_type": "sudo_command", "user": "deploy", "target_user": "root"},
            observed_at=t0 + dt.timedelta(minutes=5),
        )
        await store.add_evidence(
            [ev_brute, ev_sudo],
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

        agent = HypothesisAgent()
        result = await agent.run(ctx, {})

        assert result.status == RunStatus.SUCCEEDED
        assert result.metrics["hypotheses_generated"] == 2
        assert result.metrics["gaps_recorded"] == 2
        assert result.metrics["invariant_g3_verified"] is True

        # Verify hypotheses in database
        hypotheses = list(
            (
                await session.scalars(
                    sa.select(Hypothesis).where(Hypothesis.investigation_id == inv.id)
                )
            ).all()
        )
        assert len(hypotheses) == 2
        for h in hypotheses:
            assert h.refutation_condition.strip() != ""
            assert h.statement.strip() != ""
            assert 0.0 <= h.confidence <= 1.0

        # Verify hypothesis gaps
        gaps = list(
            (
                await session.scalars(
                    sa.select(HypothesisGap).where(
                        HypothesisGap.hypothesis_id.in_([h.id for h in hypotheses])
                    )
                )
            ).all()
        )
        assert len(gaps) == 2
        req_tools = {g.required_tool for g in gaps}
        assert "threat_intel" in req_tools
        assert "endpoint_telemetry" in req_tools


@pytest.mark.asyncio
async def test_invariant_g3_empty_refutation_condition_rejected(
    database: Database, tmp_path: Path
) -> None:
    """Invariant G3: A hypothesis without a refutation condition raises GroundingError."""
    async with database.session() as session:
        user = await session.scalar(sa.select(User))
        assert user is not None

        inv = Investigation(
            title="G3 Violation Test",
            target_type="log",
            target_value="test.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        # Attempt to persist a hypothesis with whitespace-only refutation condition
        with pytest.raises(ValueError):
            HypothesisDraft(
                statement="Adversary compromised web server via remote exploit.",
                refutation_condition="   ",  # Blank
                confidence=0.8,
            )
