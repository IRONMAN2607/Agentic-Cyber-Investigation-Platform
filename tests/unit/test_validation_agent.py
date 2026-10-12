from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.base import AgentContext
from acip.agents.validation import ValidationAgent
from acip.config import Settings
from acip.core.evidence.contracts import EvidenceDraft, HypothesisDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AgentRun, Hypothesis, Investigation, ToolRun, User
from acip.db.session import Database
from acip.tools.registry import build_default_registry
from acip.tools.runner import ToolRunner
from acip.types import EvidenceKind, HypothesisStatus, RunStatus


@pytest.mark.asyncio
async def test_validation_agent_evaluates_refutations_and_bounds_loops(
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
            title="Validation Agent Test",
            target_type="log",
            target_value="test.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t-val",
            agent_name="validation",
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

        # Ingest attack evidence
        t0 = dt.datetime(2026, 10, 1, 10, 0, 0, tzinfo=dt.UTC)
        ev_attack = EvidenceDraft(
            kind=EvidenceKind.WEB_ATTACK,
            data={"outcome": "failure", "attacks": [{"category": "sql_injection"}]},
            observed_at=t0,
        )
        ev_priv = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={"event_type": "sudo_command", "user": "deploy", "target_user": "root"},
            observed_at=t0 + dt.timedelta(minutes=2),
        )
        created_evs = await store.add_evidence(
            [ev_attack, ev_priv],
            source_tool="test_tool",
            tool_run_id=tool_run.id,
        )

        # Add 2 hypotheses:
        # H1: Intrusion attack
        # H2: Benign glitched script
        h1 = await store.add_hypothesis(
            HypothesisDraft(
                statement="Malicious intrusion campaign against web server.",
                refutation_condition="Proof of authorized red team exercise.",
                confidence=0.8,
                supporting_evidence_ids=[created_evs[0].id],
            ),
            agent_run_id=agent_run.id,
        )
        h2 = await store.add_hypothesis(
            HypothesisDraft(
                statement="Benign script retry glitch.",
                refutation_condition="Evidence of unauthorized privilege escalation or command execution.",
                confidence=0.2,
                contradicting_evidence_ids=[created_evs[1].id],
            ),
            agent_run_id=agent_run.id,
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

        agent = ValidationAgent()
        result = await agent.run(ctx, {"iteration": 1})

        assert result.status == RunStatus.SUCCEEDED
        assert result.metrics["supported"] == 1
        assert result.metrics["refuted"] == 1
        assert result.metrics["loop_bounded"] is True

        # Check DB statuses
        h1_db = await session.get(Hypothesis, h1.id)
        assert h1_db is not None
        assert h1_db.status == HypothesisStatus.SUPPORTED.value

        h2_db = await session.get(Hypothesis, h2.id)
        assert h2_db is not None
        assert h2_db.status == HypothesisStatus.REFUTED.value
