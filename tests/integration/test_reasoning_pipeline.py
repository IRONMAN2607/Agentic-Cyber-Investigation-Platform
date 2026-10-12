from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.registry import build_default_registry
from acip.config import Settings
from acip.core.llm.router import build_default_router
from acip.core.orchestration.adaptive_planner import AdaptivePlanner
from acip.core.orchestration.orchestrator import OrchestratorAgent
from acip.db.models import (
    Artifact,
    Hypothesis,
    HypothesisGap,
    Investigation,
    Report,
    User,
)
from acip.db.session import Database
from acip.tools.registry import build_default_registry as build_tool_registry
from acip.types import ArtifactKind, HypothesisStatus, InvestigationStatus, TargetType

AUTH_LOG_SAMPLE = "\n".join(
    [
        "Mar 10 03:11:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.55 port 44120 ssh2",
        "Mar 10 03:11:05 web01 sshd[1235]: Failed password for invalid user root from 203.0.113.55 port 44122 ssh2",
        "Mar 10 03:11:09 web01 sshd[1236]: Failed password for invalid user test from 203.0.113.55 port 44124 ssh2",
        "Mar 10 03:11:12 web01 sshd[1237]: Failed password for deploy from 203.0.113.55 port 44126 ssh2",
        "Mar 10 03:11:15 web01 sshd[1238]: Failed password for deploy from 203.0.113.55 port 44128 ssh2",
        "Mar 10 03:11:20 web01 sshd[1239]: Accepted password for deploy from 203.0.113.55 port 44130 ssh2",
        "Mar 10 03:11:25 web01 sudo[1245]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "",
    ]
)


@pytest.mark.asyncio
async def test_reasoning_and_hypothesis_full_pipeline(database: Database, tmp_path: Path) -> None:
    settings = Settings(
        environment="dev",
        database_url=database.url,
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("test-secret-at-least-32-bytes-long-hs256"),
        enable_llm_triage=True,
        enable_adaptive_planning=True,
    )

    agents = build_default_registry()
    tools = build_tool_registry()
    router = build_default_router(settings)
    planner = AdaptivePlanner(agents)

    orchestrator = OrchestratorAgent(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
        planner=planner,
        router=router,
    )

    # 1. Create Investigation and Upload Artifact
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir(parents=True, exist_ok=True)
    art_file = art_dir / "auth.log"
    art_file.write_text(AUTH_LOG_SAMPLE, encoding="utf-8")

    async with database.session() as session:
        user = await session.scalar(sa.select(User))
        assert user is not None

        inv = Investigation(
            title="Phase 7 Reasoning Pipeline E2E",
            target_type=TargetType.LOG.value,
            target_value="auth.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv.id,
            kind=ArtifactKind.LINUX_AUTH_LOG.value,
            original_filename="auth.log",
            sha256="test_sha256_e2e_pipeline",
            size_bytes=len(AUTH_LOG_SAMPLE.encode("utf-8")),
            storage_path=str(art_file),
        )
        session.add(art)
        await session.flush()
        inv_id = inv.id

    # 2. Run Orchestrator with Adaptive Planner
    outcome = await orchestrator.execute(inv_id)

    assert outcome.status == InvestigationStatus.COMPLETED
    executed_agents = [o.task.agent_name for o in outcome.outcomes]

    # Verify all Phase 7 reasoning agents executed in planned sequence
    assert "triage" in executed_agents
    assert "log_analysis" in executed_agents
    assert "mitre" in executed_agents
    assert "correlation" in executed_agents
    assert "reasoning" in executed_agents
    assert "hypothesis" in executed_agents
    assert "validation" in executed_agents
    assert "reporting" in executed_agents
    assert executed_agents[-1] == "reporting"

    # 3. Verify Database Records
    async with database.session() as session:
        # Verify Hypotheses (Invariant G3)
        hypotheses = list(
            (
                await session.scalars(
                    sa.select(Hypothesis).where(Hypothesis.investigation_id == inv_id)
                )
            ).all()
        )
        assert len(hypotheses) >= 2
        for h in hypotheses:
            assert h.refutation_condition is not None
            assert len(h.refutation_condition.strip()) > 0
            assert h.status in {
                HypothesisStatus.SUPPORTED.value,
                HypothesisStatus.REFUTED.value,
                HypothesisStatus.PROPOSED.value,
            }

        # Verify Hypothesis Gaps
        gaps = list(
            (
                await session.scalars(
                    sa.select(HypothesisGap).where(
                        HypothesisGap.hypothesis_id.in_([h.id for h in hypotheses])
                    )
                )
            ).all()
        )
        assert len(gaps) >= 1

        # Verify Report was generated
        report = await session.scalar(sa.select(Report).where(Report.investigation_id == inv_id))
        assert report is not None
        assert report.content != ""
