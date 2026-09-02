"""Integration tests for the Orchestrator Agent."""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.orchestrator import OrchestratorAgent
from acip.agents.registry import build_default_registry
from acip.agents.triage_schemas import (
    ExtractedEntity,
    IndicatorAssessment,
    InputClassification,
    PlannedTaskProposal,
    TriageAnalysis,
)
from acip.config import Settings
from acip.core.llm.contracts import TaskClass
from acip.core.llm.policy import CandidateModel, RoutingPolicy, TaskRoutingRule
from acip.core.llm.providers.replay import ReplayProvider
from acip.core.llm.router import ModelRouter
from acip.core.orchestration.planner import StaticPlanner
from acip.db.models import AgentRun, Artifact, AuditLog, Finding, Investigation, Report, TaskRun
from acip.db.session import Database
from acip.tools.registry import build_default_registry as build_default_tool_registry
from acip.types import (
    ArtifactKind,
    InvestigationStatus,
    RunStatus,
    Severity,
    TargetType,
    TaskStatus,
)

AUTH_LOG_SAMPLE = "\n".join(
    [
        "Mar 10 03:10:55 web01 sshd[1230]: Invalid user scanner1 from 203.0.113.55 port 44110 ssh2",
        "Mar 10 03:10:58 web01 sshd[1231]: Invalid user scanner2 from 203.0.113.55 port 44112 ssh2",
        "Mar 10 03:11:18 web01 sshd[1238]: Accepted password for deploy from 203.0.113.55 port 44126 ssh2",
        "Mar 10 03:11:22 web01 sudo[1240]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "",
    ]
)


@pytest.mark.asyncio
async def test_orchestrator_agent_end_to_end_lifecycle(database: Database, tmp_path: Path) -> None:
    """OrchestratorAgent receives an investigation, calls Triage, interprets result, creates tasks, and maintains state."""
    settings = Settings(artifact_dir=tmp_path / "artifacts", secret_key=SecretStr("secret"))
    agents = build_default_registry()
    tools = build_default_tool_registry()

    orchestrator = OrchestratorAgent(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
    )

    # 1. Setup investigation and artifact
    art_file = tmp_path / "artifacts" / "auth.log"
    art_file.parent.mkdir(parents=True, exist_ok=True)
    art_file.write_text(AUTH_LOG_SAMPLE, encoding="utf-8")

    async with database.session() as session:
        inv = Investigation(
            title="Web01 SSH Breach",
            target_type=TargetType.LOG.value,
            target_value="auth.log",
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv.id,
            kind=ArtifactKind.LINUX_AUTH_LOG.value,
            original_filename="auth.log",
            sha256="dummy_sha256_hash",
            size_bytes=len(AUTH_LOG_SAMPLE.encode("utf-8")),
            storage_path=str(art_file),
        )
        session.add(art)
        await session.flush()
        inv_id = inv.id

    # 2. Execute Orchestrator Agent
    outcome = await orchestrator.execute(inv_id)

    # 3. Assert outcome and state
    assert outcome.status == InvestigationStatus.COMPLETED
    assert len(outcome.outcomes) >= 3  # Triage, Log Analysis, Reporting

    state = orchestrator.get_state(inv_id)
    assert state is not None
    assert state.status == InvestigationStatus.COMPLETED
    assert state.completed_tasks_count >= 3
    assert state.failed_tasks_count == 0
    assert state.triage_analysis is not None
    assert state.started_at is not None
    assert state.completed_at is not None

    # 4. Verify TaskRun rows in database
    async with database.session() as session:
        task_rows = list(
            (
                await session.scalars(
                    sa.select(TaskRun)
                    .where(TaskRun.investigation_id == inv_id)
                    .order_by(TaskRun.started_at)
                )
            ).all()
        )
        assert len(task_rows) >= 3
        task_types = [t.task_type for t in task_rows]
        assert "triage" in task_types
        assert "log_analysis" in task_types
        assert "reporting" in task_types

        for t in task_rows:
            assert t.status == TaskStatus.SUCCEEDED.value
            assert t.duration_ms is not None
            assert t.duration_ms >= 0
            assert t.finished_at is not None

        # Verify AgentRun rows
        agent_runs = list(
            (
                await session.scalars(
                    sa.select(AgentRun)
                    .where(AgentRun.investigation_id == inv_id)
                    .order_by(AgentRun.started_at)
                )
            ).all()
        )
        assert len(agent_runs) >= 3
        for r in agent_runs:
            assert r.status == RunStatus.SUCCEEDED.value
            assert r.outputs is not None

        # Verify Findings
        findings = list(
            (
                await session.scalars(sa.select(Finding).where(Finding.investigation_id == inv_id))
            ).all()
        )
        assert len(findings) >= 3

        # Verify Report generated
        report = await session.scalar(sa.select(Report).where(Report.investigation_id == inv_id))
        assert report is not None
        assert "203.0.113.55" in report.content

        # Verify Audit trail
        audit_records = list(
            (
                await session.scalars(
                    sa.select(AuditLog).where(AuditLog.resource_id == str(inv_id))
                )
            ).all()
        )
        actions = [a.action for a in audit_records]
        assert "investigation.started" in actions
        assert "investigation.finished" in actions
        assert "orchestrator.tasks_created" in actions


@pytest.mark.asyncio
async def test_orchestrator_agent_with_model_router_triage(
    database: Database, tmp_path: Path
) -> None:
    """OrchestratorAgent works with model-routed Triage analysis to dynamically create tasks."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=True,
        enable_adaptive_planning=True,
    )
    agents = build_default_registry()
    tools = build_default_tool_registry()

    model_analysis = TriageAnalysis(
        classification=InputClassification(
            category="authentication_attack",
            summary="Targeted brute-force attempt against deploy user account.",
            confidence=0.96,
            initial_severity=Severity.HIGH,
            reasoning="Observed high-frequency invalid logins from external IP 203.0.113.55.",
        ),
        entities=[
            ExtractedEntity(entity_type="ip", value="203.0.113.55", role="attacker"),
            ExtractedEntity(entity_type="user", value="deploy", role="target"),
        ],
        indicators=[
            IndicatorAssessment(
                indicator_type="ip",
                value="203.0.113.55",
                scope="global",
                threat_assessment="suspicious_inbound",
                is_malicious_candidate=True,
            )
        ],
        evidence_gaps=[],
        investigation_plan=[
            PlannedTaskProposal(
                task_type="log_analysis",
                rationale="Evaluate brute-force authentication rules",
                priority=1,
            ),
            PlannedTaskProposal(
                task_type="reporting",
                rationale="Synthesize final investigation findings and risk score",
                priority=2,
            ),
        ],
    )

    replay = ReplayProvider(
        name="test_replay",
        default_response=model_analysis.model_dump_json(),
        canned_responses={"triage": model_analysis.model_dump_json()},
    )
    rule = TaskRoutingRule(
        task_class=TaskClass.CLASSIFICATION,
        candidates=[CandidateModel(provider="test_replay", model="model-triage-v1")],
        schema_retries=1,
    )
    policy = RoutingPolicy({TaskClass.CLASSIFICATION: rule})
    router = ModelRouter(providers={"test_replay": replay}, policy=policy)

    orchestrator = OrchestratorAgent(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
        router=router,
    )

    art_file = tmp_path / "artifacts" / "auth.log"
    art_file.parent.mkdir(parents=True, exist_ok=True)
    art_file.write_text(AUTH_LOG_SAMPLE, encoding="utf-8")

    async with database.session() as session:
        inv = Investigation(
            title="Model-Driven Triage Investigation",
            target_type=TargetType.LOG.value,
            target_value="auth.log",
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv.id,
            kind=ArtifactKind.LINUX_AUTH_LOG.value,
            original_filename="auth.log",
            sha256="hash_model_test",
            size_bytes=len(AUTH_LOG_SAMPLE.encode("utf-8")),
            storage_path=str(art_file),
        )
        session.add(art)
        await session.flush()
        inv_id = inv.id

    outcome = await orchestrator.execute(inv_id)

    assert outcome.status == InvestigationStatus.COMPLETED
    assert len(outcome.outcomes) >= 3

    state = orchestrator.get_state(inv_id)
    assert state is not None
    assert state.triage_analysis is not None
    assert state.triage_analysis.classification.category == "authentication_attack"
    assert state.triage_analysis.classification.confidence == 0.96


@pytest.mark.asyncio
async def test_orchestrator_agent_respects_static_planner_verbatim(
    database: Database, tmp_path: Path
) -> None:
    """When StaticPlanner is configured, OrchestratorAgent executes its plan verbatim."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=False,
        enable_adaptive_planning=False,
    )
    agents = build_default_registry()
    tools = build_default_tool_registry()
    planner = StaticPlanner(agents)

    orchestrator = OrchestratorAgent(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
        planner=planner,
    )

    art_file = tmp_path / "artifacts" / "auth.log"
    art_file.parent.mkdir(parents=True, exist_ok=True)
    art_file.write_text(AUTH_LOG_SAMPLE, encoding="utf-8")

    async with database.session() as session:
        inv = Investigation(
            title="Static Plan Verbatim Execution",
            target_type=TargetType.LOG.value,
            target_value="auth.log",
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv.id,
            kind=ArtifactKind.LINUX_AUTH_LOG.value,
            original_filename="auth.log",
            sha256="static_hash_test",
            size_bytes=len(AUTH_LOG_SAMPLE.encode("utf-8")),
            storage_path=str(art_file),
        )
        session.add(art)
        await session.flush()
        inv_id = inv.id

    outcome = await orchestrator.execute(inv_id)

    assert outcome.status == InvestigationStatus.COMPLETED
    # StaticPlanner plans triage, log_analysis, reporting
    executed_agents = [o.task.agent_name for o in outcome.outcomes]
    assert executed_agents == ["triage", "log_analysis", "reporting"]

    state = orchestrator.get_state(inv_id)
    assert state is not None
    assert [t.agent_name for t in state.tasks_planned] == ["triage", "log_analysis", "reporting"]
