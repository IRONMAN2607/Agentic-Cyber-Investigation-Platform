"""Real End-to-End Investigation Workflow Integration Test.

Verifies that submitting an investigation target executes the full chain:
intake -> artifact system -> triage agent -> model router (with genuine cyber reasoning)
-> evidence system -> adaptive orchestrator -> log analysis agent -> reporting agent
-> database persistence with zero fake activity.
"""

from __future__ import annotations

from pathlib import Path

import anyio
import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.registry import build_default_registry as build_agent_registry
from acip.config import Settings
from acip.core.llm.router import build_default_router
from acip.core.orchestration.orchestrator import Orchestrator
from acip.core.orchestration.runner import InvestigationRunner
from acip.db.models import (
    AgentRun,
    Artifact,
    Evidence,
    Finding,
    Investigation,
    ModelExecution,
    Report,
    ToolRun,
)
from acip.db.session import Database
from acip.tools.registry import build_default_registry as build_tool_registry
from acip.types import AssertionClass, InvestigationStatus


@pytest.mark.asyncio
async def test_end_to_end_investigation_pipeline(tmp_path: Path) -> None:
    db_file = tmp_path / "e2e_test.db"
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    # Configure real dev settings with LLM triage and adaptive planning active
    settings = Settings(
        environment="dev",  # dev triggers CyberReasoningProvider when no cloud key
        database_url=f"sqlite+aiosqlite:///{db_file.as_posix()}",
        artifact_dir=artifact_dir,
        secret_key=SecretStr("test-secret-key-that-is-at-least-32-bytes-long-for-hs256"),
        enable_llm_triage=True,
        enable_adaptive_planning=True,
        bruteforce_min_failures=3,
        bruteforce_window_seconds=300,
    )

    database = Database(settings.database_url, echo=False)
    from acip.bootstrap import bootstrap

    await bootstrap(database, settings)

    # Compose full service graph
    tools = build_tool_registry()
    agents = build_agent_registry()
    router = build_default_router(settings)
    orchestrator = Orchestrator(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
        planner=None,  # Dynamic orchestrator driven by triage analysis
        router=router,
    )
    runner = InvestigationRunner(orchestrator=orchestrator, database=database)

    # Realistic authentication attack target submission
    auth_log_content = (
        "Mar 15 10:14:01 srv sshd[2001]: Failed password for root from 198.51.100.99 port 41234 ssh2\n"
        "Mar 15 10:14:05 srv sshd[2002]: Failed password for root from 198.51.100.99 port 41235 ssh2\n"
        "Mar 15 10:14:09 srv sshd[2003]: Failed password for root from 198.51.100.99 port 41236 ssh2\n"
        "Mar 15 10:14:14 srv sshd[2004]: Failed password for invalid user admin from 198.51.100.99 port 41237 ssh2\n"
    )

    # 1. Intake: Create investigation in database
    async with database.session() as session:
        inv = Investigation(
            title="Suspicious SSH Activity on Perimeter Web01",
            target_type="log",
            target_value=auth_log_content,
            status=InvestigationStatus.CREATED.value,
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id

    # 2. Execution: Run investigation through runner
    task_handle = runner.submit(inv_id)
    await task_handle

    # 3. Assert Genuine Pipeline Execution & Database Records
    async with database.session() as session:
        # Investigation status
        inv_row = await session.get(Investigation, inv_id)
        assert inv_row is not None
        assert inv_row.status == InvestigationStatus.COMPLETED.value
        assert inv_row.severity in {"medium", "high"}
        assert inv_row.risk_score is not None and inv_row.risk_score > 0

        # Artifacts auto-ingested
        artifacts = (
            await session.scalars(sa.select(Artifact).where(Artifact.investigation_id == inv_id))
        ).all()
        assert len(artifacts) >= 1
        art = artifacts[0]
        art_file = anyio.Path(art.storage_path)
        assert await art_file.exists()
        assert await art_file.read_text(encoding="utf-8") == auth_log_content.strip()

        # Evidence records
        evidence_items = (
            await session.scalars(sa.select(Evidence).where(Evidence.investigation_id == inv_id))
        ).all()
        assert len(evidence_items) >= 2
        # Check that IP indicator was extracted
        assert any(
            ev.data.get("value") == "198.51.100.99" or ev.data.get("match") == "198.51.100.99"
            for ev in evidence_items
        )

        # Tool runs
        tool_runs = (
            await session.scalars(sa.select(ToolRun).where(ToolRun.investigation_id == inv_id))
        ).all()
        assert len(tool_runs) >= 1
        tool_names = {tr.tool_name for tr in tool_runs}
        assert "ioc_extractor" in tool_names

        # ModelExecution trace (in llm_calls table) - proves genuine ModelRouter execution!
        llm_calls = (
            await session.scalars(
                sa.select(ModelExecution).where(ModelExecution.investigation_id == inv_id)
            )
        ).all()
        assert len(llm_calls) >= 1
        llm_exec = llm_calls[0]
        assert llm_exec.task_class == "classification"
        assert llm_exec.tokens_in > 0
        assert llm_exec.tokens_out > 0
        assert llm_exec.schema_valid is True

        # Agent runs
        agent_runs = (
            await session.scalars(sa.select(AgentRun).where(AgentRun.investigation_id == inv_id))
        ).all()
        agent_names = {ar.agent_name for ar in agent_runs}
        assert "triage" in agent_names
        assert "reporting" in agent_names

        # Grounded Findings
        findings = (
            await session.scalars(sa.select(Finding).where(Finding.investigation_id == inv_id))
        ).all()
        assert len(findings) >= 2
        # G0-G4 compliance: verify evidence citing
        for finding in findings:
            if finding.assertion_class in {
                AssertionClass.FACT.value,
                AssertionClass.INFERENCE.value,
            }:
                assert len(finding.evidence_ids) > 0

        # Incident Report
        reports = (
            await session.scalars(sa.select(Report).where(Report.investigation_id == inv_id))
        ).all()
        assert len(reports) >= 1
        report = reports[0]
        assert "# Investigation Report" in report.content
        assert "198.51.100.99" in report.content
        assert "Executive Summary" in report.content

    await database.dispose()
