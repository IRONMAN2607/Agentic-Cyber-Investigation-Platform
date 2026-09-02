import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa

from acip.agents.base import AgentContext
from acip.agents.reporting import ReportAgent
from acip.config import Settings
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AgentRun, Artifact, Investigation, Report
from acip.db.session import Database
from acip.tools.registry import ToolRegistry
from acip.tools.runner import ToolRunner
from acip.types import RetentionState

pytestmark = pytest.mark.asyncio


async def test_report_discloses_retention_state_and_intact_bytes(
    database: Database, settings: Settings, tmp_path: Path
) -> None:
    inv_id = uuid.uuid4()
    art_file = tmp_path / "auth.log"
    art_file.write_text("test log line\n")

    async with database.session() as session:
        inv = Investigation(
            id=inv_id,
            title="Retention Intact Inv",
            target_type="log",
            target_value="auth.log",
            retention_state=RetentionState.REPRODUCIBLE.value,
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv_id,
            kind="linux_auth_log",
            original_filename="auth.log",
            sha256="1" * 64,
            size_bytes=len("test log line\n"),
            storage_path=str(art_file),
            retention_state=RetentionState.REPRODUCIBLE.value,
        )
        agent_run = AgentRun(
            investigation_id=inv_id,
            task_id="t1",
            agent_name="reporting",
            agent_version="1.0.0",
            status="running",
        )
        session.add_all([art, agent_run])
        await session.flush()

        store = EvidenceStore(session, inv_id)
        runner = ToolRunner(
            session=session,
            investigation_id=inv_id,
            registry=ToolRegistry(),
            store=store,
            artifact_root=tmp_path,
        )
        ctx = AgentContext(
            investigation=inv,
            artifacts=[art],
            store=store,
            session=session,
            tools=runner,
            settings=settings,
            agent_run_id=agent_run.id,
        )

        agent = ReportAgent()
        result = await agent.run(ctx, {})
        assert result.status.value == "succeeded"

        report = await session.scalar(sa.select(Report).where(Report.investigation_id == inv_id))
        assert report is not None
        report_text = report.content

        assert "Investigation retention policy: `reproducible`" in report_text
        assert "Source bytes are intact and verified in local storage" in report_text


async def test_report_discloses_missing_source_bytes(
    database: Database, settings: Settings, tmp_path: Path
) -> None:
    inv_id = uuid.uuid4()
    missing_file = tmp_path / "deleted_auth.log"  # Does not exist

    async with database.session() as session:
        inv = Investigation(
            id=inv_id,
            title="Retention Missing Bytes Inv",
            target_type="log",
            target_value="auth.log",
            retention_state=RetentionState.DERIVED_ONLY.value,
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv_id,
            kind="linux_auth_log",
            original_filename="auth.log",
            sha256="2" * 64,
            size_bytes=100,
            storage_path=str(missing_file),
            retention_state=RetentionState.DERIVED_ONLY.value,
        )
        agent_run = AgentRun(
            investigation_id=inv_id,
            task_id="t1",
            agent_name="reporting",
            agent_version="1.0.0",
            status="running",
        )
        session.add_all([art, agent_run])
        await session.flush()

        store = EvidenceStore(session, inv_id)
        runner = ToolRunner(
            session=session,
            investigation_id=inv_id,
            registry=ToolRegistry(),
            store=store,
            artifact_root=tmp_path,
        )
        ctx = AgentContext(
            investigation=inv,
            artifacts=[art],
            store=store,
            session=session,
            tools=runner,
            settings=settings,
            agent_run_id=agent_run.id,
        )

        agent = ReportAgent()
        result = await agent.run(ctx, {})
        assert result.status.value == "succeeded"

        report = await session.scalar(sa.select(Report).where(Report.investigation_id == inv_id))
        assert report is not None
        report_text = report.content

        assert "Investigation retention policy: `derived_only`" in report_text
        assert "are missing from storage (retention: `derived_only`)" in report_text
        assert (
            "Conclusions rely on derived evidence records rather than verifiable raw source bytes"
            in report_text
        )
