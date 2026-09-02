"""The migration chain is the schema, so the suite runs on it.

Every fixture reaches its schema through ``bootstrap`` → ``upgrade_to_head``, so
all 97 tests already exercise the migrations. These tests close the loop by
asserting the two things that silent drift would break:

* the database ends up stamped at the chain's head, and
* the head schema still matches ``Base.metadata``.

The second one is the point. A model gains a column, nobody writes a revision,
and the application keeps working right up until it runs somewhere the schema
was built by Alembic. Making that a test failure is cheaper than making it a
deployment failure.
"""

import datetime as dt
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from acip.config import Settings
from acip.db.migrate import alembic_config, upgrade_to_head
from acip.db.models import (
    AgentRun,
    Artifact,
    AuditLog,
    Base,
    Evidence,
    Finding,
    FindingEvidence,
    Hypothesis,
    HypothesisEvidence,
    HypothesisGap,
    Investigation,
    ModelExecution,
    Report,
    TaskRun,
    ToolRun,
    User,
)
from acip.db.session import Database
from acip.errors import ConfigurationError

pytestmark = pytest.mark.asyncio


def _current_revision(connection: Connection) -> str | None:
    return MigrationContext.configure(connection).get_current_revision()


def _schema_diff(connection: Connection) -> list[object]:
    context = MigrationContext.configure(connection)
    return list(compare_metadata(context, Base.metadata))


async def test_bootstrap_stamps_the_database_at_head(database: Database) -> None:
    """The fixture's schema came from Alembic, not from ``create_all``."""
    head = ScriptDirectory.from_config(alembic_config(database.url)).get_current_head()
    assert head is not None

    async with database.engine.connect() as conn:
        stamped = await conn.run_sync(_current_revision)

    assert stamped == head


async def test_models_and_migrations_do_not_drift(database: Database) -> None:
    """``Base.metadata`` describes exactly what the migrations build."""
    async with database.engine.connect() as conn:
        diff = await conn.run_sync(_schema_diff)

    assert diff == [], f"models and migrations disagree; a revision is missing: {diff}"


async def test_in_memory_is_refused_rather_than_silently_unmigrated(
    settings: Settings,
) -> None:
    """A second engine on ``:memory:`` would migrate a different database."""
    with pytest.raises(ConfigurationError, match="in-memory SQLite cannot be migrated"):
        await upgrade_to_head("sqlite+aiosqlite:///:memory:")


async def test_historical_migration_0002_to_0003_populated_upgrade(
    tmp_path: Path,
) -> None:
    """A populated 0002 database upgrades to 0003 preserving data and enforcing RESTRICT FKs."""
    db_file = tmp_path / "hist_0002_0003.db"
    url = f"sqlite+aiosqlite:///{db_file.as_posix()}"

    # 1. Migrate schema to 0002
    await upgrade_to_head(url, revision="0002_core_domain_models")

    # 2. Populate 0002 database with rich domain data
    db = Database(url)
    user_id = None
    inv_id = None
    art_id = None
    agent_run_id = None
    tool_run_id = None
    ev_id = None
    finding_id = None
    hyp_id = None

    async with db.session() as session:
        user = User(
            username="investigator1",
            email="inv1@example.com",
            password_hash="argon2id$test$dummyhash",
            role="investigator",
        )
        session.add(user)
        await session.flush()
        user_id = user.id

        inv = Investigation(
            title="Historical Investigation",
            target_type="log",
            target_value="auth.log",
            created_by=user_id,
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id

        art = Artifact(
            investigation_id=inv_id,
            kind="linux_auth_log",
            original_filename="auth.log",
            sha256="a" * 64,
            size_bytes=2048,
            storage_path="artifacts/aa/" + "a" * 64,
        )
        agent_run = AgentRun(
            investigation_id=inv_id,
            task_id="task-01",
            agent_name="log_analysis",
            agent_version="1.0.0",
            status="succeeded",
        )
        session.add_all([art, agent_run])
        await session.flush()
        art_id = art.id
        agent_run_id = agent_run.id

        tool_run = ToolRun(
            investigation_id=inv_id,
            agent_run_id=agent_run_id,
            task_id="task-01",
            tool_name="linux_auth_log_parser",
            tool_version="1.0.0",
            sandbox_tier="t0_in_process",
            status="succeeded",
        )
        session.add(tool_run)
        await session.flush()
        tool_run_id = tool_run.id

        ev = Evidence(
            investigation_id=inv_id,
            kind="auth_event",
            source_tool="linux_auth_log_parser",
            observed_at=dt.datetime(2026, 3, 10, 14, 30, tzinfo=dt.UTC),
            time_confidence="exact",
            data={"outcome": "failure", "user": "admin", "ip": "192.0.2.1"},
            entities={"refs": [{"type": "ip", "value": "192.0.2.1"}]},
            confidence=1.0,
            content_hash="b" * 64,
            artifact_id=art_id,
            tool_run_id=tool_run_id,
            agent_run_id=agent_run_id,
        )
        session.add(ev)
        await session.flush()
        ev_id = ev.id

        finding = Finding(
            investigation_id=inv_id,
            title="Failed root login from 192.0.2.1",
            description="Detected authentication failure",
            assertion_class="fact",
            severity="medium",
            confidence=1.0,
            evidence_ids=[str(ev_id)],
            detection_rule="auth.failed_login",
            agent_run_id=agent_run_id,
        )
        session.add(finding)
        await session.flush()
        finding_id = finding.id

        fe = FindingEvidence(
            finding_id=finding_id,
            evidence_id=ev_id,
            role="supports",
        )
        session.add(fe)

        hyp = Hypothesis(
            investigation_id=inv_id,
            statement="Credential stuffing attack from 192.0.2.1",
            confidence=0.7,
            refutation_condition="Inspect subsequent successful logins",
            agent_run_id=agent_run_id,
        )
        session.add(hyp)
        await session.flush()
        hyp_id = hyp.id

        he = HypothesisEvidence(
            hypothesis_id=hyp_id,
            evidence_id=ev_id,
            role="supports",
        )
        gap = HypothesisGap(
            hypothesis_id=hyp_id,
            description="Need firewall traffic logs",
            required_tool="netflow_parser",
        )
        llm = ModelExecution(
            investigation_id=inv_id,
            agent_run_id=agent_run_id,
            task_id="task-01",
            task_class="triage",
            provider="anthropic",
            model="claude-3-5-sonnet",
            prompt_name="triage_prompt",
            prompt_version="1.0.0",
            tokens_in=500,
            tokens_out=150,
            latency_ms=320,
            cost_estimate_usd=0.002,
        )
        task_run = TaskRun(
            investigation_id=inv_id,
            task_id="task-01",
            task_type="log_analysis",
            status="succeeded",
            inputs={"file": "auth.log"},
            outputs={"events": 1},
        )
        report = Report(
            investigation_id=inv_id,
            fmt="markdown",
            content="# Test Report",
            agent_run_id=agent_run_id,
        )
        audit_log = AuditLog(
            actor="investigator1",
            action="investigation.created",
            resource_type="investigation",
            resource_id=str(inv_id),
        )
        session.add_all([he, gap, llm, task_run, report, audit_log])

    await db.dispose()

    # 3. Upgrade from 0002 to 0003 (batch table rebuild on evidence and llm_calls)
    await upgrade_to_head(url, revision="0003_evidence_provenance_restrict")

    # 4. Connect to migrated database with foreign_keys=ON
    db_migrated = Database(url)
    try:
        async with db_migrated.engine.connect() as conn:
            stamped = await conn.run_sync(_current_revision)
        assert stamped == "0003_evidence_provenance_restrict"

        # Verify all populated records and fields survived table rebuild
        async with db_migrated.session() as session:
            ev_row = await session.get(Evidence, ev_id)
            assert ev_row is not None
            assert ev_row.content_hash == "b" * 64
            assert ev_row.data == {"outcome": "failure", "user": "admin", "ip": "192.0.2.1"}
            assert ev_row.artifact_id == art_id
            assert ev_row.tool_run_id == tool_run_id
            assert ev_row.agent_run_id == agent_run_id

            llm_row = await session.get(ModelExecution, llm.id)
            assert llm_row is not None
            assert llm_row.model == "claude-3-5-sonnet"
            assert llm_row.tokens_in == 500
            assert llm_row.investigation_id == inv_id
            assert llm_row.agent_run_id == agent_run_id

            finding_row = await session.get(Finding, finding_id)
            assert finding_row is not None
            assert finding_row.title == "Failed root login from 192.0.2.1"

            hyp_row = await session.get(Hypothesis, hyp_id)
            assert hyp_row is not None
            assert hyp_row.refutation_condition == "Inspect subsequent successful logins"

        # 5. Prove restrictive foreign keys survive and are enforced
        # a) Deleting a tool_run referenced by evidence raises IntegrityError (RESTRICT, not SET NULL)
        async with db_migrated.session() as session:
            tr = await session.get(ToolRun, tool_run_id)
            assert tr is not None
            with pytest.raises(IntegrityError):
                await session.delete(tr)
                await session.flush()
            await session.rollback()

        # b) Deleting an artifact referenced by evidence raises IntegrityError (RESTRICT, not SET NULL)
        async with db_migrated.session() as session:
            a = await session.get(Artifact, art_id)
            assert a is not None
            with pytest.raises(IntegrityError):
                await session.delete(a)
                await session.flush()
            await session.rollback()

        # c) Deleting an agent_run referenced by evidence & llm_calls raises IntegrityError (RESTRICT)
        async with db_migrated.session() as session:
            ar = await session.get(AgentRun, agent_run_id)
            assert ar is not None
            with pytest.raises(IntegrityError):
                await session.delete(ar)
                await session.flush()
            await session.rollback()

        # d) Deleting an investigation referenced by evidence & llm_calls raises IntegrityError (RESTRICT)
        async with db_migrated.session() as session:
            inv_obj = await session.get(Investigation, inv_id)
            assert inv_obj is not None
            with pytest.raises(IntegrityError):
                await session.delete(inv_obj)
                await session.flush()
            await session.rollback()

        # e) Verify evidence provenance links remain intact and grounded after rolled-back deletes
        async with db_migrated.session() as session:
            ev_check = await session.get(Evidence, ev_id)
            assert ev_check is not None
            assert ev_check.tool_run_id == tool_run_id
            assert ev_check.artifact_id == art_id
            assert ev_check.agent_run_id == agent_run_id
    finally:
        await db_migrated.dispose()
