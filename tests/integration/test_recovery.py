from __future__ import annotations

import datetime as dt

from acip.agents.registry import build_default_registry
from acip.config import Settings
from acip.core.orchestration.orchestrator import Orchestrator
from acip.core.orchestration.planner import StaticPlanner
from acip.core.orchestration.runner import InvestigationRunner
from acip.db.models import Investigation
from acip.db.session import Database
from acip.tools.registry import build_default_registry as build_default_tool_registry
from acip.types import InvestigationStatus


async def test_recovery_interrupted_investigation(database: Database, settings: Settings) -> None:
    agents = build_default_registry()
    tools = build_default_tool_registry()
    planner = StaticPlanner(agents)
    orchestrator = Orchestrator(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
        planner=planner,
    )
    runner = InvestigationRunner(orchestrator=orchestrator, database=database)

    # Insert an orphaned running investigation
    async with database.session() as session:
        inv = Investigation(
            title="Orphaned Running Inv",
            target_type="log",
            target_value="auth.log",
            status=InvestigationStatus.RUNNING.value,
            started_at=dt.datetime.now(dt.UTC),
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id

    # Run startup recovery sweep
    recovered_count = await runner.recover_interrupted()
    assert recovered_count == 1

    # Verify status changed to FAILED with recovery error explanation
    async with database.session() as session:
        inv_recovered = await session.get(Investigation, inv_id)
        assert inv_recovered is not None
        assert inv_recovered.status == InvestigationStatus.FAILED.value
        assert "interrupted" in (inv_recovered.error or "").lower()
