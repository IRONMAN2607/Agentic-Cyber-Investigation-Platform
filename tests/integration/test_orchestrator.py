from __future__ import annotations

from typing import Any, ClassVar

import sqlalchemy as sa

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.agents.registry import AgentRegistry
from acip.config import Settings
from acip.core.evidence.contracts import FindingDraft
from acip.core.orchestration.orchestrator import Orchestrator
from acip.core.orchestration.planner import Plan, Planner, Task
from acip.db.models import Finding, Investigation
from acip.db.session import Database
from acip.tools.registry import ToolRegistry
from acip.types import AgentCapability, AssertionClass, InvestigationStatus, RunStatus, Severity


class MockFailingAgent(Agent):
    name: ClassVar[str] = "failing_agent"
    version: ClassVar[str] = "1.0.0"
    capability: ClassVar[AgentCapability] = AgentCapability.TRIAGE
    description: ClassVar[str] = "Agent designed to throw"

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        # Create uncommitted finding draft, then raise
        f = FindingDraft(
            title="Uncommitted finding",
            description="Should be rolled back",
            assertion_class=AssertionClass.HYPOTHESIS,
            severity=Severity.INFO,
            reasoning="Valid hypothesis reasoning to pass grounding before crash",
        )
        await ctx.store.add_finding(f)
        raise RuntimeError("simulated agent crash")


class MockPlanner(Planner):
    def __init__(self) -> None:
        self.name = "mock_planner"

    def plan(self, investigation: Investigation, artifacts: list[Any]) -> Plan:
        return Plan(
            tasks=(
                Task(
                    task_id="task_fail",
                    agent_name="failing_agent",
                    rationale="Test failure rollback",
                ),
            ),
            strategy="test",
        )


async def test_orchestrator_failure_rollback(database: Database, settings: Settings) -> None:
    agents = AgentRegistry()
    agents.register(MockFailingAgent())
    tools = ToolRegistry()
    planner = MockPlanner()

    orchestrator = Orchestrator(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
        planner=planner,
    )

    async with database.session() as session:
        inv = Investigation(title="Fail Test", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()
        inv_id = inv.id

    outcome = await orchestrator.execute(inv_id)
    assert outcome.status == InvestigationStatus.FAILED
    assert len(outcome.outcomes) == 1
    assert outcome.outcomes[0].status == RunStatus.FAILED

    # Verify no partial finding was committed
    async with database.session() as session:
        inv_reloaded = await session.get(Investigation, inv_id)
        assert inv_reloaded is not None
        assert inv_reloaded.status == InvestigationStatus.FAILED.value
        assert "simulated agent crash" in (inv_reloaded.error or "")

        rows = await session.scalars(sa.select(Finding).where(Finding.investigation_id == inv_id))
        assert len(list(rows.all())) == 0
