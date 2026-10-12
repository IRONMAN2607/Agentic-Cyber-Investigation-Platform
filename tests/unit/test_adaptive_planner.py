from __future__ import annotations

from acip.agents.registry import build_default_registry
from acip.core.orchestration.adaptive_planner import AdaptivePlanner
from acip.core.orchestration.planner import Planner
from acip.db.models import Artifact, Investigation
from acip.types import ArtifactKind, TargetType


def test_adaptive_planner_implements_protocol() -> None:
    agents = build_default_registry()
    planner = AdaptivePlanner(agents)
    assert isinstance(planner, Planner)
    assert planner.name == "adaptive"


def test_adaptive_planner_schedules_reasoning_and_hypotheses_on_logs() -> None:
    agents = build_default_registry()
    planner = AdaptivePlanner(agents)

    inv = Investigation(
        title="Adaptive Plan Log Test",
        target_type=TargetType.LOG.value,
        target_value="auth.log",
    )
    art = Artifact(
        investigation_id=inv.id,
        kind=ArtifactKind.LINUX_AUTH_LOG.value,
        original_filename="auth.log",
        sha256="abc123hash",
        size_bytes=2048,
        storage_path="/tmp/auth.log",
    )

    plan = planner.plan(inv, [art])
    task_agents = [t.agent_name for t in plan.tasks]

    # Full reasoning pipeline should be scheduled
    assert "triage" in task_agents
    assert "log_analysis" in task_agents
    assert "mitre" in task_agents
    assert "correlation" in task_agents
    assert "reasoning" in task_agents
    assert "hypothesis" in task_agents
    assert "validation" in task_agents
    assert "reporting" in task_agents

    # Reporting must be the last step
    assert task_agents[-1] == "reporting"

    for t in plan.tasks:
        assert t.rationale.strip() != ""


def test_adaptive_planner_enforces_task_cap() -> None:
    agents = build_default_registry()
    capped_planner = AdaptivePlanner(agents, max_tasks=3)

    inv = Investigation(
        title="Capped Plan Test",
        target_type=TargetType.LOG.value,
        target_value="auth.log",
    )
    art = Artifact(
        investigation_id=inv.id,
        kind=ArtifactKind.LINUX_AUTH_LOG.value,
        original_filename="auth.log",
        sha256="abc123hash",
        size_bytes=2048,
        storage_path="/tmp/auth.log",
    )

    plan = capped_planner.plan(inv, [art])
    assert len(plan.tasks) == 3
    assert any("truncated at max_tasks" in n.lower() for n in plan.notes)
