from __future__ import annotations

from acip.agents.registry import build_default_registry
from acip.core.orchestration.planner import StaticPlanner
from acip.db.models import Artifact, Investigation
from acip.types import ArtifactKind, TargetType


def test_static_planner_with_auth_log() -> None:
    agents = build_default_registry()
    planner = StaticPlanner(agents)

    inv = Investigation(
        title="Test Investigation",
        target_type=TargetType.LOG.value,
        target_value="auth.log",
    )
    art = Artifact(
        investigation_id=inv.id,
        kind=ArtifactKind.LINUX_AUTH_LOG.value,
        original_filename="auth.log",
        sha256="abc123sha256",
        size_bytes=1024,
        storage_path="/tmp/auth.log",
    )

    plan = planner.plan(inv, [art])
    assert len(plan) == 3
    task_agents = [t.agent_name for t in plan.tasks]
    assert task_agents == ["triage", "log_analysis", "reporting"]
    for t in plan.tasks:
        assert t.rationale.strip() != ""


def test_static_planner_without_artifacts() -> None:
    agents = build_default_registry()
    planner = StaticPlanner(agents)

    inv = Investigation(
        title="Description Investigation",
        target_type=TargetType.DESCRIPTION.value,
        target_value="Suspicious activity reported on web01",
    )
    plan = planner.plan(inv, [])
    task_agents = [t.agent_name for t in plan.tasks]
    assert "triage" in task_agents
    assert "reporting" in task_agents
    assert "log_analysis" not in task_agents
