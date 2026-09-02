"""Unit tests for the Orchestrator Agent."""

from __future__ import annotations

import uuid
from pathlib import Path

from acip.agents.base import AgentResult
from acip.agents.orchestrator import InvestigationState, OrchestratorAgent, TaskOutcome
from acip.agents.registry import build_default_registry
from acip.agents.triage_schemas import (
    EvidenceGap,
    ExtractedEntity,
    IndicatorAssessment,
    InputClassification,
    PlannedTaskProposal,
    TriageAnalysis,
)
from acip.config import Settings
from acip.core.orchestration.planner import Task
from acip.db.models import Artifact
from acip.db.session import Database
from acip.tools.registry import build_default_registry as build_default_tool_registry
from acip.types import (
    AgentCapability,
    ArtifactKind,
    InvestigationStatus,
    RunStatus,
    Severity,
)


def test_orchestrator_agent_metadata() -> None:
    """OrchestratorAgent exposes correct agent metadata."""
    assert OrchestratorAgent.name == "orchestrator"
    assert OrchestratorAgent.version == "1.0.0"
    assert OrchestratorAgent.capability == AgentCapability.ORCHESTRATION
    assert OrchestratorAgent.description != ""


def test_investigation_state_metrics() -> None:
    """InvestigationState computes task progress metrics correctly."""
    inv_id = uuid.uuid4()
    state = InvestigationState(investigation_id=inv_id, status=InvestigationStatus.RUNNING)

    assert state.total_tasks == 0
    assert state.completed_tasks_count == 0
    assert state.failed_tasks_count == 0

    t1 = Task(task_id="t1", agent_name="triage", rationale="Triage")
    t2 = Task(task_id="t2", agent_name="log_analysis", rationale="Analysis")
    state.tasks_planned = [t1, t2]

    state.task_outcomes.append(
        TaskOutcome(
            task=t1,
            status=RunStatus.SUCCEEDED,
            agent_run_id=uuid.uuid4(),
            summary="Triage complete",
        )
    )
    assert state.total_tasks == 2
    assert state.completed_tasks_count == 1
    assert state.failed_tasks_count == 0

    state.task_outcomes.append(
        TaskOutcome(
            task=t2,
            status=RunStatus.FAILED,
            agent_run_id=uuid.uuid4(),
            summary="Log analysis crashed",
            error="RuntimeError",
        )
    )
    assert state.completed_tasks_count == 1
    assert state.failed_tasks_count == 1


def test_interpret_triage_result_structured_analysis(tmp_path: Path) -> None:
    """OrchestratorAgent interprets structured TriageAnalysis and maps to registered agents."""
    agents = build_default_registry()
    tools = build_default_tool_registry()
    settings = Settings(artifact_dir=tmp_path / "artifacts")
    database = Database("sqlite+aiosqlite:///:memory:")

    orchestrator = OrchestratorAgent(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
    )

    triage_analysis = TriageAnalysis(
        classification=InputClassification(
            category="authentication_attack",
            summary="SSH brute force observed against deploy account.",
            confidence=0.92,
            initial_severity=Severity.HIGH,
            reasoning="Observed failed login burst from external IP.",
        ),
        entities=[
            ExtractedEntity(entity_type="ip", value="198.51.100.1", role="attacker"),
            ExtractedEntity(entity_type="user", value="deploy", role="target"),
        ],
        indicators=[
            IndicatorAssessment(
                indicator_type="ip",
                value="198.51.100.1",
                scope="global",
                is_malicious_candidate=True,
            )
        ],
        evidence_gaps=[
            EvidenceGap(
                description="Threat reputation of 198.51.100.1 is unverified",
                required_source="threat_intelligence_enrichment",
                importance="high",
            )
        ],
        investigation_plan=[
            PlannedTaskProposal(
                task_type="log_analysis",
                rationale="Parse authentication logs for credential abuse rules",
                priority=1,
            ),
            PlannedTaskProposal(
                task_type="threat_intelligence",
                rationale="Query reputation of 198.51.100.1",
                priority=2,
            ),
            PlannedTaskProposal(
                task_type="reporting",
                rationale="Synthesize final investigation findings",
                priority=3,
            ),
        ],
    )

    agent_result = AgentResult(
        status=RunStatus.SUCCEEDED,
        summary="Triage succeeded",
        metrics={"triage_analysis": triage_analysis.model_dump(mode="json")},
    )

    art = Artifact(
        investigation_id=uuid.uuid4(),
        kind=ArtifactKind.LINUX_AUTH_LOG.value,
        original_filename="auth.log",
        sha256="hash123",
        size_bytes=100,
        storage_path="/tmp/auth.log",
    )

    tasks, notes, analysis = orchestrator.interpret_triage_result(agent_result, [art])

    assert analysis is not None
    assert analysis.classification.category == "authentication_attack"
    assert (
        len(tasks) == 2
    )  # log_analysis and reporting (threat_intelligence not in default registry)
    assert tasks[0].agent_name == "log_analysis"
    assert tasks[1].agent_name == "reporting"

    # Note recorded for unavailable threat_intelligence agent
    assert any("threat_intelligence" in note and "not registered" in note for note in notes)


def test_interpret_triage_result_fallback_when_unsuccessful(tmp_path: Path) -> None:
    """OrchestratorAgent falls back to deterministic rules if triage fails or is missing structured data."""
    agents = build_default_registry()
    tools = build_default_tool_registry()
    settings = Settings(artifact_dir=tmp_path / "artifacts")
    database = Database("sqlite+aiosqlite:///:memory:")

    orchestrator = OrchestratorAgent(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
    )

    art = Artifact(
        investigation_id=uuid.uuid4(),
        kind=ArtifactKind.LINUX_AUTH_LOG.value,
        original_filename="auth.log",
        sha256="hash123",
        size_bytes=100,
        storage_path="/tmp/auth.log",
    )

    # When triage result is failed
    failed_result = AgentResult(status=RunStatus.FAILED, summary="Triage crashed", errors=["crash"])
    tasks, notes, analysis = orchestrator.interpret_triage_result(failed_result, [art])

    assert analysis is None
    assert len(tasks) == 2  # Fallback: log_analysis + reporting
    assert tasks[0].agent_name == "log_analysis"
    assert tasks[1].agent_name == "reporting"
    assert any("fallback" in note.lower() for note in notes)
