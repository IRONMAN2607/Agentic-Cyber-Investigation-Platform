"""Investigation orchestration and Orchestrator Agent.

Executes a dynamic or planned investigation task by task, recording an ``agent_runs``
and ``task_runs`` row for every attempt, interpreting triage results, creating
follow-up investigation tasks, and maintaining complete investigation state.

Transaction shape
-----------------
Each task spans three short transactions:

1. Insert the ``AgentRun`` and update ``TaskRun`` as ``running`` and commit.
   The attempt is now durable, so a crash mid-task leaves visible evidence that it was tried.
2. Run the agent. Committed on success; rolled back on failure, which discards
   the partial evidence and tool rows written by the failing task. Partial output
   from a failed tool must not become citable evidence.
3. Update the ``AgentRun`` and ``TaskRun`` with their outcome and commit.

Failure policy
--------------
A failing task does not abort the investigation. Later tasks still run and the
report records what failed, because "step three crashed" is itself a finding a
reader needs. Terminal status is derived from the set of outcomes, so an
investigation is never reported as ``completed`` when part of it did not run.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.agents.registry import AgentRegistry
from acip.agents.triage_schemas import TriageAnalysis
from acip.config import Settings
from acip.core import audit
from acip.core.evidence.store import EvidenceStore
from acip.core.orchestration.planner import Plan, Planner, Task
from acip.db.models import AgentRun, Artifact, Investigation, TaskRun
from acip.db.session import Database
from acip.errors import NotFoundError
from acip.logging import get_logger, log_context
from acip.tools.registry import ToolRegistry
from acip.tools.runner import ToolRunner
from acip.types import (
    AgentCapability,
    ArtifactKind,
    InvestigationStatus,
    RunStatus,
    TaskStatus,
)

if TYPE_CHECKING:
    from acip.core.llm.router import ModelRouter

logger = get_logger(__name__)

_REPORT_GRACE_SECONDS = 30


@dataclass(frozen=True, slots=True)
class TaskOutcome:
    """Outcome of an individual task execution."""

    task: Task
    status: RunStatus
    agent_run_id: uuid.UUID
    summary: str
    result: AgentResult | None = None
    error: str | None = None


@dataclass
class InvestigationState:
    """In-memory and durable state representation of an active investigation."""

    investigation_id: uuid.UUID
    status: InvestigationStatus = InvestigationStatus.RUNNING
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None
    triage_analysis: TriageAnalysis | None = None
    tasks_planned: list[Task] = field(default_factory=list)
    task_outcomes: list[TaskOutcome] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    halted_reason: str | None = None
    error: str | None = None

    @property
    def total_tasks(self) -> int:
        return len(self.tasks_planned)

    @property
    def completed_tasks_count(self) -> int:
        return sum(1 for o in self.task_outcomes if o.status == RunStatus.SUCCEEDED)

    @property
    def failed_tasks_count(self) -> int:
        return sum(1 for o in self.task_outcomes if o.status == RunStatus.FAILED)


@dataclass(frozen=True, slots=True)
class InvestigationOutcome:
    """Final outcome of an orchestrated investigation."""

    investigation_id: uuid.UUID
    status: InvestigationStatus
    plan: Plan
    outcomes: tuple[TaskOutcome, ...]
    state: InvestigationState | None = None
    halted_reason: str | None = None


class OrchestratorAgent:
    """First functional Orchestrator Agent.

    Coordinates the investigation lifecycle:
    1. Receives an investigation and initializes durable tracking state.
    2. Calls the Triage Agent to inventory indicators, extract entities, and assess severity.
    3. Interprets the structured TriageAnalysis result.
    4. Dynamically generates and schedules subsequent investigation tasks (e.g. log analysis).
    5. Executes each task with transactional rollback, timeout checks, and budget bounding.
    6. Maintains complete investigation state, metrics, and auditable execution trace.
    """

    name: ClassVar[str] = "orchestrator"
    version: ClassVar[str] = "1.0.0"
    capability: ClassVar[AgentCapability] = AgentCapability.ORCHESTRATION
    description: ClassVar[str] = (
        "Orchestrates investigations: coordinates triage, interprets structured findings, "
        "creates tasks, and maintains lifecycle state."
    )

    def __init__(
        self,
        *,
        database: Database,
        settings: Settings,
        agents: AgentRegistry,
        tools: ToolRegistry,
        planner: Planner | None = None,
        router: ModelRouter | None = None,
    ) -> None:
        self._db = database
        self._settings = settings
        self._agents = agents
        self._tools = tools
        self._planner = planner
        self._router = router
        self._active_states: dict[uuid.UUID, InvestigationState] = {}

    def get_state(self, investigation_id: uuid.UUID) -> InvestigationState | None:
        """Retrieve the in-memory state of an active or recent investigation."""
        return self._active_states.get(investigation_id)

    async def execute(self, investigation_id: uuid.UUID) -> InvestigationOutcome:
        """Run the full investigation lifecycle. Never raises for task-level failures."""
        with log_context(investigation_id=str(investigation_id)):
            state = InvestigationState(investigation_id=investigation_id)
            self._active_states[investigation_id] = state

            initial_plan, artifacts = await self._begin(investigation_id, state)
            deadline = asyncio.get_running_loop().time() + self._settings.max_investigation_seconds

            tasks_to_run: list[Task] = list(initial_plan.tasks)
            all_planned_tasks: list[Task] = list(initial_plan.tasks)
            task_idx = 0

            while task_idx < len(tasks_to_run):
                task = tasks_to_run[task_idx]
                remaining = deadline - asyncio.get_running_loop().time()
                is_report = task.agent_name == "reporting"

                if remaining <= 0 and not is_report:
                    halted_reason = (
                        "Investigation budget of "
                        f"{self._settings.max_investigation_seconds}s was exhausted."
                    )
                    state.halted_reason = halted_reason
                    outcome = await self._skip(investigation_id, task, halted_reason)
                    state.task_outcomes.append(outcome)
                    task_idx += 1
                    continue

                # Reporting receives a grace budget past the deadline to preserve auditable report
                budget = max(remaining, _REPORT_GRACE_SECONDS) if is_report else remaining
                outcome = await self._run_task(investigation_id, task, budget)
                state.task_outcomes.append(outcome)

                # If Triage was executed, extract triage analysis and optionally
                # dynamically create tasks if adaptive planning is active.
                if (
                    task.agent_name == "triage"
                    and outcome.status is RunStatus.SUCCEEDED
                    and task_idx == 0
                ):
                    created_tasks, notes, analysis = self.interpret_triage_result(
                        outcome.result, artifacts
                    )
                    state.triage_analysis = analysis
                    state.notes.extend(notes)

                    is_adaptive = self._settings.enable_adaptive_planning or (
                        self._planner is None or getattr(self._planner, "name", "") == "adaptive"
                    )

                    if is_adaptive:
                        # Only add tasks that aren't already scheduled
                        existing_names = {t.agent_name for t in tasks_to_run}
                        new_tasks = [t for t in created_tasks if t.agent_name not in existing_names]

                        # Enforce per-investigation task limit
                        available_slots = self._settings.max_tasks_per_investigation - len(
                            all_planned_tasks
                        )
                        if available_slots < len(new_tasks):
                            note = (
                                f"Plan truncated to {self._settings.max_tasks_per_investigation} "
                                "task(s) by the configured per-investigation limit."
                            )
                            state.notes.append(note)
                            new_tasks = new_tasks[: max(0, available_slots)]

                        if new_tasks:
                            async with self._db.session() as session:
                                for new_t in new_tasks:
                                    task_row = TaskRun(
                                        investigation_id=investigation_id,
                                        task_id=new_t.task_id,
                                        task_type=new_t.agent_name,
                                        status=TaskStatus.PENDING.value,
                                        rationale=new_t.rationale,
                                        inputs=dict(new_t.inputs),
                                    )
                                    session.add(task_row)

                                await audit.record(
                                    session,
                                    actor="system",
                                    action="orchestrator.tasks_created",
                                    resource_type="investigation",
                                    resource_id=str(investigation_id),
                                    detail={
                                        "triage_category": (
                                            analysis.classification.category
                                            if analysis is not None
                                            else "unknown"
                                        ),
                                        "tasks": [t.agent_name for t in new_tasks],
                                        "notes": notes,
                                    },
                                )

                            tasks_to_run.extend(new_tasks)
                            all_planned_tasks.extend(new_tasks)
                            state.tasks_planned = list(all_planned_tasks)

                task_idx += 1

            status = _derive_status(state.task_outcomes, state.halted_reason is not None)
            await self._finish(investigation_id, status, state.task_outcomes, state.halted_reason)

            state.status = status
            state.completed_at = dt.datetime.now(dt.UTC)

            final_plan = Plan(
                tasks=tuple(all_planned_tasks),
                strategy=initial_plan.strategy,
                notes=tuple(state.notes),
            )

            logger.info(
                "investigation finished",
                extra={
                    "status": status.value,
                    "tasks": len(state.task_outcomes),
                    "failed": sum(1 for o in state.task_outcomes if o.status is RunStatus.FAILED),
                },
            )
            return InvestigationOutcome(
                investigation_id=investigation_id,
                status=status,
                plan=final_plan,
                outcomes=tuple(state.task_outcomes),
                state=state,
                halted_reason=state.halted_reason,
            )

    def interpret_triage_result(
        self,
        result: AgentResult | None,
        artifacts: list[Artifact],
    ) -> tuple[list[Task], list[str], TriageAnalysis | None]:
        """Interprets the structured result of the Triage Agent to generate follow-up tasks."""
        if result is None or not result.succeeded:
            fallback_tasks, fallback_notes = self._fallback_tasks(artifacts)
            return (
                fallback_tasks,
                ["Triage agent did not produce a successful result; using fallback plan."],
                None,
            )

        raw_analysis = result.metrics.get("triage_analysis")
        triage_analysis: TriageAnalysis | None = None
        if isinstance(raw_analysis, dict):
            try:
                triage_analysis = TriageAnalysis.model_validate(raw_analysis)
            except Exception as exc:
                logger.warning(
                    "could not validate triage_analysis from metrics", extra={"error": str(exc)}
                )
        elif isinstance(raw_analysis, TriageAnalysis):
            triage_analysis = raw_analysis

        tasks: list[Task] = []
        notes: list[str] = []

        if triage_analysis is not None:
            step_idx = 2
            for proposal in sorted(triage_analysis.investigation_plan, key=lambda p: p.priority):
                task_type = proposal.task_type.strip()
                if task_type == "triage":
                    continue
                if self._agents.has(task_type):
                    tasks.append(
                        Task(
                            task_id=f"t{step_idx}-{task_type}",
                            agent_name=task_type,
                            rationale=proposal.rationale,
                            inputs={},
                        )
                    )
                    step_idx += 1
                else:
                    notes.append(
                        f"Skipped proposed task '{task_type}': "
                        "agent is not registered in this deployment."
                    )

            # Ensure reporting is always scheduled to synthesize findings
            if not any(t.agent_name == "reporting" for t in tasks) and self._agents.has(
                "reporting"
            ):
                tasks.append(
                    Task(
                        task_id="t9-report",
                        agent_name="reporting",
                        rationale=(
                            "Reporting runs last so it can summarise every finding recorded by "
                            "preceding tasks and compute the risk roll-up over all of them."
                        ),
                    )
                )
        else:
            tasks, fallback_notes = self._fallback_tasks(artifacts)
            notes.extend(fallback_notes)

        return tasks, notes, triage_analysis

    def _fallback_tasks(self, artifacts: list[Artifact]) -> tuple[list[Task], list[str]]:
        """Deterministic rule-based fallback when model-driven triage analysis is unavailable."""
        tasks: list[Task] = []
        notes: list[str] = []

        log_like = [
            artifact
            for artifact in artifacts
            if artifact.kind
            in {
                ArtifactKind.LINUX_AUTH_LOG.value,
                ArtifactKind.GENERIC_TEXT.value,
                ArtifactKind.SYS_LOG.value,
            }
            or artifact.kind == ArtifactKind.UNKNOWN.value
        ]
        if log_like and self._agents.has("log_analysis"):
            tasks.append(
                Task(
                    task_id="t2-log-analysis",
                    agent_name="log_analysis",
                    rationale=(
                        f"{len(log_like)} artifact(s) may contain authentication records, so "
                        "the log parser and its detection rules are applicable."
                    ),
                )
            )

        if self._agents.has("reporting"):
            tasks.append(
                Task(
                    task_id="t9-report",
                    agent_name="reporting",
                    rationale=(
                        "Reporting runs last so it can summarise every finding recorded by "
                        "preceding tasks and compute the risk roll-up over all of them."
                    ),
                )
            )

        return tasks, notes

    # --- Lifecycle ----------------------------------------------------------

    async def _begin(
        self, investigation_id: uuid.UUID, state: InvestigationState
    ) -> tuple[Plan, list[Artifact]]:
        async with self._db.session() as session:
            investigation = await _load_investigation(session, investigation_id)
            artifacts = await _load_artifacts(session, investigation_id)

            # If a planner is provided, respect its plan
            if self._planner is not None:
                plan = self._planner.plan(investigation, artifacts)
                if len(plan) > self._settings.max_tasks_per_investigation:
                    plan = Plan(
                        tasks=plan.tasks[: self._settings.max_tasks_per_investigation],
                        strategy=plan.strategy,
                        notes=(
                            *plan.notes,
                            f"Plan truncated to {self._settings.max_tasks_per_investigation} "
                            "task(s) by the configured per-investigation limit.",
                        ),
                    )
                initial_tasks = list(plan.tasks)
                strategy = plan.strategy
                notes = list(plan.notes)
            else:
                # Standard Orchestrator dynamic plan starts with triage
                triage_task = Task(
                    task_id="t1-triage",
                    agent_name="triage",
                    rationale=(
                        "Triage always runs first: it inventories the indicators present in "
                        "the submission, identifies evidence gaps, and formulates an initial "
                        "investigation plan."
                    ),
                )
                initial_tasks = [triage_task]
                strategy = "dynamic_orchestrator"
                notes = []
                plan = Plan(tasks=tuple(initial_tasks), strategy=strategy, notes=tuple(notes))

            state.tasks_planned = list(initial_tasks)
            state.notes = list(notes)

            # Persist initial tasks in task_runs table
            for task in initial_tasks:
                task_row = TaskRun(
                    investigation_id=investigation_id,
                    task_id=task.task_id,
                    task_type=task.agent_name,
                    status=TaskStatus.PENDING.value,
                    rationale=task.rationale,
                    inputs=dict(task.inputs),
                )
                session.add(task_row)

            investigation.status = InvestigationStatus.RUNNING.value
            investigation.started_at = dt.datetime.now(dt.UTC)
            investigation.error = None
            state.started_at = investigation.started_at

            await audit.record(
                session,
                actor="system",
                action=audit.INVESTIGATION_STARTED,
                resource_type="investigation",
                resource_id=str(investigation_id),
                detail={
                    "planner": strategy,
                    "initial_tasks": [task.agent_name for task in initial_tasks],
                    "notes": notes,
                },
            )

        logger.info(
            "investigation started",
            extra={"strategy": strategy, "task_count": len(initial_tasks)},
        )
        return plan, artifacts

    async def _finish(
        self,
        investigation_id: uuid.UUID,
        status: InvestigationStatus,
        outcomes: list[TaskOutcome],
        halted_reason: str | None,
    ) -> None:
        failures = [
            f"{outcome.task.agent_name}: {outcome.error}"
            for outcome in outcomes
            if outcome.status is RunStatus.FAILED and outcome.error
        ]
        async with self._db.session() as session:
            investigation = await _load_investigation(session, investigation_id)
            investigation.status = status.value
            investigation.completed_at = dt.datetime.now(dt.UTC)
            reasons = [*([halted_reason] if halted_reason else []), *failures]
            investigation.error = "; ".join(reasons) or None

            await audit.record(
                session,
                actor="system",
                action=audit.INVESTIGATION_FINISHED,
                resource_type="investigation",
                resource_id=str(investigation_id),
                outcome=(
                    audit.SUCCESS if status is InvestigationStatus.COMPLETED else audit.FAILURE
                ),
                detail={
                    "status": status.value,
                    "task_status": {o.task.task_id: o.status.value for o in outcomes},
                },
            )

    # --- Task execution -----------------------------------------------------

    async def _run_task(
        self, investigation_id: uuid.UUID, task: Task, budget: float
    ) -> TaskOutcome:
        agent = self._agents.get(task.agent_name)
        agent_cls = type(agent)
        agent_run_id = await self._open_run(investigation_id, task, agent_cls)

        started = dt.datetime.now(dt.UTC)
        result: AgentResult | None = None
        error: str | None = None

        try:
            async with self._db.session() as session:
                investigation = await _load_investigation(session, investigation_id)
                artifacts = await _load_artifacts(session, investigation_id)
                store = EvidenceStore(
                    session,
                    investigation_id,
                    max_evidence=self._settings.max_evidence_per_investigation,
                )
                runner = ToolRunner(
                    session=session,
                    investigation_id=investigation_id,
                    registry=self._tools,
                    store=store,
                    artifact_root=self._settings.artifact_dir,
                )
                ctx = AgentContext(
                    investigation=investigation,
                    artifacts=artifacts,
                    session=session,
                    store=store,
                    tools=runner,
                    settings=self._settings,
                    agent_run_id=agent_run_id,
                    router=self._router,
                )
                result = await asyncio.wait_for(agent.run(ctx, dict(task.inputs)), timeout=budget)
        except TimeoutError:
            error = f"agent exceeded its remaining time budget of {budget:.0f}s"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            logger.exception("agent failed", extra={"agent": task.agent_name})

        finished = dt.datetime.now(dt.UTC)
        status = result.status if result is not None else RunStatus.FAILED
        await self._close_run(
            investigation_id,
            task,
            agent_run_id,
            status=status,
            result=result,
            error=error,
            duration_ms=int((finished - started).total_seconds() * 1000),
        )
        return TaskOutcome(
            task=task,
            status=status,
            agent_run_id=agent_run_id,
            summary=result.summary if result is not None else (error or "failed"),
            result=result,
            error=error,
        )

    async def _skip(self, investigation_id: uuid.UUID, task: Task, reason: str) -> TaskOutcome:
        agent_cls = type(self._agents.get(task.agent_name))
        async with self._db.session() as session:
            run = AgentRun(
                investigation_id=investigation_id,
                task_id=task.task_id,
                agent_name=agent_cls.name,
                agent_version=agent_cls.version,
                status=RunStatus.SKIPPED.value,
                rationale=task.rationale,
                inputs=dict(task.inputs),
                outputs={"skipped_because": reason},
                finished_at=dt.datetime.now(dt.UTC),
                duration_ms=0,
                error=reason,
            )
            session.add(run)

            task_row = await session.scalar(
                sa.select(TaskRun).where(
                    TaskRun.investigation_id == investigation_id,
                    TaskRun.task_id == task.task_id,
                )
            )
            if task_row is not None:
                task_row.status = TaskStatus.CANCELLED.value
                task_row.finished_at = dt.datetime.now(dt.UTC)
                task_row.error = reason
                task_row.outputs = {"skipped_because": reason}

            await session.flush()
            run_id = run.id
        logger.warning("task skipped", extra={"agent": task.agent_name, "reason": reason})
        return TaskOutcome(
            task=task,
            status=RunStatus.SKIPPED,
            agent_run_id=run_id,
            summary=reason,
            result=None,
            error=reason,
        )

    async def _open_run(
        self, investigation_id: uuid.UUID, task: Task, agent_cls: type[Agent]
    ) -> uuid.UUID:
        async with self._db.session() as session:
            run = AgentRun(
                investigation_id=investigation_id,
                task_id=task.task_id,
                agent_name=agent_cls.name,
                agent_version=agent_cls.version,
                status=RunStatus.RUNNING.value,
                rationale=task.rationale,
                inputs=dict(task.inputs),
            )
            session.add(run)

            task_row = await session.scalar(
                sa.select(TaskRun).where(
                    TaskRun.investigation_id == investigation_id,
                    TaskRun.task_id == task.task_id,
                )
            )
            if task_row is None:
                task_row = TaskRun(
                    investigation_id=investigation_id,
                    task_id=task.task_id,
                    task_type=agent_cls.name,
                    status=TaskStatus.RUNNING.value,
                    rationale=task.rationale,
                    inputs=dict(task.inputs),
                    started_at=dt.datetime.now(dt.UTC),
                )
                session.add(task_row)
            else:
                task_row.status = TaskStatus.RUNNING.value
                task_row.started_at = dt.datetime.now(dt.UTC)

            await session.flush()
            return run.id

    async def _close_run(
        self,
        investigation_id: uuid.UUID,
        task: Task,
        agent_run_id: uuid.UUID,
        *,
        status: RunStatus,
        result: AgentResult | None,
        error: str | None,
        duration_ms: int,
    ) -> None:
        outputs = (
            {
                "summary": result.summary,
                "evidence_ids": result.evidence_ids,
                "finding_ids": result.finding_ids,
                "metrics": result.metrics,
                "next_actions": result.next_actions,
                "errors": result.errors,
            }
            if result is not None
            else {}
        )
        async with self._db.session() as session:
            run = await session.get(AgentRun, agent_run_id)
            if run is not None:
                run.status = status.value
                run.finished_at = dt.datetime.now(dt.UTC)
                run.duration_ms = duration_ms
                run.outputs = outputs
                run.error = error

            task_row = await session.scalar(
                sa.select(TaskRun).where(
                    TaskRun.investigation_id == investigation_id,
                    TaskRun.task_id == task.task_id,
                )
            )
            if task_row is not None:
                task_row.status = (
                    TaskStatus.SUCCEEDED.value
                    if status is RunStatus.SUCCEEDED
                    else TaskStatus.FAILED.value
                )
                task_row.finished_at = dt.datetime.now(dt.UTC)
                task_row.duration_ms = duration_ms
                task_row.outputs = outputs
                task_row.error = error


# Backward-compatible alias
Orchestrator = OrchestratorAgent


def _derive_status(outcomes: list[TaskOutcome], halted: bool) -> InvestigationStatus:
    """Terminal status from task outcomes.

    Ordering matters: a halt or a failure must never be reported as completion.
    """
    if not outcomes:
        return InvestigationStatus.FAILED
    failed = [o for o in outcomes if o.status is RunStatus.FAILED]
    succeeded = [o for o in outcomes if o.status is RunStatus.SUCCEEDED]
    if halted:
        return InvestigationStatus.HALTED
    if failed and succeeded:
        return InvestigationStatus.PARTIAL
    if failed:
        return InvestigationStatus.FAILED
    return InvestigationStatus.COMPLETED


async def _load_investigation(session: AsyncSession, investigation_id: uuid.UUID) -> Investigation:
    investigation = await session.get(Investigation, investigation_id)
    if investigation is None:
        raise NotFoundError(f"investigation {investigation_id} not found")
    return investigation


async def _load_artifacts(session: AsyncSession, investigation_id: uuid.UUID) -> list[Artifact]:
    rows = await session.scalars(
        sa.select(Artifact)
        .where(Artifact.investigation_id == investigation_id)
        .order_by(Artifact.uploaded_at)
    )
    return list(rows.all())
