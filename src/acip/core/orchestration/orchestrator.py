"""Investigation orchestration.

Executes a plan task by task, recording an ``agent_runs`` and ``task_runs`` row for every attempt.

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
from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from acip.agents.base import Agent, AgentContext, AgentResult
from acip.agents.registry import AgentRegistry
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
from acip.types import InvestigationStatus, RunStatus, TaskStatus

logger = get_logger(__name__)

_REPORT_GRACE_SECONDS = 30


@dataclass(frozen=True, slots=True)
class TaskOutcome:
    task: Task
    status: RunStatus
    agent_run_id: uuid.UUID
    summary: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class InvestigationOutcome:
    investigation_id: uuid.UUID
    status: InvestigationStatus
    plan: Plan
    outcomes: tuple[TaskOutcome, ...]
    halted_reason: str | None = None


class Orchestrator:
    """Plans and executes one investigation at a time."""

    def __init__(
        self,
        *,
        database: Database,
        settings: Settings,
        agents: AgentRegistry,
        tools: ToolRegistry,
        planner: Planner,
    ) -> None:
        self._db = database
        self._settings = settings
        self._agents = agents
        self._tools = tools
        self._planner = planner

    async def execute(self, investigation_id: uuid.UUID) -> InvestigationOutcome:
        """Run the full investigation. Never raises for task-level failures."""
        with log_context(investigation_id=str(investigation_id)):
            plan = await self._begin(investigation_id)
            deadline = asyncio.get_running_loop().time() + self._settings.max_investigation_seconds

            outcomes: list[TaskOutcome] = []
            halted_reason: str | None = None

            for task in plan.tasks:
                remaining = deadline - asyncio.get_running_loop().time()
                is_report = task.agent_name == "reporting"

                if remaining <= 0 and not is_report:
                    halted_reason = (
                        "Investigation budget of "
                        f"{self._settings.max_investigation_seconds}s was exhausted."
                    )
                    outcomes.append(await self._skip(investigation_id, task, halted_reason))
                    continue

                # Reporting is given a grace budget even past the deadline: a
                # halted investigation with no report would be indistinguishable
                # from one that produced nothing.
                budget = max(remaining, _REPORT_GRACE_SECONDS) if is_report else remaining
                outcomes.append(await self._run_task(investigation_id, task, budget))

            status = _derive_status(outcomes, halted_reason is not None)
            await self._finish(investigation_id, status, outcomes, halted_reason)

            logger.info(
                "investigation finished",
                extra={
                    "status": status.value,
                    "tasks": len(outcomes),
                    "failed": sum(1 for o in outcomes if o.status is RunStatus.FAILED),
                },
            )
            return InvestigationOutcome(
                investigation_id=investigation_id,
                status=status,
                plan=plan,
                outcomes=tuple(outcomes),
                halted_reason=halted_reason,
            )

    # --- Lifecycle ----------------------------------------------------------

    async def _begin(self, investigation_id: uuid.UUID) -> Plan:
        async with self._db.session() as session:
            investigation = await _load_investigation(session, investigation_id)
            artifacts = await _load_artifacts(session, investigation_id)

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

            # Persist planned tasks in task_runs table
            for task in plan.tasks:
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

            await audit.record(
                session,
                actor="system",
                action=audit.INVESTIGATION_STARTED,
                resource_type="investigation",
                resource_id=str(investigation_id),
                detail={
                    "planner": plan.strategy,
                    "tasks": [task.agent_name for task in plan.tasks],
                    "notes": list(plan.notes),
                },
            )

        logger.info(
            "investigation planned",
            extra={"planner": plan.strategy, "task_count": len(plan)},
        )
        return plan

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
                store = EvidenceStore(session, investigation_id)
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
