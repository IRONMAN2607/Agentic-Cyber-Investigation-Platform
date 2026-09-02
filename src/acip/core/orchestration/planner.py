"""Investigation planning.

A plan is an ordered list of :class:`Task`, each naming an agent and carrying a
``rationale`` — the recorded reason the task exists. The rationale is persisted
on the agent run and shown in the report, so an investigation can always answer
"why was this step taken?".

:class:`Planner` is a protocol with one deterministic implementation in this
milestone. The seam matters: Phase 7 introduces an LLM-backed planner (built on
Phase 6 model abstraction), and the research design needs the two to be
swappable behind an identical interface so they can be compared on the same
inputs. An LLM planner will be constrained to emitting :class:`Task` objects
naming registered agents — it selects among known capabilities and never
invents an executable step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from acip.agents.registry import AgentRegistry
from acip.db.models import Artifact, Investigation
from acip.types import ArtifactKind


@dataclass(frozen=True, slots=True)
class Task:
    """One planned agent execution."""

    task_id: str
    agent_name: str
    rationale: str
    inputs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Plan:
    """An ordered set of tasks plus the reason the shape was chosen."""

    tasks: tuple[Task, ...]
    strategy: str
    notes: tuple[str, ...] = ()

    def __len__(self) -> int:
        return len(self.tasks)


@runtime_checkable
class Planner(Protocol):
    """Chooses which agents run, in what order, and why."""

    name: str

    def plan(self, investigation: Investigation, artifacts: list[Artifact]) -> Plan: ...


class StaticPlanner:
    """Rule-based planner: reproducible, and the control condition for the study.

    Every branch is a stated rule over observable inputs, so the same submission
    always yields the same plan. That property is what makes it usable as the
    baseline an adaptive planner is measured against.
    """

    name = "static"

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    def plan(self, investigation: Investigation, artifacts: list[Artifact]) -> Plan:
        tasks: list[Task] = []
        notes: list[str] = []

        tasks.append(
            Task(
                task_id="t1-triage",
                agent_name="triage",
                rationale=(
                    "Triage always runs first: it inventories the indicators present in "
                    "the submission, which bounds what later steps can examine."
                ),
            )
        )

        log_like = [
            artifact
            for artifact in artifacts
            if artifact.kind in {ArtifactKind.LINUX_AUTH_LOG.value, ArtifactKind.GENERIC_TEXT.value}
            or artifact.kind == ArtifactKind.UNKNOWN.value
        ]
        if log_like:
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
        else:
            notes.append(
                "Log analysis was not scheduled: no submitted artifact could plausibly "
                "contain authentication records."
            )

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

        unavailable = [task.agent_name for task in tasks if not self._registry.has(task.agent_name)]
        if unavailable:
            # Degrade explicitly rather than failing the whole investigation.
            notes.append(
                "Skipped unavailable agent(s): " + ", ".join(sorted(set(unavailable))) + "."
            )
            tasks = [task for task in tasks if self._registry.has(task.agent_name)]

        return Plan(tasks=tuple(tasks), strategy=self.name, notes=tuple(notes))
