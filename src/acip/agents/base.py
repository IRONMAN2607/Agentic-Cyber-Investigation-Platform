"""Agent contract.

Agents receive a typed context and return a typed result (spec s6). They do not
talk to each other directly — the orchestrator passes results along — which keeps
the execution trace linear and auditable.

An agent may reason, but it may only *assert* through the evidence store, which
enforces the grounding invariants. That is the structural reason an agent cannot
become an unquestioned source of truth.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from acip.config import Settings
from acip.core.evidence.store import EvidenceStore
from acip.db.models import Artifact, Investigation
from acip.tools.runner import ToolRunner
from acip.types import AgentCapability, RunStatus

if TYPE_CHECKING:
    from acip.core.llm.router import ModelRouter


@dataclass
class AgentContext:
    """Everything an agent is given for one execution."""

    investigation: Investigation
    artifacts: list[Artifact]
    session: AsyncSession
    store: EvidenceStore
    tools: ToolRunner
    settings: Settings
    agent_run_id: uuid.UUID
    router: ModelRouter | None = None

    def artifacts_of_kind(self, *kinds: str) -> list[Artifact]:
        return [artifact for artifact in self.artifacts if artifact.kind in kinds]


class AgentResult(BaseModel):
    """Structured outcome of one agent execution."""

    status: RunStatus = RunStatus.SUCCEEDED
    summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    next_actions: list[str] = Field(
        default_factory=list,
        description="What this agent believes should happen next. Advisory; the "
        "orchestrator decides.",
    )
    errors: list[str] = Field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.status is RunStatus.SUCCEEDED


class Agent(ABC):
    """Base class for all agents."""

    name: ClassVar[str]
    version: ClassVar[str]
    capability: ClassVar[AgentCapability]
    description: ClassVar[str] = ""

    @abstractmethod
    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult:
        """Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure."""
