"""Tool adapter contract.

A tool is the only thing in the platform allowed to produce evidence. Adapters
are deliberately narrow:

* Arguments arrive as a validated Pydantic model. An agent (or, later, an LLM)
  can only express what the schema permits — never a free-form command line.
* File access happens through ``ToolContext``, which carries an already-resolved
  and containment-checked artifact path. Adapters never accept a path argument.
* Results are evidence drafts plus metrics and warnings. An adapter that cannot
  do its job says so in ``warnings`` or raises; it never invents output.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID

from pydantic import BaseModel, Field

from acip.core.evidence.contracts import EvidenceDraft
from acip.types import SandboxTier


class ToolAvailability(BaseModel):
    """Honest report of whether a tool can actually run right now.

    Surfaced through ``GET /capabilities`` so the UI never implies a capability
    the deployment does not have (spec s31: no fake functionality).
    """

    name: str
    version: str
    tier: SandboxTier
    available: bool
    reason: str | None = None


@dataclass(frozen=True)
class ToolContext:
    """Everything an adapter is permitted to know about its invocation."""

    investigation_id: UUID
    agent_run_id: UUID | None = None
    artifact_id: UUID | None = None
    artifact_path: Path | None = None


class ToolResult(BaseModel):
    """What an adapter returns."""

    evidence: list[EvidenceDraft] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    exit_status: int | None = None


class NoArgs(BaseModel):
    """For adapters that take no options."""


class ToolAdapter(ABC):
    """Base class for all tool adapters."""

    name: ClassVar[str]
    version: ClassVar[str]
    tier: ClassVar[SandboxTier]
    args_model: ClassVar[type[BaseModel]] = NoArgs
    description: ClassVar[str] = ""
    requires_artifact: ClassVar[bool] = False

    def probe(self) -> ToolAvailability:
        """Report runtime availability.

        In-process adapters are always available. Adapters that shell out to an
        external binary override this to check for it, so a missing dependency
        is reported rather than discovered mid-investigation.
        """
        return ToolAvailability(
            name=self.name, version=self.version, tier=self.tier, available=True
        )

    @abstractmethod
    async def execute(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        """Do the work. Raise :class:`~acip.errors.ToolError` on failure."""
