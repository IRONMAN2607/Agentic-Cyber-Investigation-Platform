"""Audited tool invocation.

Every tool call passes through :class:`ToolRunner`, which is responsible for the
guarantees the rest of the system relies on:

* **Schema validation.** Arguments are validated against the adapter's model
  before execution. Anything not in the schema cannot be expressed.
* **Path containment.** An artifact path is checked to live inside the
  configured artifact directory before an adapter can read it.
* **Durable audit.** A ``tool_runs`` row is written before execution and updated
  after, so a crash still leaves a record of what was attempted (spec s12).
* **Bounded execution.** Every call runs under a timeout.
* **Provenance binding.** Evidence is persisted here, with ``tool_run_id`` set.
  That link is what allows a claim to be classified as a FACT.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from acip.core.evidence.store import EvidenceStore
from acip.db.models import Evidence, ToolRun
from acip.errors import ToolError, ValidationError
from acip.logging import get_logger
from acip.tools.base import ToolContext, ToolResult
from acip.tools.registry import ToolRegistry
from acip.types import RunStatus

logger = get_logger(__name__)

DEFAULT_TOOL_TIMEOUT_SECONDS = 120
_MAX_AUDITED_ARG_CHARS = 512


@dataclass
class ToolInvocation:
    """Outcome of one audited tool call."""

    tool_run: ToolRun
    result: ToolResult
    evidence: list[Evidence]

    @property
    def evidence_ids(self) -> list[uuid.UUID]:
        return [row.id for row in self.evidence]


class ToolRunner:
    """Executes tools for one investigation, recording each invocation."""

    def __init__(
        self,
        *,
        session: AsyncSession,
        investigation_id: uuid.UUID,
        registry: ToolRegistry,
        store: EvidenceStore,
        artifact_root: Path,
        default_timeout: int = DEFAULT_TOOL_TIMEOUT_SECONDS,
    ) -> None:
        self._session = session
        self._investigation_id = investigation_id
        self._registry = registry
        self._store = store
        self._artifact_root = artifact_root.resolve()
        self._default_timeout = default_timeout

    async def run(
        self,
        tool_name: str,
        args: dict[str, Any] | BaseModel | None = None,
        *,
        agent_run_id: uuid.UUID | None = None,
        artifact_id: uuid.UUID | None = None,
        artifact_path: Path | None = None,
        timeout: int | None = None,  # noqa: ASYNC109
    ) -> ToolInvocation:
        """Validate, execute and audit a single tool call."""
        tool = self._registry.get(tool_name)

        availability = tool.probe()
        if not availability.available:
            raise ToolError(
                f"tool '{tool_name}' is not available in this deployment",
                detail={"reason": availability.reason},
            )

        validated = self._validate_args(tool.args_model, args)

        if tool.requires_artifact and artifact_path is None:
            raise ValidationError(f"tool '{tool_name}' requires an artifact")
        if artifact_path is not None:
            artifact_path = self._check_containment(artifact_path)

        tool_run = ToolRun(
            investigation_id=self._investigation_id,
            agent_run_id=agent_run_id,
            tool_name=tool.name,
            tool_version=tool.version,
            sandbox_tier=tool.tier.value,
            args=_redact_args(validated.model_dump(mode="json")),
            status=RunStatus.RUNNING.value,
        )
        self._session.add(tool_run)
        await self._session.flush()

        started = dt.datetime.now(dt.UTC)
        ctx = ToolContext(
            investigation_id=self._investigation_id,
            agent_run_id=agent_run_id,
            artifact_id=artifact_id,
            artifact_path=artifact_path,
        )

        try:
            result = await asyncio.wait_for(
                tool.execute(validated, ctx), timeout=timeout or self._default_timeout
            )
        except TimeoutError as exc:
            await self._finalize(tool_run, started, status=RunStatus.FAILED, error="timed out")
            raise ToolError(
                f"tool '{tool_name}' timed out",
                detail={"timeout_seconds": timeout or self._default_timeout},
            ) from exc
        except Exception as exc:
            await self._finalize(
                tool_run, started, status=RunStatus.FAILED, error=f"{type(exc).__name__}: {exc}"
            )
            raise

        evidence = await self._store.add_evidence(
            result.evidence,
            source_tool=tool.name,
            artifact_id=artifact_id,
            tool_run_id=tool_run.id,
            agent_run_id=agent_run_id,
        )

        await self._finalize(
            tool_run,
            started,
            status=RunStatus.SUCCEEDED,
            evidence_count=len(evidence),
            warnings=result.warnings,
            exit_status=result.exit_status,
        )
        logger.info(
            "tool completed",
            extra={
                "tool": tool.name,
                "tool_version": tool.version,
                "evidence_created": len(evidence),
                "duration_ms": tool_run.duration_ms,
            },
        )
        return ToolInvocation(tool_run=tool_run, result=result, evidence=evidence)

    # --- Internals ----------------------------------------------------------

    @staticmethod
    def _validate_args(
        model: type[BaseModel], args: dict[str, Any] | BaseModel | None
    ) -> BaseModel:
        if isinstance(args, model):
            return args
        payload = args.model_dump() if isinstance(args, BaseModel) else (args or {})
        try:
            return model.model_validate(payload)
        except PydanticValidationError as exc:
            raise ValidationError(
                "invalid tool arguments",
                detail={"errors": exc.errors(include_url=False)},
            ) from exc

    def _check_containment(self, path: Path) -> Path:
        """Reject any artifact path outside the configured storage root."""
        resolved = path.resolve()
        if not resolved.is_relative_to(self._artifact_root):
            raise ValidationError(
                "artifact path is outside the artifact directory",
                detail={"path": str(path)},
            )
        if not resolved.is_file():
            raise ValidationError("artifact file does not exist", detail={"path": str(path)})
        return resolved

    async def _finalize(
        self,
        tool_run: ToolRun,
        started: dt.datetime,
        *,
        status: RunStatus,
        error: str | None = None,
        evidence_count: int = 0,
        warnings: list[str] | None = None,
        exit_status: int | None = None,
    ) -> None:
        finished = dt.datetime.now(dt.UTC)
        tool_run.status = status.value
        tool_run.finished_at = finished
        tool_run.duration_ms = int((finished - started).total_seconds() * 1000)
        tool_run.error = error
        tool_run.evidence_count = evidence_count
        tool_run.warnings = warnings or []
        tool_run.exit_status = exit_status
        await self._session.flush()


def _redact_args(args: dict[str, Any]) -> dict[str, Any]:
    """Keep the audit record useful without copying bulk input into it."""
    redacted: dict[str, Any] = {}
    for key, value in args.items():
        if isinstance(value, str) and len(value) > _MAX_AUDITED_ARG_CHARS:
            redacted[key] = f"<{len(value)} characters omitted>"
        else:
            redacted[key] = value
    return redacted
