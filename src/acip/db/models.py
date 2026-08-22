"""ORM models.

Design notes
------------
* No ORM ``relationship()`` declarations. Async SQLAlchemy raises on implicit
  lazy loads, and every access path in M1 is an explicit query, so relationships
  would add failure modes without adding value.
* ``Evidence`` is append-only, enforced by mapper-level events at the bottom of
  this module. Provenance columns (``artifact_id``, ``tool_run_id``,
  ``agent_run_id``) are what make a finding traceable back to a tool.
* Enums are stored as strings; see :mod:`acip.types`.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.orm import Mapped, mapped_column

from acip.db.base import Base, utcnow
from acip.types import (
    ArtifactKind,
    AssertionClass,
    EvidenceKind,
    InvestigationStatus,
    Role,
    RunStatus,
    Severity,
    TargetType,
    TimeConfidence,
)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    username: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(sa.String(255), default=None)
    password_hash: Mapped[str] = mapped_column(sa.String(255))
    role: Mapped[str] = mapped_column(sa.String(32), default=Role.INVESTIGATOR.value)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)

    @property
    def role_enum(self) -> Role:
        return Role(self.role)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    title: Mapped[str] = mapped_column(sa.String(255))
    target_type: Mapped[str] = mapped_column(sa.String(32))
    target_value: Mapped[str] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(
        sa.String(32), default=InvestigationStatus.CREATED.value, index=True
    )

    # Roll-ups derived deterministically from findings; never set by an LLM.
    severity: Mapped[str | None] = mapped_column(sa.String(32), default=None)
    confidence: Mapped[float | None] = mapped_column(sa.Float, default=None)
    risk_score: Mapped[int | None] = mapped_column(sa.Integer, default=None)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow, index=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    completed_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(sa.Text, default=None)

    @property
    def display_id(self) -> str:
        return f"INV-{str(self.id)[:8].upper()}"

    @property
    def status_enum(self) -> InvestigationStatus:
        return InvestigationStatus(self.status)

    @property
    def target_type_enum(self) -> TargetType:
        return TargetType(self.target_type)


class Artifact(Base):
    """An uploaded input, stored content-addressed under the quarantine dir."""

    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(sa.String(64), default=ArtifactKind.UNKNOWN.value)
    original_filename: Mapped[str] = mapped_column(sa.String(255))
    sha256: Mapped[str] = mapped_column(sa.String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(sa.BigInteger)
    storage_path: Mapped[str] = mapped_column(sa.Text)
    uploaded_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    @property
    def display_id(self) -> str:
        return f"ART-{str(self.id)[:8].upper()}"


class AgentRun(Base):
    """One execution of one agent. Part of the investigation execution trace."""

    __tablename__ = "agent_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str] = mapped_column(sa.String(64))
    agent_name: Mapped[str] = mapped_column(sa.String(64), index=True)
    agent_version: Mapped[str] = mapped_column(sa.String(32))
    status: Mapped[str] = mapped_column(sa.String(32), default=RunStatus.PENDING.value)
    rationale: Mapped[str | None] = mapped_column(sa.Text, default=None)
    inputs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    outputs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    started_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    duration_ms: Mapped[int | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(sa.Text, default=None)


class ToolRun(Base):
    """One audited tool invocation (spec s12).

    Every tool call is recorded before it runs and updated after, so a crash
    leaves a durable record of what was attempted.
    """

    __tablename__ = "tool_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("agent_runs.id", ondelete="SET NULL"), default=None
    )
    tool_name: Mapped[str] = mapped_column(sa.String(64), index=True)
    tool_version: Mapped[str] = mapped_column(sa.String(32))
    sandbox_tier: Mapped[str] = mapped_column(sa.String(32))
    args: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[str] = mapped_column(sa.String(32), default=RunStatus.PENDING.value)
    exit_status: Mapped[int | None] = mapped_column(default=None)
    evidence_count: Mapped[int] = mapped_column(default=0)
    warnings: Mapped[list[str]] = mapped_column(default=list)
    started_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    duration_ms: Mapped[int | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(sa.Text, default=None)


class Evidence(Base):
    """An immutable observation with full provenance.

    ``tool_run_id`` being non-NULL is the marker of deterministic origin; the
    grounding invariants in :mod:`acip.core.evidence.store` depend on it.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        sa.UniqueConstraint("investigation_id", "content_hash", name="uq_evidence_dedupe"),
        sa.Index("ix_evidence_inv_kind", "investigation_id", "kind"),
        sa.Index("ix_evidence_inv_observed", "investigation_id", "observed_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(sa.String(64))
    source_tool: Mapped[str] = mapped_column(sa.String(64))

    observed_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    time_confidence: Mapped[str] = mapped_column(
        sa.String(32), default=TimeConfidence.EXACT.value
    )
    collected_at: Mapped[dt.datetime] = mapped_column(default=utcnow)

    data: Mapped[dict[str, Any]] = mapped_column(default=dict)
    entities: Mapped[dict[str, Any]] = mapped_column(default=dict)
    confidence: Mapped[float] = mapped_column(sa.Float, default=1.0)
    content_hash: Mapped[str] = mapped_column(sa.String(64), index=True)

    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("artifacts.id", ondelete="SET NULL"), default=None
    )
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("tool_runs.id", ondelete="SET NULL"), default=None
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("agent_runs.id", ondelete="SET NULL"), default=None
    )

    @property
    def display_id(self) -> str:
        return f"EVD-{str(self.id)[:8].upper()}"

    @property
    def kind_enum(self) -> EvidenceKind:
        return EvidenceKind(self.kind)


class Finding(Base):
    """A claim about the investigation, bound to the evidence supporting it."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(sa.String(255))
    description: Mapped[str] = mapped_column(sa.Text)
    assertion_class: Mapped[str] = mapped_column(sa.String(32))
    severity: Mapped[str] = mapped_column(sa.String(32), default=Severity.INFO.value)
    confidence: Mapped[float] = mapped_column(sa.Float, default=0.5)

    # Evidence ids as text so the report layer can cite them without a join
    # table; a proper claim/evidence join table arrives with the graph (Phase 5).
    evidence_ids: Mapped[list[str]] = mapped_column(default=list)
    reasoning: Mapped[str | None] = mapped_column(sa.Text, default=None)
    detection_rule: Mapped[str | None] = mapped_column(sa.String(128), default=None)

    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("agent_runs.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)

    @property
    def display_id(self) -> str:
        return f"FND-{str(self.id)[:8].upper()}"

    @property
    def assertion_class_enum(self) -> AssertionClass:
        return AssertionClass(self.assertion_class)

    @property
    def severity_enum(self) -> Severity:
        return Severity(self.severity)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    fmt: Mapped[str] = mapped_column(sa.String(16), default="markdown")
    content: Mapped[str] = mapped_column(sa.Text)
    generated_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("agent_runs.id", ondelete="SET NULL"), default=None
    )


class AuditLog(Base):
    """Append-only record of security-relevant actions (spec s13)."""

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = _uuid_pk()
    ts: Mapped[dt.datetime] = mapped_column(default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(sa.String(128))
    action: Mapped[str] = mapped_column(sa.String(64), index=True)
    resource_type: Mapped[str] = mapped_column(sa.String(64))
    resource_id: Mapped[str | None] = mapped_column(sa.String(64), default=None)
    outcome: Mapped[str] = mapped_column(sa.String(32), default="success")
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)


# --- Append-only enforcement -------------------------------------------------
# Evidence and audit records are immutable. Enforcing this at the mapper means a
# mistake anywhere in the codebase fails loudly instead of silently rewriting
# history. Database-level enforcement (revoked UPDATE/DELETE grants) is added
# with the PostgreSQL migration in Phase 5.


def _forbid_mutation(mapper: Any, connection: Any, target: Any) -> None:
    raise RuntimeError(
        f"{type(target).__name__} is append-only and cannot be modified or deleted"
    )


for _model in (Evidence, AuditLog):
    event.listen(_model, "before_update", _forbid_mutation)
    event.listen(_model, "before_delete", _forbid_mutation)
