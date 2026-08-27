"""ORM models.

Design notes
------------
* No ORM ``relationship()`` declarations. Async SQLAlchemy raises on implicit
  lazy loads, and every access path is an explicit query, so relationships
  would add failure modes without adding value.
* ``Evidence``, ``AuditLog``, and ``ModelExecution`` are append-only, enforced
  by mapper-level events at the bottom of this module. Provenance columns
  (``artifact_id``, ``tool_run_id``, ``agent_run_id``) are what make a finding
  traceable back to a tool.
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
    EvidenceRole,
    FinishReason,
    HypothesisStatus,
    InvestigationStatus,
    RetentionState,
    Role,
    RunStatus,
    Severity,
    TargetType,
    TaskStatus,
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
    retention_state: Mapped[str] = mapped_column(
        sa.String(32), default=RetentionState.REPRODUCIBLE.value
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

    @property
    def retention_state_enum(self) -> RetentionState:
        return RetentionState(self.retention_state)


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
    retention_state: Mapped[str] = mapped_column(
        sa.String(32), default=RetentionState.REPRODUCIBLE.value
    )
    uploaded_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    @property
    def display_id(self) -> str:
        return f"ART-{str(self.id)[:8].upper()}"


class TaskRun(Base):
    """One scheduled or executed unit of work in an investigation plan."""

    __tablename__ = "task_runs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    task_id: Mapped[str] = mapped_column(sa.String(64), index=True)
    task_type: Mapped[str] = mapped_column(sa.String(64), index=True)
    status: Mapped[str] = mapped_column(sa.String(32), default=TaskStatus.PENDING.value)
    rationale: Mapped[str | None] = mapped_column(sa.Text, default=None)
    inputs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    outputs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    started_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    duration_ms: Mapped[int | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(sa.Text, default=None)

    @property
    def status_enum(self) -> TaskStatus:
        return TaskStatus(self.status)


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
    task_id: Mapped[str | None] = mapped_column(sa.String(64), default=None)
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

    Every provenance foreign key is ``RESTRICT``, not ``CASCADE`` or
    ``SET NULL``. Both of the softer options destroy an immutable row's
    provenance as a side effect of deleting something else, below the ORM where
    the append-only guards cannot see it: ``CASCADE`` on the investigation
    silently deletes the evidence, and ``SET NULL`` on ``tool_run_id`` erases
    the G1 deterministic-origin marker, retroactively ungrounding every FACT
    that cited it. database.md s1 is explicit that parent deletion is not an
    integrity policy — evidence destruction goes through the audited purge in
    the investigations router, which records what it removed.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        sa.UniqueConstraint("investigation_id", "content_hash", name="uq_evidence_dedupe"),
        sa.Index("ix_evidence_inv_kind", "investigation_id", "kind"),
        sa.Index("ix_evidence_inv_observed", "investigation_id", "observed_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="RESTRICT"), index=True
    )
    kind: Mapped[str] = mapped_column(sa.String(64))
    source_tool: Mapped[str] = mapped_column(sa.String(64))

    observed_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    time_confidence: Mapped[str] = mapped_column(sa.String(32), default=TimeConfidence.EXACT.value)
    collected_at: Mapped[dt.datetime] = mapped_column(default=utcnow)

    data: Mapped[dict[str, Any]] = mapped_column(default=dict)
    entities: Mapped[dict[str, Any]] = mapped_column(default=dict)
    confidence: Mapped[float] = mapped_column(sa.Float, default=1.0)
    content_hash: Mapped[str] = mapped_column(sa.String(64), index=True)

    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("artifacts.id", ondelete="RESTRICT"), default=None
    )
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("tool_runs.id", ondelete="RESTRICT"), default=None
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("agent_runs.id", ondelete="RESTRICT"), default=None
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

    # Evidence ids as text for backwards-compatible string citations
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


class FindingEvidence(Base):
    """Relational citation mapping evidence to findings with support/contradict roles."""

    __tablename__ = "finding_evidence"
    __table_args__ = (
        sa.UniqueConstraint("finding_id", "evidence_id", "role", name="uq_finding_evidence"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(sa.String(32), default=EvidenceRole.SUPPORTS.value)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)

    @property
    def role_enum(self) -> EvidenceRole:
        return EvidenceRole(self.role)


class Hypothesis(Base):
    """A competing candidate explanation, requiring a refutation condition (G3)."""

    __tablename__ = "hypotheses"

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    statement: Mapped[str] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(
        sa.String(32), default=HypothesisStatus.PROPOSED.value, index=True
    )
    confidence: Mapped[float] = mapped_column(sa.Float, default=0.5)
    # Refutation condition is NOT NULL, enforcing Invariant G3 at the schema layer
    refutation_condition: Mapped[str] = mapped_column(sa.Text)
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("agent_runs.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)

    @property
    def display_id(self) -> str:
        return f"HYP-{str(self.id)[:8].upper()}"

    @property
    def status_enum(self) -> HypothesisStatus:
        return HypothesisStatus(self.status)


class HypothesisEvidence(Base):
    """Relational citation linking evidence to a hypothesis."""

    __tablename__ = "hypothesis_evidence"
    __table_args__ = (
        sa.UniqueConstraint("hypothesis_id", "evidence_id", "role", name="uq_hypothesis_evidence"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("hypotheses.id", ondelete="CASCADE"), index=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(sa.String(32), default=EvidenceRole.SUPPORTS.value)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)

    @property
    def role_enum(self) -> EvidenceRole:
        return EvidenceRole(self.role)


class HypothesisGap(Base):
    """Missing evidence or tool capability needed to decide a hypothesis."""

    __tablename__ = "hypothesis_gaps"

    id: Mapped[uuid.UUID] = _uuid_pk()
    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("hypotheses.id", ondelete="CASCADE"), index=True
    )
    description: Mapped[str] = mapped_column(sa.Text)
    required_tool: Mapped[str | None] = mapped_column(sa.String(64), default=None)
    resolved: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class ModelExecution(Base):
    """Audited execution trace of any LLM invocation (append-only research dataset).

    Provenance foreign keys are ``RESTRICT`` for the same reason as
    :class:`Evidence`: this table is append-only, so it must not be destroyed or
    have its provenance erased as a side effect of deleting a parent row. Empty
    until Phase 6 introduces the first model call.
    """

    __tablename__ = "llm_calls"

    id: Mapped[uuid.UUID] = _uuid_pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("investigations.id", ondelete="RESTRICT"), index=True
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("agent_runs.id", ondelete="RESTRICT"), default=None
    )
    task_id: Mapped[str | None] = mapped_column(sa.String(64), default=None)
    task_class: Mapped[str] = mapped_column(sa.String(64))
    provider: Mapped[str] = mapped_column(sa.String(64))
    model: Mapped[str] = mapped_column(sa.String(128))
    prompt_name: Mapped[str] = mapped_column(sa.String(128))
    prompt_version: Mapped[str] = mapped_column(sa.String(32))

    tokens_in: Mapped[int] = mapped_column(sa.Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(sa.Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(sa.Integer, default=0)
    cost_estimate_usd: Mapped[float] = mapped_column(sa.Float, default=0.0)

    finish_reason: Mapped[str] = mapped_column(sa.String(32), default=FinishReason.STOP.value)
    retries: Mapped[int] = mapped_column(sa.Integer, default=0)
    schema_valid: Mapped[bool] = mapped_column(default=True)
    fallback_from: Mapped[str | None] = mapped_column(sa.String(128), default=None)
    temperature: Mapped[float] = mapped_column(sa.Float, default=0.0)
    seed: Mapped[int | None] = mapped_column(sa.Integer, default=None)
    nondeterminism_risk: Mapped[str] = mapped_column(sa.String(32), default="low")
    grounding_violations: Mapped[int] = mapped_column(sa.Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow, index=True)

    @property
    def finish_reason_enum(self) -> FinishReason:
        return FinishReason(self.finish_reason)


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
# Evidence, audit records, and model execution traces are immutable.
# Enforcing this at the mapper means a mistake anywhere in the codebase
# fails loudly instead of silently rewriting history.


def _forbid_mutation(mapper: Any, connection: Any, target: Any) -> None:
    raise RuntimeError(f"{type(target).__name__} is append-only and cannot be modified or deleted")


for _model in (Evidence, AuditLog, ModelExecution):
    event.listen(_model, "before_update", _forbid_mutation)
    event.listen(_model, "before_delete", _forbid_mutation)
