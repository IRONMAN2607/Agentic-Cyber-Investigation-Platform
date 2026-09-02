"""API request and response models.

Response models exist separately from the ORM so the wire format is explicit.
Two properties matter here:

* Provenance is not optional in a response. Evidence carries its source tool and
  run ids; findings carry their assertion class, reasoning and cited evidence.
  A client physically cannot render a claim without its epistemic status.
* Nothing is invented for presentation. Where a value is unknown it is ``null``,
  never a placeholder that reads as data.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from acip.types import (
    ArtifactKind,
    AssertionClass,
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

_ORM = ConfigDict(from_attributes=True)


# --- Auth --------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in_seconds: int
    user: UserResponse


class UserResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    username: str
    role: Role


# --- Investigations ----------------------------------------------------------


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    target_type: TargetType
    target_value: str = Field(min_length=1, max_length=4096)

    @field_validator("title", "target_value")
    @classmethod
    def _strip(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be blank")
        return stripped

    @model_validator(mode="after")
    def _validate_target(self) -> InvestigationCreate:
        from acip.core.security.validation import validate_target_value

        try:
            self.target_value = validate_target_value(self.target_type, self.target_value)
        except Exception as exc:
            raise ValueError(str(exc)) from exc
        return self


class URLArtifactIngest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    declared_kind: ArtifactKind = ArtifactKind.URL_RESPONSE


class TextArtifactIngest(BaseModel):
    content: str = Field(min_length=1)
    filename: str = Field(default="pasted_artifact.txt", max_length=255)
    declared_kind: ArtifactKind = ArtifactKind.GENERIC_TEXT


class ArtifactResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    display_id: str
    kind: ArtifactKind
    original_filename: str
    sha256: str
    size_bytes: int
    retention_state: RetentionState = RetentionState.REPRODUCIBLE
    uploaded_at: dt.datetime


class InvestigationResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    display_id: str
    title: str
    target_type: TargetType
    target_value: str
    status: InvestigationStatus
    severity: Severity | None
    confidence: float | None
    risk_score: int | None
    retention_state: RetentionState = RetentionState.REPRODUCIBLE
    created_at: dt.datetime
    started_at: dt.datetime | None
    completed_at: dt.datetime | None
    error: str | None


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    target_value: str | None = Field(default=None, min_length=1, max_length=4096)
    retention_state: RetentionState | None = None


class InvestigationProgress(BaseModel):
    investigation_id: uuid.UUID
    status: InvestigationStatus
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    running_task: str | None = None
    percent_complete: float


class TaskCreate(BaseModel):
    task_type: str = Field(min_length=1, max_length=64)
    agent_name: str = Field(min_length=1, max_length=64)
    rationale: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)


class EvidenceResponse(BaseModel):
    """An observation with its provenance chain intact."""

    model_config = _ORM

    id: uuid.UUID
    display_id: str
    kind: str
    source_tool: str
    observed_at: dt.datetime | None
    time_confidence: TimeConfidence
    collected_at: dt.datetime
    confidence: float
    data: dict[str, Any]
    entities: dict[str, Any]
    artifact_id: uuid.UUID | None
    tool_run_id: uuid.UUID | None
    agent_run_id: uuid.UUID | None


class FindingEvidenceResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    finding_id: uuid.UUID
    evidence_id: uuid.UUID
    role: EvidenceRole
    created_at: dt.datetime


class FindingResponse(BaseModel):
    """A claim, inseparable from its epistemic status and support."""

    model_config = _ORM

    id: uuid.UUID
    display_id: str
    title: str
    description: str
    assertion_class: AssertionClass
    severity: Severity
    confidence: float
    evidence_ids: list[str]
    reasoning: str | None
    detection_rule: str | None
    agent_run_id: uuid.UUID | None
    created_at: dt.datetime


class TaskRunResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    investigation_id: uuid.UUID
    task_id: str
    task_type: str
    status: TaskStatus
    rationale: str | None
    inputs: dict[str, Any]
    outputs: dict[str, Any]
    started_at: dt.datetime
    finished_at: dt.datetime | None
    duration_ms: int | None
    error: str | None


class AgentRunResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    task_id: str
    agent_name: str
    agent_version: str
    status: RunStatus
    rationale: str | None
    started_at: dt.datetime
    finished_at: dt.datetime | None
    duration_ms: int | None
    error: str | None
    outputs: dict[str, Any]


class ToolRunResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    agent_run_id: uuid.UUID | None
    task_id: str | None = None
    tool_name: str
    tool_version: str
    sandbox_tier: str
    status: RunStatus
    args: dict[str, Any]
    evidence_count: int
    warnings: list[str]
    started_at: dt.datetime
    finished_at: dt.datetime | None
    duration_ms: int | None
    error: str | None


class ProvenanceChainResponse(BaseModel):
    """One observation resolved down to the bytes it came from.

    evidence-model.md s7 requires that, for any statement in the output, the tool,
    arguments, agent, timestamp and input file that produced it can be named. This
    is that resolution in a single call, so a client does not have to reassemble
    the chain from four lookups and infer for itself when a link is missing.

    ``complete`` is false when any link is absent and ``gaps`` says which. A
    broken chain is stated rather than rendered as a whole one: evidence whose
    tool run is gone can no longer support a FACT under G1, and a caller that
    cannot see the difference will present it as though it could.
    """

    evidence: EvidenceResponse
    tool_run: ToolRunResponse | None
    artifact: ArtifactResponse | None
    agent_run: AgentRunResponse | None
    complete: bool
    gaps: list[str]


# --- Hypotheses --------------------------------------------------------------


class HypothesisCreate(BaseModel):
    statement: str = Field(min_length=1, max_length=4096)
    refutation_condition: str = Field(min_length=1, max_length=4096)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class HypothesisEvidenceResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    hypothesis_id: uuid.UUID
    evidence_id: uuid.UUID
    role: EvidenceRole
    created_at: dt.datetime


class HypothesisGapResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    hypothesis_id: uuid.UUID
    description: str
    required_tool: str | None
    resolved: bool
    created_at: dt.datetime


class HypothesisResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    display_id: str
    investigation_id: uuid.UUID
    statement: str
    status: HypothesisStatus
    confidence: float
    refutation_condition: str
    agent_run_id: uuid.UUID | None
    created_at: dt.datetime


# --- Model Executions (LLM Calls) --------------------------------------------


class ModelExecutionResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    investigation_id: uuid.UUID
    agent_run_id: uuid.UUID | None
    task_id: str | None
    task_class: str
    provider: str
    model: str
    prompt_name: str
    prompt_version: str
    tokens_in: int
    tokens_out: int
    latency_ms: int
    cost_estimate_usd: float
    finish_reason: FinishReason
    retries: int
    schema_valid: bool
    fallback_from: str | None
    temperature: float
    seed: int | None
    nondeterminism_risk: str
    grounding_violations: int
    created_at: dt.datetime


# --- Audit & Reports ---------------------------------------------------------


class AuditLogResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    ts: dt.datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    detail: dict[str, Any]


class ReportResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    fmt: str
    content: str
    generated_at: dt.datetime


class InvestigationDetail(BaseModel):
    """Everything needed to render an investigation workspace in one call."""

    investigation: InvestigationResponse
    artifacts: list[ArtifactResponse]
    findings: list[FindingResponse]
    agent_runs: list[AgentRunResponse]
    tool_runs: list[ToolRunResponse]
    report: ReportResponse | None
    counts: dict[str, int]


class PagedEvidence(BaseModel):
    """A page of evidence. Cursor-paged, per api.md s5.

    ``next_cursor`` is null on the final page. It is opaque: clients pass it back
    verbatim and must not parse it, so the sort key can change without breaking
    them.
    """

    items: list[EvidenceResponse]
    total: int
    limit: int
    next_cursor: str | None = None


class StartResponse(BaseModel):
    investigation_id: uuid.UUID
    status: InvestigationStatus
    accepted: bool
    message: str


# --- System ------------------------------------------------------------------


class ToolCapability(BaseModel):
    name: str
    version: str
    tier: str
    available: bool
    reason: str | None = None


class AgentCapabilityInfo(BaseModel):
    name: str
    version: str
    capability: str
    description: str


class CapabilitiesResponse(BaseModel):
    """What this deployment can actually do, and what it cannot.

    ``not_implemented`` is served from the same source the report renders, so the
    API and the report cannot disagree about the platform's limits.
    """

    environment: str
    tools: list[str]
    agents: list[str]
    planner: str
    not_implemented: list[str]
    operating_boundary: str


class AdminCapabilitiesResponse(BaseModel):
    """Detailed diagnostic report for administrators."""

    environment: str
    tools: list[ToolCapability]
    agents: list[AgentCapabilityInfo]
    planner: str
    not_implemented: list[str]
    operating_boundary: str


class HealthResponse(BaseModel):
    status: str
    database: str
    version: str


class ErrorResponse(BaseModel):
    code: str
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)


# Resolve the forward reference in TokenResponse.
TokenResponse.model_rebuild()
