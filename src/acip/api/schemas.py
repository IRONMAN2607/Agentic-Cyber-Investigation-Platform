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

from pydantic import BaseModel, ConfigDict, Field, field_validator

from acip.types import (
    ArtifactKind,
    AssertionClass,
    InvestigationStatus,
    Role,
    RunStatus,
    Severity,
    TargetType,
    TimeConfidence,
)

_ORM = ConfigDict(from_attributes=True)


# --- Auth --------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
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


class ArtifactResponse(BaseModel):
    model_config = _ORM

    id: uuid.UUID
    display_id: str
    kind: ArtifactKind
    original_filename: str
    sha256: str
    size_bytes: int
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
    created_at: dt.datetime
    started_at: dt.datetime | None
    completed_at: dt.datetime | None
    error: str | None


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
    items: list[EvidenceResponse]
    total: int
    limit: int
    offset: int


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
    tools: list[ToolCapability]
    agents: list[AgentCapabilityInfo]
    planner: str
    not_implemented: list[str]


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
