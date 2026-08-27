"""Evidence and finding contracts.

Agents and tools exchange these Pydantic models rather than ORM objects, so the
persistence layer stays replaceable and validation happens at the boundary
(spec s6: typed structured messages, not free-form text).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from acip.types import (
    AssertionClass,
    EntityType,
    EvidenceKind,
    EvidenceRole,
    FinishReason,
    Severity,
    TimeConfidence,
)


def normalize_entity_value(entity_type: EntityType, value: str) -> str:
    """Canonicalise an entity value so the same thing has one representation.

    Entity resolution in Phase 5 depends on this being deterministic and stable;
    it lives here so evidence recorded in M1 is already normalised.
    """
    candidate = value.strip()
    match entity_type:
        case EntityType.IP:
            # Collapses forms such as 2001:0db8::0001 and 203.0.113.045.
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                return candidate
        case EntityType.DOMAIN:
            return candidate.rstrip(".").lower()
        case EntityType.URL:
            scheme, sep, rest = candidate.partition("://")
            return f"{scheme.lower()}{sep}{rest}" if sep else candidate
        case EntityType.HASH:
            return candidate.lower()
        case EntityType.USER | EntityType.HOST:
            return candidate.lower()
        case _:
            return candidate


class EntityRef(BaseModel):
    """A typed reference to a real-world entity observed in evidence."""

    model_config = ConfigDict(frozen=True)

    type: EntityType
    value: str
    role: str | None = Field(
        default=None,
        description="How the entity participates, e.g. 'source', 'target', 'actor'.",
    )

    @field_validator("value")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("entity value must not be empty")
        return value

    def normalized(self) -> EntityRef:
        try:
            value = normalize_entity_value(self.type, self.value)
        except ValueError:
            value = self.value.strip()
        return EntityRef(type=self.type, value=value, role=self.role)


class EvidenceDraft(BaseModel):
    """An observation produced by a tool, before persistence.

    ``observed_at`` is when the event happened; the store records ``collected_at``
    separately. Conflating the two corrupts a timeline, so they stay distinct.
    """

    kind: EvidenceKind
    data: dict[str, Any]
    observed_at: dt.datetime | None = None
    time_confidence: TimeConfidence = TimeConfidence.EXACT
    entities: list[EntityRef] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator("observed_at")
    @classmethod
    def _require_aware(cls, value: dt.datetime | None) -> dt.datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        return value

    def content_hash(self, source_tool: str) -> str:
        """Stable digest of the observation, used to deduplicate evidence.

        Covers only intrinsic content — not collection time or run ids — so the
        same observation seen twice hashes identically.
        """
        canonical = json.dumps(
            {
                "kind": self.kind.value,
                "source_tool": source_tool,
                "observed_at": self.observed_at.isoformat() if self.observed_at else None,
                "data": self.data,
                "entities": sorted(
                    (e.type.value, e.value, e.role or "") for e in self.normalized_entities()
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def normalized_entities(self) -> list[EntityRef]:
        return [entity.normalized() for entity in self.entities]


class FindingDraft(BaseModel):
    """A claim an agent wishes to record.

    The store validates this against the grounding invariants before it becomes
    a persisted finding; see :mod:`acip.core.evidence.store`.
    """

    title: str = Field(min_length=1, max_length=255)
    description: str
    assertion_class: AssertionClass
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_ids: list[uuid.UUID] = Field(default_factory=list)
    reasoning: str | None = None
    detection_rule: str | None = Field(
        default=None,
        description="Identifier of the deterministic rule that fired, when applicable.",
    )


class FindingEvidenceDraft(BaseModel):
    """A citation connecting evidence to a finding with a supporting or contradicting role."""

    finding_id: uuid.UUID
    evidence_id: uuid.UUID
    role: EvidenceRole = EvidenceRole.SUPPORTS


class HypothesisDraft(BaseModel):
    """A competing candidate explanation under evaluation (Invariant G3)."""

    statement: str = Field(min_length=1, max_length=4096)
    refutation_condition: str = Field(
        min_length=1,
        max_length=4096,
        description="A falsifiable condition that would refute this hypothesis (Invariant G3).",
    )
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    supporting_evidence_ids: list[uuid.UUID] = Field(default_factory=list)
    contradicting_evidence_ids: list[uuid.UUID] = Field(default_factory=list)

    @field_validator("statement", "refutation_condition")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be empty or whitespace only")
        return stripped


class HypothesisGapDraft(BaseModel):
    """A declared gap in evidence preventing resolution of a hypothesis."""

    description: str = Field(min_length=1, max_length=4096)
    required_tool: str | None = None


class ModelExecutionDraft(BaseModel):
    """Structured record of an LLM call for experimental tracking."""

    task_class: str = Field(min_length=1, max_length=64)
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    prompt_name: str = Field(min_length=1, max_length=128)
    prompt_version: str = Field(min_length=1, max_length=32)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    cost_estimate_usd: float = Field(default=0.0, ge=0.0)
    finish_reason: FinishReason = FinishReason.STOP
    retries: int = Field(default=0, ge=0)
    schema_valid: bool = True
    fallback_from: str | None = None
    temperature: float = Field(default=0.0, ge=0.0)
    seed: int | None = None
    nondeterminism_risk: str = "low"
    grounding_violations: int = Field(default=0, ge=0)
