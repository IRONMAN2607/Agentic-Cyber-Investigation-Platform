"""Structured output schemas for the Triage Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

from acip.types import Severity


class ExtractedEntity(BaseModel):
    """An entity extracted during initial investigation triage."""

    entity_type: str = Field(
        description=(
            "The entity type: 'ip', 'domain', 'url', 'user', 'host', 'hash', "
            "'file', 'process', 'port', 'email', etc."
        )
    )
    value: str = Field(description="Normalized value of the entity")
    role: str = Field(
        default="unknown",
        description=(
            "Entity role in this context: 'attacker', 'target', 'victim', "
            "'infrastructure', 'compromised_user', 'suspicious_file', 'c2_server', etc."
        ),
    )
    context: str = Field(
        default="",
        description="Specific context or observation associated with this entity",
    )


class InputClassification(BaseModel):
    """Classification of the submitted investigation target and artifacts."""

    category: str = Field(
        description=(
            "Category of the incident/target: 'authentication_attack', 'brute_force', "
            "'credential_access', 'phishing_attempt', 'malware_delivery', 'reconnaissance', "
            "'suspicious_infrastructure', 'benign_activity', 'unknown'"
        )
    )
    summary: str = Field(
        description="Concise 1-2 sentence executive summary of what the input represents"
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Epistemic confidence in this classification assessment",
    )
    initial_severity: Severity = Field(
        default=Severity.INFO,
        description="Initial estimated severity: 'info', 'low', 'medium', 'high', 'critical'",
    )
    reasoning: str = Field(
        description=(
            "Detailed epistemic justification and reasoning connecting observations "
            "to this classification"
        )
    )


class IndicatorAssessment(BaseModel):
    """Initial indicator of compromise assessment."""

    indicator_type: str = Field(
        description="Indicator type: 'ip', 'domain', 'url', 'hash', 'email', etc."
    )
    value: str = Field(description="Indicator value")
    scope: str = Field(
        default="global",
        description=(
            "Indicator scope: 'global' (externally routable/public), "
            "'internal' (private/RFC1918), 'local' (localhost)"
        ),
    )
    threat_assessment: str = Field(
        default="unverified",
        description=(
            "Initial threat assessment: 'suspicious_inbound', 'target_asset', "
            "'external_c2_candidate', 'unverified_reputation', 'benign_internal'"
        ),
    )
    is_malicious_candidate: bool = Field(
        default=False,
        description="Whether this indicator warrants priority threat intelligence enrichment",
    )


class EvidenceGap(BaseModel):
    """An identified knowledge or evidence gap requiring resolution."""

    description: str = Field(description="Description of what remains unknown or unverified")
    required_source: str = Field(
        description=(
            "Data source or tool needed to resolve this gap (e.g. "
            "'threat_intelligence_enrichment', 'network_pcap', "
            "'windows_event_log', 'endpoint_process_tree')"
        )
    )
    importance: str = Field(
        default="medium",
        description="Importance level of closing this gap: 'low', 'medium', 'high'",
    )


class PlannedTaskProposal(BaseModel):
    """A proposed subsequent investigation task."""

    task_type: str = Field(
        description=(
            "Recommended agent capability or tool task: 'log_analysis', "
            "'network_analysis', 'threat_intelligence', 'reporting'"
        )
    )
    rationale: str = Field(
        description="Explicit rationale explaining why this step should be taken"
    )
    priority: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Priority rank (1 = highest immediate priority)",
    )


class TriageAnalysis(BaseModel):
    """Complete structured triage output schema."""

    classification: InputClassification
    entities: list[ExtractedEntity] = Field(default_factory=list)
    indicators: list[IndicatorAssessment] = Field(default_factory=list)
    evidence_gaps: list[EvidenceGap] = Field(default_factory=list)
    investigation_plan: list[PlannedTaskProposal] = Field(default_factory=list)


__all__ = [
    "EvidenceGap",
    "ExtractedEntity",
    "IndicatorAssessment",
    "InputClassification",
    "PlannedTaskProposal",
    "TriageAnalysis",
]
