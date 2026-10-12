"""Ground truth schemas for evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field

from acip.types import ArtifactKind, Severity


@dataclass(frozen=True)
class GroundTruthFinding:
    """A ground-truth malicious event or attack step to be detected."""

    id: str
    title: str
    behavior_class: str  # e.g. "credential_access", "privilege_escalation", "web_attack"
    technique_id: str | None = None  # e.g. "T1110.001", "T1548.003", "T1190"
    primary_entities: frozenset[str] = field(default_factory=frozenset)
    severity: Severity = Severity.MEDIUM


@dataclass(frozen=True)
class GroundTruthScenario:
    """A benchmark scenario with raw artifacts and ground truth labels."""

    id: str
    name: str
    description: str
    target_type: str
    target_value: str
    artifacts: tuple[tuple[str, str, ArtifactKind], ...]  # (filename, content, kind)
    expected_findings: tuple[GroundTruthFinding, ...]
    is_benign: bool = False
