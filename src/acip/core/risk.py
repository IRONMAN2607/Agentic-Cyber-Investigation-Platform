"""Deterministic risk scoring.

Severity and risk are computed from findings by a fixed formula, never assigned
by a language model. An LLM may later propose an adjustment, but it will be
recorded as a separate, attributed opinion rather than overwriting this value
(spec s5.11).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from acip.types import AssertionClass, Severity

# Contribution of a single finding at each severity, out of 100.
_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 1,
}

# A hypothesis is not yet established, so it contributes at a reduced rate.
_HYPOTHESIS_DISCOUNT = 0.5


class ScorableFinding(Protocol):
    """Structural type covering both ORM findings and drafts."""

    @property
    def severity(self) -> str: ...

    @property
    def confidence(self) -> float: ...

    @property
    def assertion_class(self) -> str: ...


@dataclass(frozen=True)
class RiskAssessment:
    severity: Severity
    risk_score: int
    confidence: float
    rationale: str


def assess(findings: Sequence[ScorableFinding]) -> RiskAssessment:
    """Roll findings up into an investigation-level severity and risk score."""
    if not findings:
        return RiskAssessment(
            severity=Severity.INFO,
            risk_score=0,
            confidence=0.0,
            rationale="No findings were produced, so no risk can be attributed.",
        )

    score = 0.0
    top = Severity.INFO
    weighted_confidence = 0.0
    weight_total = 0.0
    counts: dict[Severity, int] = {}

    for finding in findings:
        severity = Severity(str(finding.severity))
        assertion = AssertionClass(str(finding.assertion_class))
        counts[severity] = counts.get(severity, 0) + 1

        # An UNKNOWN records an evidence gap; it must not raise the risk score.
        if assertion is AssertionClass.UNKNOWN:
            continue

        contribution = _WEIGHTS[severity] * float(finding.confidence)
        if assertion is AssertionClass.HYPOTHESIS:
            contribution *= _HYPOTHESIS_DISCOUNT
        score += contribution

        if severity.rank > top.rank:
            top = severity

        weight = float(severity.rank + 1)
        weighted_confidence += float(finding.confidence) * weight
        weight_total += weight

    risk_score = int(min(100.0, round(score)))
    confidence = round(weighted_confidence / weight_total, 3) if weight_total else 0.0
    breakdown = ", ".join(
        f"{count} {severity.value}" for severity, count in sorted(counts.items(), key=lambda kv: -kv[0].rank)
    )
    return RiskAssessment(
        severity=top,
        risk_score=risk_score,
        confidence=confidence,
        rationale=(
            f"Derived from {len(findings)} finding(s) ({breakdown}) using fixed severity "
            "weights scaled by per-finding confidence. Hypotheses contribute at half weight; "
            "findings recording an evidence gap contribute nothing."
        ),
    )
