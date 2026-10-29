"""Hybrid 50/50 risk scoring: blending AI decisions and deterministic mechanisms.

Risk scoring balances both deterministic detection tools (rule hits, threat feeds,
evidence graph paths) and AI structured reasoning (triage categorization, model
assessments) in an equal 50% AI / 50% deterministic blend.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from acip.types import AssertionClass, Severity

# Contribution of a single finding at each severity for deterministic mechanism roll-up.
_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 1,
}

# A hypothesis is not yet established, so it contributes at a reduced rate.
_HYPOTHESIS_DISCOUNT = 0.5

# Base risk scores attributed to AI severity decisions (0-100 scale).
_AI_SEVERITY_BASE_SCORES: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 45,
    Severity.LOW: 20,
    Severity.INFO: 0,
}

_RANK_TO_SEVERITY: dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


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
    model_opinion: str | None = None
    model_adjusted_score: int | None = None
    deterministic_score: int | None = None
    deterministic_severity: Severity | None = None
    ai_score: int | None = None
    ai_severity: Severity | None = None


def assess(
    findings: Sequence[ScorableFinding],
    *,
    ai_severity: Severity | None = None,
    ai_score: int | None = None,
    ai_confidence: float | None = None,
    ai_rationale: str | None = None,
) -> RiskAssessment:
    """Compute risk score and categorical severity.

    When an AI decision is provided or identified in findings (via 'triage.classification'),
    the assessment computes a 50% AI decision and 50% deterministic mechanism blend.
    If no AI decision is available, it gracefully defaults to the deterministic roll-up.
    """
    if not findings and ai_score is None and ai_severity is None:
        return RiskAssessment(
            severity=Severity.INFO,
            risk_score=0,
            confidence=0.0,
            rationale="No findings were produced, so no risk can be attributed.",
            deterministic_score=0,
            deterministic_severity=Severity.INFO,
            ai_score=0,
            ai_severity=Severity.INFO,
        )

    # Separate deterministic tool findings from AI triage classification findings
    det_findings: list[ScorableFinding] = []
    ai_finding: ScorableFinding | None = None

    for f in findings:
        rule = getattr(f, "detection_rule", None)
        if rule in {"triage.classification", "risk.ai_decision"}:
            ai_finding = f
        else:
            det_findings.append(f)

    # Resolve AI decision parameters from kwargs or extracted AI finding
    if ai_finding is not None:
        if ai_severity is None:
            ai_severity = Severity(str(ai_finding.severity))
        if ai_confidence is None:
            ai_confidence = float(ai_finding.confidence)
        if ai_score is None:
            ai_score = round(_AI_SEVERITY_BASE_SCORES[ai_severity] * ai_confidence)
        if ai_rationale is None:
            ai_rationale = getattr(ai_finding, "reasoning", None) or getattr(
                ai_finding, "description", None
            )

    if ai_severity is not None and ai_score is None:
        conf = ai_confidence if ai_confidence is not None else 1.0
        ai_score = round(_AI_SEVERITY_BASE_SCORES[ai_severity] * conf)

    # 1. Deterministic Mechanism Roll-Up
    det_score_raw = 0.0
    det_top = Severity.INFO
    det_weighted_conf = 0.0
    det_weight_total = 0.0
    counts: dict[Severity, int] = {}

    for finding in det_findings:
        severity = Severity(str(finding.severity))
        assertion = AssertionClass(str(finding.assertion_class))
        counts[severity] = counts.get(severity, 0) + 1

        # An UNKNOWN records an evidence gap; it must not raise the risk score.
        if assertion is AssertionClass.UNKNOWN:
            continue

        contribution = _WEIGHTS[severity] * float(finding.confidence)
        if assertion is AssertionClass.HYPOTHESIS:
            contribution *= _HYPOTHESIS_DISCOUNT
        det_score_raw += contribution

        if severity.rank > det_top.rank:
            det_top = severity

        weight = float(severity.rank + 1)
        det_weighted_conf += float(finding.confidence) * weight
        det_weight_total += weight

    det_risk_score = int(min(100.0, round(det_score_raw)))
    det_confidence = round(det_weighted_conf / det_weight_total, 3) if det_weight_total else 0.0

    # 2. If no AI decision is present, fall back to pure deterministic score
    if ai_score is None and ai_severity is None:
        breakdown = ", ".join(
            f"{count} {severity.value}"
            for severity, count in sorted(counts.items(), key=lambda kv: -kv[0].rank)
        )
        return RiskAssessment(
            severity=det_top,
            risk_score=det_risk_score,
            confidence=det_confidence,
            rationale=(
                f"Derived from {len(det_findings)} finding(s) ({breakdown}) using fixed severity "
                "weights scaled by per-finding confidence. Hypotheses contribute at half weight; "
                "findings recording an evidence gap contribute nothing."
            ),
            deterministic_score=det_risk_score,
            deterministic_severity=det_top,
        )

    # 3. 50% AI Decision + 50% Deterministic Mechanism Blend
    ai_score_val = int(max(0, min(100, ai_score if ai_score is not None else 0)))
    ai_sev = ai_severity or Severity.INFO
    ai_conf = ai_confidence if ai_confidence is not None else 0.8

    # Blended numerical score
    raw_blended_score = int(min(100, max(0, round(0.5 * det_risk_score + 0.5 * ai_score_val))))

    # Safety floor: verified critical exploit signals from deterministic detection
    # must not be diluted into non-actionable risk bands by missing or conservative AI signals.
    if det_top == Severity.CRITICAL and det_risk_score >= 80:
        final_risk_score = max(raw_blended_score, 80)
    elif det_top == Severity.CRITICAL:
        final_risk_score = max(raw_blended_score, 50)
    else:
        final_risk_score = raw_blended_score

    # Blended categorical rank (50% AI + 50% deterministic)
    blended_rank = round(0.5 * det_top.rank + 0.5 * ai_sev.rank)
    final_severity = _RANK_TO_SEVERITY[min(4, max(0, blended_rank))]

    # Ensure categorical risk remains coherent with blended numerical score boundaries
    if final_risk_score >= 80:
        if det_top == Severity.CRITICAL or ai_sev == Severity.CRITICAL:
            final_severity = Severity.CRITICAL
        else:
            final_severity = max(final_severity, Severity.HIGH)
    elif final_risk_score >= 50:
        final_severity = max(
            final_severity,
            Severity.HIGH if (det_top.rank >= 3 or ai_sev.rank >= 3) else Severity.MEDIUM,
        )
    elif final_risk_score <= 10 and det_top.rank <= 1 and ai_sev.rank <= 1:
        final_severity = min(
            final_severity,
            Severity.LOW if (det_top == Severity.LOW or ai_sev == Severity.LOW) else Severity.INFO,
        )

    final_confidence = (
        round(0.5 * det_confidence + 0.5 * ai_conf, 3) if det_weight_total else ai_conf
    )

    breakdown = ", ".join(
        f"{count} {sev.value}" for sev, count in sorted(counts.items(), key=lambda kv: -kv[0].rank)
    )
    rationale = (
        f"Blended 50% AI decision (score: {ai_score_val}/100, severity: {ai_sev.value.upper()}) "
        f"and 50% deterministic mechanism (score: {det_risk_score}/100, "
        f"severity: {det_top.value.upper()}). "
        f"Deterministic component derived from {len(det_findings)} finding(s) "
        f"({breakdown or 'none'}). "
        f"AI assessment: {ai_rationale or 'structured triage reasoning'}."
    )

    return RiskAssessment(
        severity=final_severity,
        risk_score=final_risk_score,
        confidence=final_confidence,
        rationale=rationale,
        model_opinion=ai_rationale,
        model_adjusted_score=ai_score_val,
        deterministic_score=det_risk_score,
        deterministic_severity=det_top,
        ai_score=ai_score_val,
        ai_severity=ai_sev,
    )


def assess_with_model_opinion(
    findings: Sequence[ScorableFinding],
    *,
    model_opinion: str | None = None,
    model_adjusted_score: int | None = None,
    model_severity: Severity | None = None,
) -> RiskAssessment:
    """Assess risk blending 50% AI decision and 50% deterministic mechanism."""
    return assess(
        findings,
        ai_severity=model_severity,
        ai_score=model_adjusted_score,
        ai_rationale=model_opinion,
    )
