from __future__ import annotations

from acip.core.risk import assess, assess_with_model_opinion
from acip.db.models import Finding
from acip.types import AssertionClass, Severity


def _make_finding(
    assertion_class: AssertionClass,
    severity: Severity,
    confidence: float = 1.0,
    detection_rule: str | None = None,
) -> Finding:
    f = Finding(
        title="Test finding",
        description="Description",
        assertion_class=assertion_class.value,
        severity=severity.value,
        confidence=confidence,
        detection_rule=detection_rule,
    )
    return f


def test_empty_findings_risk() -> None:
    assessment = assess([])
    assert assessment.severity == Severity.INFO
    assert assessment.risk_score == 0
    assert assessment.confidence == 0.0


def test_high_severity_finding_risk() -> None:
    f = _make_finding(AssertionClass.FACT, Severity.HIGH, confidence=1.0)
    assessment = assess([f])
    assert assessment.severity == Severity.HIGH
    assert assessment.risk_score > 20
    assert assessment.confidence == 1.0


def test_hypothesis_discounted() -> None:
    fact = _make_finding(AssertionClass.FACT, Severity.MEDIUM, confidence=1.0)
    hypo = _make_finding(AssertionClass.HYPOTHESIS, Severity.MEDIUM, confidence=1.0)

    res_fact = assess([fact])
    res_hypo = assess([hypo])

    assert res_hypo.risk_score < res_fact.risk_score


def test_blended_50_50_ai_and_deterministic_risk() -> None:
    """Verify that numerical and categorical risk compute a true 50/50 blend."""
    # Deterministic finding: MEDIUM (weight 10, confidence 1.0 -> det_score = 10, det_sev = MEDIUM)
    det_f = _make_finding(
        AssertionClass.INFERENCE,
        Severity.MEDIUM,
        confidence=1.0,
        detection_rule="R-AUTH-001",
    )
    # AI triage finding: HIGH (base score 75, confidence 0.90 -> ai_score = 68, ai_sev = HIGH)
    ai_f = _make_finding(
        AssertionClass.INFERENCE,
        Severity.HIGH,
        confidence=0.90,
        detection_rule="triage.classification",
    )

    assessment = assess([det_f, ai_f])

    assert assessment.deterministic_score == 10
    assert assessment.deterministic_severity == Severity.MEDIUM
    assert assessment.ai_score == 68
    assert assessment.ai_severity == Severity.HIGH

    # Blended numerical score: 0.5 * 10 + 0.5 * 68 = 5 + 34 = 39
    assert assessment.risk_score == 39
    # Blended categorical severity: 0.5 * 2 (MEDIUM) + 0.5 * 3 (HIGH) = 2.5 -> rank 3 (HIGH)
    assert assessment.severity in {Severity.HIGH, Severity.MEDIUM}
    assert "Blended 50% AI decision" in assessment.rationale


def test_ai_elevates_unmatched_telemetry() -> None:
    """When deterministic rules have no detections, AI decision still contributes 50%."""
    # Deterministic findings: only baseline parsing (INFO, weight 1)
    det_f = _make_finding(
        AssertionClass.FACT,
        Severity.INFO,
        confidence=1.0,
        detection_rule="log_analysis.parse_summary",
    )
    # AI triage finding identifies critical web exploit attempt
    ai_f = _make_finding(
        AssertionClass.INFERENCE,
        Severity.CRITICAL,
        confidence=0.95,
        detection_rule="triage.classification",
    )

    assessment = assess([det_f, ai_f])

    assert assessment.deterministic_score == 1
    assert assessment.deterministic_severity == Severity.INFO
    # AI score: 100 * 0.95 = 95
    assert assessment.ai_score == 95
    assert assessment.ai_severity == Severity.CRITICAL

    # Blended score: 0.5 * 1 + 0.5 * 95 = 48
    assert assessment.risk_score == 48
    # Elevated from INFO to at least MEDIUM
    assert assessment.severity.rank >= Severity.MEDIUM.rank


def test_ai_damps_false_alarm() -> None:
    """When deterministic rule triggers a false alarm, benign AI assessment damps risk by 50%."""
    det_f = _make_finding(
        AssertionClass.INFERENCE,
        Severity.HIGH,
        confidence=0.90,
        detection_rule="R-WEB-001",
    )
    # AI triage identifies safe test/documentation activity
    ai_f = _make_finding(
        AssertionClass.INFERENCE,
        Severity.INFO,
        confidence=1.0,
        detection_rule="triage.classification",
    )

    assessment = assess([det_f, ai_f])

    # Det score: 25 * 0.9 = 22.5 -> 22 (round half to even)
    assert assessment.deterministic_score == 22
    assert assessment.ai_score == 0
    # Blended score: 0.5 * 22 + 0 = 11 (reduced from 22)
    assert assessment.risk_score == 11
    # Severity damped from HIGH to LOW or MEDIUM
    assert assessment.severity.rank < Severity.HIGH.rank


def test_assess_with_model_opinion_50_50() -> None:
    """assess_with_model_opinion blends model adjusted score and deterministic score 50/50."""
    det_f = _make_finding(
        AssertionClass.FACT,
        Severity.HIGH,
        confidence=1.0,
        detection_rule="threat_intel.reputation",
    )
    # det_score = 25
    assessment = assess_with_model_opinion(
        [det_f],
        model_adjusted_score=75,
        model_severity=Severity.HIGH,
        model_opinion="Analyst LLM confirms high-confidence attack pattern.",
    )

    assert assessment.deterministic_score == 25
    assert assessment.ai_score == 75
    # Blended: 0.5 * 25 + 0.5 * 75 = 50
    assert assessment.risk_score == 50
    assert assessment.severity == Severity.HIGH
    assert assessment.model_opinion is not None


def test_safety_floor_prevents_critical_dilution() -> None:
    """Verified deterministic critical findings must not be diluted below CRITICAL boundary."""
    # Deterministic findings: multiple confirmed critical and high hits totaling >= 80 pts
    det_crit1 = _make_finding(
        AssertionClass.INFERENCE,
        Severity.CRITICAL,
        confidence=1.0,
        detection_rule="R-WEB-008",
    )
    det_crit2 = _make_finding(
        AssertionClass.INFERENCE,
        Severity.CRITICAL,
        confidence=1.0,
        detection_rule="R-WEB-003",
    )
    # Total det score: 45 + 45 = 90
    # AI triage finding fails to classify or returns INFO (score 0)
    ai_f = _make_finding(
        AssertionClass.INFERENCE,
        Severity.INFO,
        confidence=1.0,
        detection_rule="triage.classification",
    )

    assessment = assess([det_crit1, det_crit2, ai_f])

    assert assessment.deterministic_score == 90
    assert assessment.deterministic_severity == Severity.CRITICAL
    assert assessment.ai_score == 0
    # Without safety floor, blended would be 0.5 * 90 + 0 = 45 (MEDIUM).
    # With safety floor, it is protected at >= 80 (CRITICAL).
    assert assessment.risk_score >= 80
    assert assessment.severity == Severity.CRITICAL
