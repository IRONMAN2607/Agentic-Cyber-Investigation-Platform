from __future__ import annotations

from acip.core.risk import assess
from acip.db.models import Finding
from acip.types import AssertionClass, Severity


def _make_finding(
    assertion_class: AssertionClass,
    severity: Severity,
    confidence: float = 1.0,
) -> Finding:
    f = Finding(
        title="Test finding",
        description="Description",
        assertion_class=assertion_class.value,
        severity=severity.value,
        confidence=confidence,
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
