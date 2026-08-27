from __future__ import annotations

from acip.types import (
    AssertionClass,
    InvestigationStatus,
    Role,
    Severity,
    TimeConfidence,
)


def test_severity_ordering() -> None:
    assert Severity.INFO.rank < Severity.LOW.rank
    assert Severity.LOW.rank < Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank < Severity.HIGH.rank
    assert Severity.HIGH.rank < Severity.CRITICAL.rank
    assert Severity.CRITICAL.rank == 4


def test_investigation_status_terminal() -> None:
    assert not InvestigationStatus.CREATED.terminal
    assert not InvestigationStatus.RUNNING.terminal
    assert InvestigationStatus.COMPLETED.terminal
    assert InvestigationStatus.PARTIAL.terminal
    assert InvestigationStatus.FAILED.terminal
    assert InvestigationStatus.HALTED.terminal


def test_role_values() -> None:
    assert Role.VIEWER.value == "viewer"
    assert Role.INVESTIGATOR.value == "investigator"
    assert Role.ADMIN.value == "admin"


def test_assertion_class_values() -> None:
    assert AssertionClass.FACT.value == "fact"
    assert AssertionClass.INFERENCE.value == "inference"
    assert AssertionClass.HYPOTHESIS.value == "hypothesis"
    assert AssertionClass.UNKNOWN.value == "unknown"


def test_time_confidence_values() -> None:
    assert TimeConfidence.EXACT.value == "exact"
    assert TimeConfidence.DERIVED.value == "derived"
    assert TimeConfidence.APPROXIMATE.value == "approximate"
    assert TimeConfidence.UNKNOWN.value == "unknown"
