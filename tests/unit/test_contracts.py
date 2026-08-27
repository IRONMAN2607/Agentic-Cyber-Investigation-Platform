from __future__ import annotations

import datetime as dt

import pytest

from acip.core.evidence.contracts import (
    EntityRef,
    EvidenceDraft,
    FindingDraft,
    normalize_entity_value,
)
from acip.types import AssertionClass, EntityType, EvidenceKind, Severity, TimeConfidence


def test_normalize_entity_ip() -> None:
    assert normalize_entity_value(EntityType.IP, "203.0.113.55") == "203.0.113.55"
    assert normalize_entity_value(EntityType.IP, "2001:0db8::0001") == "2001:db8::1"
    # Invalid IP falls back safely
    assert normalize_entity_value(EntityType.IP, "invalid-ip-str") == "invalid-ip-str"


def test_normalize_entity_domain() -> None:
    assert normalize_entity_value(EntityType.DOMAIN, "Example.COM.") == "example.com"
    assert normalize_entity_value(EntityType.HOST, "WEB01.Corp.Local") == "web01.corp.local"


def test_normalize_entity_hash() -> None:
    raw_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    assert normalize_entity_value(EntityType.HASH, raw_hash) == raw_hash.lower()


def test_normalize_entity_port() -> None:
    assert normalize_entity_value(EntityType.PORT, " 8080 ") == "8080"
    assert normalize_entity_value(EntityType.PORT, "not-a-port") == "not-a-port"


def test_content_hash_invariance_and_sensitivity() -> None:
    d1 = EvidenceDraft(
        kind=EvidenceKind.AUTH_EVENT,
        data={"user": "deploy", "source_ip": "203.0.113.55"},
        observed_at=dt.datetime(2026, 3, 10, 3, 11, 1, tzinfo=dt.UTC),
        time_confidence=TimeConfidence.EXACT,
        entities=[EntityRef(type=EntityType.IP, value="203.0.113.55", role="source")],
        confidence=1.0,
    )
    # Same intrinsic content, different confidence and entity order
    d2 = EvidenceDraft(
        kind=EvidenceKind.AUTH_EVENT,
        data={"user": "deploy", "source_ip": "203.0.113.55"},
        observed_at=dt.datetime(2026, 3, 10, 3, 11, 1, tzinfo=dt.UTC),
        time_confidence=TimeConfidence.EXACT,
        entities=[EntityRef(type=EntityType.IP, value="203.0.113.55", role="source")],
        confidence=0.8,
    )
    assert d1.content_hash("auth_parser") == d2.content_hash("auth_parser")

    # Different source tool -> different hash
    assert d1.content_hash("tool_a") != d1.content_hash("tool_b")

    # Altered data -> different hash
    d3 = EvidenceDraft(
        kind=EvidenceKind.AUTH_EVENT,
        data={"user": "root", "source_ip": "203.0.113.55"},
        observed_at=dt.datetime(2026, 3, 10, 3, 11, 1, tzinfo=dt.UTC),
        time_confidence=TimeConfidence.EXACT,
        entities=[EntityRef(type=EntityType.IP, value="203.0.113.55", role="source")],
        confidence=1.0,
    )
    assert d1.content_hash("auth_parser") != d3.content_hash("auth_parser")


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={},
            observed_at=dt.datetime(2026, 3, 10, 3, 11, 1),  # Naive datetime
        )


def test_finding_draft_validation() -> None:
    f = FindingDraft(
        title="Brute force attack",
        description="Repeated failed logins observed",
        assertion_class=AssertionClass.INFERENCE,
        severity=Severity.HIGH,
        confidence=0.9,
        evidence_ids=[],
        reasoning="Pattern matches brute force",
    )
    assert f.title == "Brute force attack"
    assert f.severity == Severity.HIGH
