from __future__ import annotations

import pytest

from acip.core.detection.mitre import (
    ATTACK_CATALOG,
    ATTACK_CATALOG_VERSION,
    get_attack_technique,
    map_rule_to_technique,
)
from acip.errors import GroundingError


def test_mitre_catalog_version_and_contents() -> None:
    assert ATTACK_CATALOG_VERSION == "15.1"
    assert "T1110.001" in ATTACK_CATALOG
    assert "T1087.001" in ATTACK_CATALOG
    assert "T1548.003" in ATTACK_CATALOG

    tech = get_attack_technique("T1110.001")
    assert tech.name == "Password Guessing"
    assert tech.tactic == "credential-access"
    assert tech.is_subtechnique is True


def test_mitre_deterministic_rule_mapping() -> None:
    t1 = map_rule_to_technique("R-AUTH-001")
    assert t1 is not None
    assert t1.id == "T1110.001"

    t3 = map_rule_to_technique("R-AUTH-003")
    assert t3 is not None
    assert t3.id == "T1087.001"

    t4 = map_rule_to_technique("R-AUTH-004")
    assert t4 is not None
    assert t4.id == "T1548.003"

    assert map_rule_to_technique("UNKNOWN-RULE-999") is None


def test_mitre_invariant_g7_hallucinated_technique_rejected() -> None:
    with pytest.raises(GroundingError) as exc_info:
        get_attack_technique("T9999.999")

    assert exc_info.value.detail["invariant"] == "G7"
    assert exc_info.value.detail["technique_id"] == "T9999.999"
