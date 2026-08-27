"""MITRE ATT&CK catalog and mapping validation.

Enforces Invariant G7: no finding or agent claim can emit or cite a MITRE ATT&CK
technique ID that does not exist in the recorded catalog version.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from acip.errors import GroundingError

ATTACK_CATALOG_VERSION: Final[str] = "15.1"


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    id: str
    name: str
    tactic: str
    description: str
    is_subtechnique: bool = False


# Local deterministic catalog of verified ATT&CK Enterprise techniques
ATTACK_CATALOG: Final[dict[str, AttackTechnique]] = {
    "T1110": AttackTechnique(
        id="T1110",
        name="Brute Force",
        tactic="credential-access",
        description="Adversaries may use brute force techniques to attempt access to accounts.",
    ),
    "T1110.001": AttackTechnique(
        id="T1110.001",
        name="Password Guessing",
        tactic="credential-access",
        description="Adversaries may guess passwords to attempt access to accounts.",
        is_subtechnique=True,
    ),
    "T1110.003": AttackTechnique(
        id="T1110.003",
        name="Password Spraying",
        tactic="credential-access",
        description=(
            "Adversaries may use a single or small list of passwords against many accounts."
        ),
        is_subtechnique=True,
    ),
    "T1087": AttackTechnique(
        id="T1087",
        name="Account Discovery",
        tactic="discovery",
        description=(
            "Adversaries may attempt to get a listing of accounts on a system or environment."
        ),
    ),
    "T1087.001": AttackTechnique(
        id="T1087.001",
        name="Local Account Discovery",
        tactic="discovery",
        description="Adversaries may attempt to get a listing of local system accounts.",
        is_subtechnique=True,
    ),
    "T1078": AttackTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic="defense-evasion",
        description="Adversaries may obtain and abuse credentials of existing accounts.",
    ),
    "T1548": AttackTechnique(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="privilege-escalation",
        description="Adversaries may circumvent mechanisms designed to control elevate privileges.",
    ),
    "T1548.003": AttackTechnique(
        id="T1548.003",
        name="Sudo and Sudo Caching",
        tactic="privilege-escalation",
        description="Adversaries may perform sudo operations to execute commands as root.",
        is_subtechnique=True,
    ),
    "T1059": AttackTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="execution",
        description="Adversaries may abuse command and script interpreters to execute commands.",
    ),
    "T1059.004": AttackTechnique(
        id="T1059.004",
        name="Unix Shell",
        tactic="execution",
        description="Adversaries may abuse Unix shells to execute commands.",
        is_subtechnique=True,
    ),
}

# Deterministic rule to technique mapping
RULE_TO_ATTACK_MAP: Final[dict[str, str]] = {
    "R-AUTH-001": "T1110.001",  # Brute force
    "R-AUTH-003": "T1087.001",  # User enumeration
    "R-AUTH-004": "T1548.003",  # Privilege escalation
}


def get_attack_technique(technique_id: str) -> AttackTechnique:
    """Lookup a technique in the catalog.

    Enforces Invariant G7: raises GroundingError if the technique does not exist.
    """
    clean_id = technique_id.strip().upper()
    technique = ATTACK_CATALOG.get(clean_id)
    if technique is None:
        raise GroundingError(
            f"unknown ATT&CK technique ID {technique_id!r} in catalog v{ATTACK_CATALOG_VERSION}",
            detail={
                "invariant": "G7",
                "technique_id": technique_id,
                "catalog_version": ATTACK_CATALOG_VERSION,
            },
        )
    return technique


def map_rule_to_technique(rule_id: str) -> AttackTechnique | None:
    """Deterministically map a detection rule to its ATT&CK technique."""
    technique_id = RULE_TO_ATTACK_MAP.get(rule_id)
    if technique_id is None:
        return None
    return get_attack_technique(technique_id)
