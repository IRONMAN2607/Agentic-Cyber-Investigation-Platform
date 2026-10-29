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
    "T1110.004": AttackTechnique(
        id="T1110.004",
        name="Credential Stuffing",
        tactic="credential-access",
        description="Adversaries may attempt credential stuffing using compromised pairs.",
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
    "T1190": AttackTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="initial-access",
        description="Adversaries may exploit a weakness in an Internet-facing computer or program.",
    ),
    "T1083": AttackTechnique(
        id="T1083",
        name="File and Directory Discovery",
        tactic="discovery",
        description="Adversaries may enumerate files and directories or search for specific files.",
    ),
    "T1505": AttackTechnique(
        id="T1505",
        name="Server Software Component",
        tactic="persistence",
        description="Adversaries may abuse software components installed on web servers.",
    ),
    "T1505.003": AttackTechnique(
        id="T1505.003",
        name="Web Shell",
        tactic="persistence",
        description="Adversaries may install a web shell to establish persistent backdoor access.",
        is_subtechnique=True,
    ),
    "T1595": AttackTechnique(
        id="T1595",
        name="Active Scanning",
        tactic="reconnaissance",
        description="Adversaries may execute active reconnaissance scans against targets.",
    ),
    "T1595.002": AttackTechnique(
        id="T1595.002",
        name="Vulnerability Scanning",
        tactic="reconnaissance",
        description="Adversaries may scan for vulnerabilities using automated scanner tools.",
        is_subtechnique=True,
    ),
    "T1046": AttackTechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic="discovery",
        description="Adversaries may attempt to enumerate services running on remote hosts.",
    ),
    "T1071": AttackTechnique(
        id="T1071",
        name="Application Layer Protocol",
        tactic="command-and-control",
        description="Adversaries may communicate using application layer protocols (HTTP/DNS).",
    ),
    "T1071.001": AttackTechnique(
        id="T1071.001",
        name="Web Protocols",
        tactic="command-and-control",
        description="Adversaries may communicate using web protocols such as HTTP/HTTPS.",
        is_subtechnique=True,
    ),
    "T1071.004": AttackTechnique(
        id="T1071.004",
        name="DNS",
        tactic="command-and-control",
        description="Adversaries may communicate using the Domain Name System (DNS) protocol.",
        is_subtechnique=True,
    ),
    "T1566": AttackTechnique(
        id="T1566",
        name="Phishing",
        tactic="initial-access",
        description="Adversaries may send phishing messages to gain access to victim systems.",
    ),
    "T1566.002": AttackTechnique(
        id="T1566.002",
        name="Spearphishing Link",
        tactic="initial-access",
        description=(
            "Adversaries may send spearphishing messages with a link to an "
            "attacker-controlled site."
        ),
        is_subtechnique=True,
    ),
    "T1583": AttackTechnique(
        id="T1583",
        name="Acquire Infrastructure",
        tactic="resource-development",
        description="Adversaries may acquire infrastructure such as domains to support operations.",
    ),
    "T1583.001": AttackTechnique(
        id="T1583.001",
        name="Domains",
        tactic="resource-development",
        description=(
            "Adversaries may register or acquire domains that imitate legitimate "
            "sites (typosquatting)."
        ),
        is_subtechnique=True,
    ),
}

# Deterministic detection rule to ATT&CK technique mapping
RULE_TO_ATTACK_MAP: Final[dict[str, str]] = {
    # Authentication rules
    "R-AUTH-001": "T1110.001",  # Password Guessing
    "R-AUTH-002": "T1110.004",  # Credential Stuffing
    "R-AUTH-003": "T1087.001",  # Local Account Discovery
    "R-AUTH-004": "T1548.003",  # Sudo and Sudo Caching
    # Web rules
    "R-WEB-001": "T1190",  # SQL Injection -> Exploit Public-Facing Application
    "R-WEB-002": "T1083",  # Path Traversal -> File and Directory Discovery
    "R-WEB-003": "T1059.004",  # Command Injection -> Unix Shell
    "R-WEB-004": "T1505.003",  # Web Shell -> Server Software Component: Web Shell
    "R-WEB-005": "T1083",  # Sensitive File Recon -> File and Directory Discovery
    "R-WEB-006": "T1595.002",  # Scanner -> Vulnerability Scanning
    "R-WEB-007": "T1595",  # Error Burst -> Active Scanning
    "R-WEB-008": "T1190",  # Successful Exploit -> Exploit Public-Facing Application
    # URL and Domain rules
    "R-URL-001": "T1583.001",  # Brand Impersonation / Typosquatting -> Domains
    "R-URL-002": "T1583.001",  # Subdomain Spoofing -> Domains
    "R-URL-003": "T1566.002",  # Phishing Lure -> Spearphishing Link
    "R-URL-004": "T1566.002",  # Credential Phishing Campaign -> Spearphishing Link
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
