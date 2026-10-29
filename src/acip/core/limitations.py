"""Declared limitations of this deployment.

A single source for what the platform does *not* do, consumed by both the report
renderer and ``GET /capabilities``. Keeping one list means the API and the report
cannot drift into disagreeing about the platform's limits, and removing a
capability gap is a one-line diff when the phase that closes it lands.
"""

from typing import Any


def get_not_implemented(settings: Any = None) -> list[str]:
    """Return declared capability limitations reflecting the active runtime configuration."""
    items: list[str] = [
        "No endpoint or memory forensics: process, registry and memory artifacts are not examined.",
        "No dynamic malware or sample execution: the deployment does not detonate files or "
        "provide a VM/container escape boundary for live samples.",
        "Threat intelligence uses only the bundled deterministic evaluation feed; no external "
        "VirusTotal, AbuseIPDB, OTX, Shodan, DNS, or RDAP provider is contacted.",
        "Object-level authorization is not implemented; the supported boundary is one trusted "
        "developer on localhost rather than a shared multi-user deployment.",
    ]
    if settings is not None and getattr(settings, "enable_llm_triage", False):
        items.append(
            "Language-model reasoning is active for triage classification and entity extraction; "
            "narratives in generated reports remain template-produced from stored records."
        )
    else:
        items.append(
            "No language-model reasoning: triage and report narratives are produced "
            "deterministically from stored records."
        )
    items.append(
        "Parsing covers Linux authentication logs (sshd/sudo/PAM), Web server access logs "
        "(Nginx/Apache/W3C), PCAP packet captures, and URL/domain indicator inspection "
        "(brand typosquatting, deceptive subdomains, and credential phishing lures)."
    )
    items.append(
        "Deterministic MITRE ATT&CK mapping is active for authentication, web attack, "
        "and URL/domain phishing detection rules."
    )
    items.append(
        "Deterministic evidence graph correlation and canonical entity resolution are active."
    )
    items.append(
        "Hypothesis generation and bounded validation are available to the adaptive planner; "
        "the execution trace records whether they ran for a particular investigation."
    )
    return items


NOT_IMPLEMENTED: tuple[str, ...] = tuple(get_not_implemented(None))

# This is a support boundary, not a claim about the process's current socket.
# It is exposed by the API and CLI so a client cannot mistake the local
# prototype for a multi-user or remotely deployable service.
OPERATING_BOUNDARY = (
    "Supported only for one trusted developer on localhost, using synthetic or sanitised data. "
    "Remote, multi-user, and production deployments are not supported."
)
