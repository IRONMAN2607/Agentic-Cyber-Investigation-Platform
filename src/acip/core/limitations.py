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
        "No threat-intelligence enrichment: indicator reputation was not queried.",
        "No network analysis: PCAP, DNS and flow evidence are not processed.",
        "No endpoint or memory forensics: process, registry and memory artifacts are not examined.",
        "No MITRE ATT&CK mapping: observed behaviour is not mapped to tactics or techniques.",
        "No hypothesis generation or validation: competing explanations are not enumerated "
        "or tested against evidence.",
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
        "Log parsing covers Linux authentication logs only (BSD syslog and ISO-8601 forms)."
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
