"""Declared limitations of this deployment.

A single source for what the platform does *not* do, consumed by both the report
renderer and ``GET /capabilities``. Keeping one list means the API and the report
cannot drift into disagreeing about the platform's limits, and removing a
capability gap is a one-line diff when the phase that closes it lands.
"""

from __future__ import annotations

NOT_IMPLEMENTED: tuple[str, ...] = (
    "No threat-intelligence enrichment: indicator reputation was not queried.",
    "No network analysis: PCAP, DNS and flow evidence are not processed.",
    "No endpoint or memory forensics: process, registry and memory artifacts are not examined.",
    "No MITRE ATT&CK mapping: observed behaviour is not mapped to tactics or techniques.",
    "No hypothesis generation or validation: competing explanations are not enumerated "
    "or tested against evidence.",
    "No language-model reasoning: all narrative in generated reports is template-produced "
    "from stored records.",
    "Log parsing covers Linux authentication logs only (BSD syslog and ISO-8601 forms).",
)
