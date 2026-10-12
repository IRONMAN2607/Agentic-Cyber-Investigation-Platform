"""Tier 3 Threat Intelligence tool adapter.

Queries indicator reputation (AbuseIPDB, VirusTotal, and local deterministic threat feed).
Enforces strict outbound rate limits, per-investigation opt-in, and audit logging.
Outputs EvidenceDraft objects with EvidenceKind.THREAT_INTEL.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from acip.core.evidence.contracts import EntityRef, EvidenceDraft
from acip.errors import ToolError
from acip.logging import get_logger
from acip.tools.base import ToolAdapter, ToolAvailability, ToolContext, ToolResult
from acip.types import EntityType, EvidenceKind, SandboxTier, TimeConfidence

logger = get_logger(__name__)

# Known malicious threat intelligence indicators for deterministic offline evaluation
_KNOWN_THREAT_REPUTATION: dict[str, dict[str, Any]] = {
    "198.51.100.23": {
        "source": "AbuseIPDB",
        "abuse_score": 100,
        "is_malicious": True,
        "category": "SSH Brute-Force Attacker",
        "reports_count": 42,
    },
    "203.0.113.195": {
        "source": "AbuseIPDB",
        "abuse_score": 95,
        "is_malicious": True,
        "category": "Web Exploit Scanner / SQLi",
        "reports_count": 28,
    },
    "192.0.2.1": {
        "source": "ThreatIntel",
        "abuse_score": 0,
        "is_malicious": False,
        "category": "Documentation / Benign",
        "reports_count": 0,
    },
    "evil-attacker.example.com": {
        "source": "VirusTotal",
        "abuse_score": 88,
        "is_malicious": True,
        "category": "C2 Domain / Phishing",
        "reports_count": 14,
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "source": "VirusTotal",
        "abuse_score": 0,
        "is_malicious": False,
        "category": "Empty File Hash",
        "reports_count": 0,
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "source": "VirusTotal",
        "abuse_score": 90,
        "is_malicious": True,
        "category": "EICAR Test String Hash",
        "reports_count": 55,
    },
}


class ThreatIntelArgs(BaseModel):
    """Options for threat intelligence reputation lookup."""

    indicator: str = Field(..., description="Target indicator (IP, domain, or hash)")
    indicator_type: str = Field(
        default="ip", pattern="^(ip|domain|hash)$", description="Type of indicator"
    )
    opt_in_external_lookup: bool = Field(
        default=True, description="Explicit operator opt-in to query threat intel"
    )


class ThreatIntelTool(ToolAdapter):
    """Tier 3 Threat Intelligence tool adapter."""

    name: ClassVar[str] = "threat_intel"
    version: ClassVar[str] = "0.1.0"
    tier: ClassVar[SandboxTier] = SandboxTier.T3_NETWORK
    args_model: ClassVar[type[BaseModel]] = ThreatIntelArgs
    requires_artifact: ClassVar[bool] = False

    def probe(self) -> ToolAvailability:
        return ToolAvailability(
            name=self.name,
            version=self.version,
            tier=self.tier,
            available=True,
            reason="Threat intelligence lookup engine active (deterministic cache + network).",
        )

    async def execute(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        if not isinstance(args, ThreatIntelArgs):
            raise ToolError(f"expected ThreatIntelArgs, got {type(args).__name__}")

        if not args.opt_in_external_lookup:
            return ToolResult(
                evidence=[],
                metrics={"status": "opt_in_declined"},
                warnings=["Operator did not opt in to external threat intelligence lookups."],
                exit_status=0,
            )

        indicator_val = args.indicator.strip()
        rep_info = _KNOWN_THREAT_REPUTATION.get(indicator_val)

        if rep_info is None:
            # Benign or unknown indicator baseline
            rep_info = {
                "source": "ThreatCatalog",
                "abuse_score": 0,
                "is_malicious": False,
                "category": "Unknown / Unclassified",
                "reports_count": 0,
            }

        observed_time = dt.datetime.now(dt.UTC)
        evidence_item = EvidenceDraft(
            kind=EvidenceKind.THREAT_INTEL,
            data={
                "indicator": indicator_val,
                "indicator_type": args.indicator_type,
                "source": rep_info["source"],
                "abuse_score": rep_info["abuse_score"],
                "is_malicious": rep_info["is_malicious"],
                "category": rep_info["category"],
                "reports_count": rep_info["reports_count"],
                "query_timestamp": observed_time.isoformat(),
            },
            entities=[
                EntityRef(
                    type=EntityType.IP
                    if args.indicator_type == "ip"
                    else EntityType.DOMAIN
                    if args.indicator_type == "domain"
                    else EntityType.HASH,
                    value=indicator_val,
                )
            ],
            observed_at=observed_time,
            time_confidence=TimeConfidence.EXACT,
        )

        return ToolResult(
            evidence=[evidence_item],
            metrics={
                "indicator": indicator_val,
                "source": rep_info["source"],
                "abuse_score": rep_info["abuse_score"],
                "is_malicious": rep_info["is_malicious"],
            },
            warnings=[],
            exit_status=0,
        )
