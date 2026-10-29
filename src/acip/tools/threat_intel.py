"""Local deterministic threat-intelligence evaluation adapter.

The bundled entries are synthetic demo data, not third-party reputation results.
No network requests are made. A missing entry has unknown reputation, not a clean verdict.
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

# Synthetic indicators for deterministic offline evaluation, not live provider results.
_KNOWN_THREAT_REPUTATION: dict[str, dict[str, Any]] = {
    "198.51.100.23": {
        "source": "local_deterministic_feed",
        "abuse_score": 100,
        "is_malicious": True,
        "reputation_status": "malicious",
        "category": "SSH Brute-Force Attacker",
        "reports_count": 42,
    },
    "203.0.113.195": {
        "source": "local_deterministic_feed",
        "abuse_score": 95,
        "is_malicious": True,
        "reputation_status": "malicious",
        "category": "Web Exploit Scanner / SQLi",
        "reports_count": 28,
    },
    "192.0.2.1": {
        "source": "local_deterministic_feed",
        "abuse_score": 0,
        "is_malicious": False,
        "reputation_status": "benign",
        "category": "Documentation / Benign",
        "reports_count": 0,
    },
    "evil-attacker.example.com": {
        "source": "local_deterministic_feed",
        "abuse_score": 88,
        "is_malicious": True,
        "reputation_status": "malicious",
        "category": "C2 Domain / Phishing",
        "reports_count": 14,
    },
    "safe.example.com": {
        "source": "local_deterministic_feed",
        "abuse_score": 0,
        "is_malicious": False,
        "reputation_status": "benign",
        "category": "Documentation / Benign",
        "reports_count": 0,
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {  # pragma: allowlist secret  # noqa: E501
        "source": "local_deterministic_feed",
        "abuse_score": 0,
        "is_malicious": False,
        "reputation_status": "benign",
        "category": "Empty File Hash",
        "reports_count": 0,
    },
    "44d88612fea8a8f36de82e1278abb02f": {  # pragma: allowlist secret
        "source": "local_deterministic_feed",
        "abuse_score": 90,
        "is_malicious": True,
        "reputation_status": "malicious",
        "category": "EICAR Test String Hash",
        "reports_count": 55,
    },
}


class ThreatIntelArgs(BaseModel):
    """Options for threat intelligence reputation lookup."""

    indicator: str = Field(..., description="Target indicator (IP, domain, or hash)")
    indicator_type: str = Field(
        default="ip", pattern="^(ip|domain|hash|url)$", description="Type of indicator"
    )
    opt_in_external_lookup: bool = Field(
        default=True,
        description="Legacy lookup switch; this adapter only queries the local evaluation feed",
    )


class ThreatIntelTool(ToolAdapter):
    """Local evaluation-feed lookup; no external reputation service is queried."""

    name: ClassVar[str] = "threat_intel"
    version: ClassVar[str] = "0.2.0"
    tier: ClassVar[SandboxTier] = SandboxTier.T0_IN_PROCESS
    args_model: ClassVar[type[BaseModel]] = ThreatIntelArgs
    requires_artifact: ClassVar[bool] = False

    def probe(self) -> ToolAvailability:
        return ToolAvailability(
            name=self.name,
            version=self.version,
            tier=self.tier,
            available=True,
            reason="Local deterministic evaluation feed active; no network lookup is performed.",
        )

    async def execute(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        if not isinstance(args, ThreatIntelArgs):
            raise ToolError(f"expected ThreatIntelArgs, got {type(args).__name__}")

        if not args.opt_in_external_lookup:
            return ToolResult(
                evidence=[],
                metrics={"status": "opt_in_declined"},
                warnings=["Operator did not opt in to the local threat-intelligence lookup."],
                exit_status=0,
            )

        indicator_val = args.indicator.strip()
        rep_info = _KNOWN_THREAT_REPUTATION.get(indicator_val)

        if rep_info is None:
            from acip.core.detection.url_rules import inspect_target_reputation

            rep_info = inspect_target_reputation(indicator_val)

        observed_time = dt.datetime.now(dt.UTC)
        evidence_item = EvidenceDraft(
            kind=EvidenceKind.THREAT_INTEL,
            data={
                "indicator": indicator_val,
                "indicator_type": args.indicator_type,
                "source": rep_info["source"],
                "abuse_score": rep_info["abuse_score"],
                "is_malicious": rep_info["is_malicious"],
                "reputation_status": rep_info["reputation_status"],
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
                "reputation_status": rep_info["reputation_status"],
            },
            warnings=[
                "Synthetic evaluation feed only; scores and report counts are demo values, "
                "not third-party reputation results."
            ],
            exit_status=0,
        )
