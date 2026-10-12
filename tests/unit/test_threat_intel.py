from __future__ import annotations

import uuid

import pytest

from acip.tools.base import ToolContext
from acip.tools.threat_intel import ThreatIntelArgs, ThreatIntelTool
from acip.types import EvidenceKind


@pytest.mark.asyncio
async def test_threat_intel_malicious_ip_lookup() -> None:
    tool = ThreatIntelTool()
    ctx = ToolContext(investigation_id=uuid.uuid4())

    args = ThreatIntelArgs(
        indicator="198.51.100.23",
        indicator_type="ip",
        opt_in_external_lookup=True,
    )
    result = await tool.execute(args, ctx)

    assert result.exit_status == 0
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.kind == EvidenceKind.THREAT_INTEL
    assert ev.data["indicator"] == "198.51.100.23"
    assert ev.data["abuse_score"] == 100
    assert ev.data["is_malicious"] is True
    assert ev.data["source"] == "AbuseIPDB"


@pytest.mark.asyncio
async def test_threat_intel_benign_indicator_lookup() -> None:
    tool = ThreatIntelTool()
    ctx = ToolContext(investigation_id=uuid.uuid4())

    args = ThreatIntelArgs(
        indicator="192.0.2.1",
        indicator_type="ip",
        opt_in_external_lookup=True,
    )
    result = await tool.execute(args, ctx)

    assert result.exit_status == 0
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.kind == EvidenceKind.THREAT_INTEL
    assert ev.data["indicator"] == "192.0.2.1"
    assert ev.data["abuse_score"] == 0
    assert ev.data["is_malicious"] is False


@pytest.mark.asyncio
async def test_threat_intel_opt_in_declined() -> None:
    tool = ThreatIntelTool()
    ctx = ToolContext(investigation_id=uuid.uuid4())

    args = ThreatIntelArgs(
        indicator="198.51.100.23",
        indicator_type="ip",
        opt_in_external_lookup=False,
    )
    result = await tool.execute(args, ctx)

    assert result.exit_status == 0
    assert len(result.evidence) == 0
    assert "opt in" in result.warnings[0].lower()
