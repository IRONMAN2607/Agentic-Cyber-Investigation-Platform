"""Unit tests for the CyberReasoningProvider."""

from __future__ import annotations

import pytest

from acip.agents.triage_schemas import TriageAnalysis
from acip.core.llm.contracts import ChatMessage, LLMRequest, MessageRole
from acip.core.llm.providers.reasoning import CyberReasoningProvider
from acip.types import Severity


@pytest.mark.asyncio
async def test_cyber_reasoning_ssh_brute_force() -> None:
    provider = CyberReasoningProvider(name="test_reasoning")

    prompt = (
        "Investigation Title: Host 01 SSH Attack\n"
        "Target Type: log\n"
        "Target Value: auth.log\n\n"
        "Attached Artifacts:\n"
        "- File: auth.log (Kind: linux_auth_log, Size: 1024B)\n"
        "  Excerpt: Mar 10 02:11:00 srv sshd[123]: Failed password for root from 198.51.100.42 port 54321 ssh2\n"
        "  Mar 10 02:11:04 srv sshd[124]: Failed password for root from 198.51.100.42 port 54322 ssh2\n"
        "  Mar 10 02:11:08 srv sshd[125]: Failed password for invalid user admin from 198.51.100.42 port 54323 ssh2\n\n"
        "Extracted Indicators (2 total):\n"
        "- ipv4: 198.51.100.42 (scope: global)\n\n"
        "Analyze this submission and generate the complete structured triage analysis."
    )

    request = LLMRequest(
        messages=[
            ChatMessage(role=MessageRole.SYSTEM, content="You are a cyber triage analyst."),
            ChatMessage(role=MessageRole.USER, content=prompt),
        ]
    )

    response = await provider.complete(request, model="nemotron-test")

    assert response.provider == "test_reasoning"
    assert response.usage.total_tokens > 0
    assert response.latency_ms > 0

    # Parse and validate structured output conforms strictly to TriageAnalysis schema
    analysis = TriageAnalysis.model_validate_json(response.content)

    assert analysis.classification.category == "brute_force"
    assert analysis.classification.initial_severity == Severity.HIGH
    assert analysis.classification.confidence >= 0.85
    assert (
        "credential" in analysis.classification.summary.lower()
        or "brute" in analysis.classification.summary.lower()
    )

    # Entities
    entity_vals = {e.value for e in analysis.entities}
    assert "198.51.100.42" in entity_vals
    assert any(e.entity_type == "user" for e in analysis.entities)

    # Indicator assessment
    ind_vals = {i.value: i for i in analysis.indicators}
    assert "198.51.100.42" in ind_vals
    assert ind_vals["198.51.100.42"].scope == "global"
    assert ind_vals["198.51.100.42"].is_malicious_candidate is True

    # Evidence gaps
    assert len(analysis.evidence_gaps) >= 1
    assert any("threat_intelligence" in g.required_source for g in analysis.evidence_gaps)

    # Plan
    plan_tasks = [p.task_type for p in analysis.investigation_plan]
    assert "log_analysis" in plan_tasks
    assert "reporting" in plan_tasks


@pytest.mark.asyncio
async def test_cyber_reasoning_malware_hash() -> None:
    provider = CyberReasoningProvider(name="test_reasoning")

    prompt = (
        "Investigation Title: Malicious Payload Analysis\n"
        "Target Type: hash\n"
        "Target Value: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n"
        "Attached Artifacts:\nNo artifacts attached.\n\n"
        "Extracted Indicators (1 total):\n"
        "- sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (scope: global)\n\n"
        "Analyze this submission and generate the complete structured triage analysis."
    )

    request = LLMRequest(messages=[ChatMessage(role=MessageRole.USER, content=prompt)])

    response = await provider.complete(request, model="deepseek-test")
    analysis = TriageAnalysis.model_validate_json(response.content)

    assert analysis.classification.category == "malware_delivery"
    assert analysis.classification.initial_severity == Severity.HIGH
    assert any(e.entity_type == "hash" for e in analysis.entities)
    assert any("sandbox" in g.required_source.lower() for g in analysis.evidence_gaps)


@pytest.mark.asyncio
async def test_cyber_reasoning_web_server_attack() -> None:
    provider = CyberReasoningProvider(name="test_reasoning")

    prompt = (
        "Investigation Title: Web Server Exploit Investigation\n"
        "Target Type: log\n"
        "Target Value: access.log\n\n"
        "Attached Artifacts:\n"
        "- File: access.log (Kind: web_server_log, Size: 1024B)\n"
        '  Excerpt: 203.0.113.80 - - [10/Mar/2026:04:00:05 +0000] "GET /products.php?id=1%20UNION%20SELECT%20user,pass%20FROM%20users HTTP/1.1" 200 8912 "-" "sqlmap/1.5.2"\n'
        '  203.0.113.80 - - [10/Mar/2026:04:00:10 +0000] "GET /../../etc/passwd HTTP/1.1" 403 280 "-" "Nikto/2.1.6"\n'
        '  203.0.113.80 - - [10/Mar/2026:04:00:15 +0000] "POST /cgi-bin/status?cmd=;%20whoami HTTP/1.1" 500 120 "-" "curl/7.88.1"\n\n'
        "Extracted Indicators (1 total):\n"
        "- ipv4: 203.0.113.80 (scope: global)\n\n"
        "Analyze this submission and generate the complete structured triage analysis."
    )

    request = LLMRequest(messages=[ChatMessage(role=MessageRole.USER, content=prompt)])
    response = await provider.complete(request, model="nemotron-test")
    analysis = TriageAnalysis.model_validate_json(response.content)

    assert analysis.classification.category == "web_application_attack"
    assert analysis.classification.initial_severity == Severity.CRITICAL
    assert analysis.classification.confidence >= 0.90
    assert any("waf" in g.required_source.lower() for g in analysis.evidence_gaps)
    plan_tasks = [p.task_type for p in analysis.investigation_plan]
    assert "log_analysis" in plan_tasks


@pytest.mark.asyncio
async def test_cyber_reasoning_probe() -> None:
    provider = CyberReasoningProvider()
    avail = await provider.probe()
    assert avail.available is True
    assert len(avail.models) > 0


@pytest.mark.asyncio
async def test_cyber_reasoning_layman_summary() -> None:
    from acip.api.schemas import LaymanSummary

    provider = CyberReasoningProvider(name="test_reasoning")

    prompt = (
        "Investigation Title: Web Server Exploit Investigation\n"
        "Target Type: log\n"
        "Target Value: access.log\n"
        "Status: completed\n"
        "Severity: high\n"
        "Blended Risk Score: 78 / 100\n\n"
        "Grounded Findings:\n"
        "- [CRITICAL] SQL Injection Detected: Attack patterns observed\n\n"
        "Generate a clear, objective executive summary in layman terms using "
        "NVIDIA Nemotron 3 Ultra 550B. Explain what happened chronologically."
    )

    request = LLMRequest(messages=[ChatMessage(role=MessageRole.USER, content=prompt)])
    response = await provider.complete(request, model="nvidia/nemotron-3-ultra-550b")

    assert response.raw_response is not None
    assert response.raw_response.get("schema") == "LaymanSummary"
    summary = LaymanSummary.model_validate_json(response.content)
    assert len(summary.headline) > 5
    assert len(summary.what_happened) > 10
    assert len(summary.key_findings) >= 1
    assert len(summary.conclusion) > 10
    assert len(summary.recommended_actions) >= 1
