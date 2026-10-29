"""Unit and integration tests for URL and Domain security detection rules and triage."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from acip.agents.base import AgentContext
from acip.agents.triage import TriageAgent
from acip.config import Settings
from acip.core.detection.mitre import map_rule_to_technique
from acip.core.detection.url_rules import (
    RULE_BRAND_IMPERSONATION,
    RULE_CREDENTIAL_PHISHING_CAMPAIGN,
    RULE_LEGITIMATE_DOMAIN,
    RULE_PHISHING_LURE,
    RULE_SUBDOMAIN_SPOOFING,
    decompose_url_target,
    evaluate_url_rules,
    inspect_target_reputation,
)
from acip.core.evidence.store import EvidenceStore
from acip.core.llm.providers.reasoning import CyberReasoningProvider
from acip.core.llm.router import ModelRouter
from acip.core.risk import assess
from acip.db.models import AgentRun, Investigation
from acip.db.session import Database
from acip.tools.registry import build_default_registry
from acip.tools.runner import ToolRunner
from acip.types import Severity, TargetType


def test_decompose_url_target() -> None:
    host, path, query, clean_url = decompose_url_target("microslop.com/rewards/claim5000discount")
    assert host == "microslop.com"
    assert path == "/rewards/claim5000discount"
    assert query is None
    assert clean_url == "https://microslop.com/rewards/claim5000discount"

    host, path, query, clean_url = decompose_url_target(
        "https://claude.com/contact-sales/education-plan?ref=edu"
    )
    assert host == "claude.com"
    assert path == "/contact-sales/education-plan"
    assert query == "ref=edu"
    assert clean_url == "https://claude.com/contact-sales/education-plan?ref=edu"


def test_inspect_target_reputation() -> None:
    # 1. Microslop typosquat with reward lure
    rep_bad = inspect_target_reputation("microslop.com/rewards/claim5000discount")
    assert rep_bad["reputation_status"] == "malicious"
    assert rep_bad["is_malicious"] is True
    assert rep_bad["abuse_score"] == 95
    assert "Microsoft" in rep_bad["category"]

    # 2. Legitimate Claude / Anthropic domain
    rep_good = inspect_target_reputation("https://claude.com/contact-sales/education-plan")
    assert rep_good["reputation_status"] == "benign"
    assert rep_good["is_malicious"] is False
    assert rep_good["abuse_score"] == 0
    assert "Anthropic Claude" in rep_good["category"]


def test_evaluate_url_rules_phishing_campaign() -> None:
    hits = evaluate_url_rules("microslop.com/rewards/claim5000discount")
    rule_ids = {h.rule_id for h in hits}
    assert RULE_CREDENTIAL_PHISHING_CAMPAIGN in rule_ids
    assert RULE_BRAND_IMPERSONATION in rule_ids
    assert RULE_PHISHING_LURE in rule_ids

    top_hit = hits[0]
    assert top_hit.rule_id == RULE_CREDENTIAL_PHISHING_CAMPAIGN
    assert top_hit.severity == Severity.CRITICAL
    assert top_hit.confidence >= 0.95


def test_evaluate_url_rules_legitimate_domain() -> None:
    hits = evaluate_url_rules("https://claude.com/contact-sales/education-plan")
    assert len(hits) == 1
    assert hits[0].rule_id == RULE_LEGITIMATE_DOMAIN
    assert hits[0].severity == Severity.INFO
    assert hits[0].confidence == 1.0


def test_mitre_mapping_for_url_rules() -> None:
    tech_phish = map_rule_to_technique(RULE_CREDENTIAL_PHISHING_CAMPAIGN)
    assert tech_phish is not None
    assert tech_phish.id == "T1566.002"
    assert tech_phish.name == "Spearphishing Link"

    tech_typo = map_rule_to_technique(RULE_BRAND_IMPERSONATION)
    assert tech_typo is not None
    assert tech_typo.id == "T1583.001"

    tech_subdomain = map_rule_to_technique(RULE_SUBDOMAIN_SPOOFING)
    assert tech_subdomain is not None
    assert tech_subdomain.id == "T1583.001"
    assert tech_subdomain.name == "Domains"

    tech_lure = map_rule_to_technique(RULE_PHISHING_LURE)
    assert tech_lure is not None
    assert tech_lure.id == "T1566.002"


def _make_reasoning_router() -> ModelRouter:
    from acip.core.llm.policy import RoutingPolicy

    reasoning_provider = CyberReasoningProvider(name="nvidia")
    policy = RoutingPolicy.create_default(
        nemotron_model="nvidia/nemotron-3-ultra-550b",
        deepseek_model="deepseek-ai/deepseek-r1",
    )
    return ModelRouter(providers={"nvidia": reasoning_provider}, policy=policy)


@pytest.mark.asyncio
async def test_triage_agent_and_risk_microslop_phishing(database: Database, tmp_path: Path) -> None:
    """microslop.com/rewards/claim5000discount must evaluate to HIGH or CRITICAL (score >= 85)."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=True,
    )
    router = _make_reasoning_router()

    async with database.session() as session:
        inv = Investigation(
            title="Suspicious Discount Link",
            target_type=TargetType.URL.value,
            target_value="microslop.com/rewards/claim5000discount",
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t1",
            agent_name="triage",
            agent_version="0.1.0",
            status="running",
        )
        session.add(agent_run)
        await session.flush()

        store = EvidenceStore(session, inv.id)
        tools = ToolRunner(
            session=session,
            investigation_id=inv.id,
            registry=build_default_registry(),
            store=store,
            artifact_root=tmp_path / "artifacts",
        )
        ctx = AgentContext(
            investigation=inv,
            artifacts=[],
            session=session,
            tools=tools,
            settings=settings,
            store=store,
            agent_run_id=agent_run.id,
            router=router,
        )

        agent = TriageAgent()
        result = await agent.run(ctx, {})
        assert result.status.value == "succeeded"

        findings = await store.list_findings()
        rule_ids = {f.detection_rule for f in findings if f.detection_rule}
        assert (
            RULE_CREDENTIAL_PHISHING_CAMPAIGN in rule_ids or "threat_intel.reputation" in rule_ids
        )

        # Compute risk roll-up
        risk = assess(findings)
        assert risk.risk_score >= 85
        assert risk.severity in {Severity.CRITICAL, Severity.HIGH}


@pytest.mark.asyncio
async def test_triage_agent_and_risk_claude_legitimate(database: Database, tmp_path: Path) -> None:
    """https://claude.com/contact-sales/education-plan must evaluate to INFO/BENIGN (score <= 5)."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=True,
    )
    router = _make_reasoning_router()

    async with database.session() as session:
        inv = Investigation(
            title="Official Anthropic Claude Sales Portal",
            target_type=TargetType.URL.value,
            target_value="https://claude.com/contact-sales/education-plan",
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t1",
            agent_name="triage",
            agent_version="0.1.0",
            status="running",
        )
        session.add(agent_run)
        await session.flush()

        store = EvidenceStore(session, inv.id)
        tools = ToolRunner(
            session=session,
            investigation_id=inv.id,
            registry=build_default_registry(),
            store=store,
            artifact_root=tmp_path / "artifacts",
        )
        ctx = AgentContext(
            investigation=inv,
            artifacts=[],
            session=session,
            tools=tools,
            settings=settings,
            store=store,
            agent_run_id=agent_run.id,
            router=router,
        )

        agent = TriageAgent()
        result = await agent.run(ctx, {})
        assert result.status.value == "succeeded"

        findings = await store.list_findings()
        rule_ids = {f.detection_rule for f in findings if f.detection_rule}
        assert RULE_LEGITIMATE_DOMAIN in rule_ids

        # Compute risk roll-up
        risk = assess(findings)
        assert risk.risk_score <= 5
        assert risk.severity == Severity.INFO
