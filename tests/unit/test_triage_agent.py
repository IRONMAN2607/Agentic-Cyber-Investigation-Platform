"""Unit and integration tests for the model-driven Triage Agent."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.base import AgentContext
from acip.agents.triage import TriageAgent
from acip.agents.triage_schemas import (
    EvidenceGap,
    ExtractedEntity,
    IndicatorAssessment,
    InputClassification,
    PlannedTaskProposal,
    TriageAnalysis,
)
from acip.config import Settings
from acip.core.evidence.store import EvidenceStore
from acip.core.llm.contracts import (
    FinishReason,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    TaskClass,
)
from acip.core.llm.errors import LLMError
from acip.core.llm.policy import CandidateModel, RoutingPolicy, TaskRoutingRule
from acip.core.llm.providers.replay import ReplayProvider
from acip.core.llm.router import ModelRouter
from acip.db.models import AgentRun, Artifact, Finding, Investigation, ModelExecution
from acip.db.session import Database
from acip.tools.registry import build_default_registry
from acip.tools.runner import ToolRunner
from acip.types import AssertionClass, Severity


def _make_triage_router(response_json: str) -> ModelRouter:
    """Construct a test ModelRouter backed by ReplayProvider."""
    replay = ReplayProvider(
        name="replay_provider",
        default_response=response_json,
        canned_responses={"triage": response_json, "Triage": response_json},
    )
    rule = TaskRoutingRule(
        task_class=TaskClass.CLASSIFICATION,
        candidates=[CandidateModel(provider="replay_provider", model="test-triage-model")],
        schema_retries=2,
    )
    policy = RoutingPolicy({TaskClass.CLASSIFICATION: rule})
    return ModelRouter(providers={"replay_provider": replay}, policy=policy)


@pytest.mark.asyncio
async def test_triage_agent_auth_attack_representative_case(
    database: Database, tmp_path: Path
) -> None:
    """Representative Case 1: Authentication attack triage with model-structured reasoning."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=True,
    )
    log_content = (
        "Mar 10 03:10:55 web01 sshd[1230]: Invalid user scanner from 203.0.113.55 port 44110 ssh2\n"
        "Mar 10 03:11:18 web01 sshd[1238]: Accepted password for deploy from 203.0.113.55 port 44126 ssh2\n"
    )
    art_file = tmp_path / "artifacts" / "auth.log"
    art_file.parent.mkdir(parents=True, exist_ok=True)
    art_file.write_text(log_content, encoding="utf-8")

    llm_analysis = TriageAnalysis(
        classification=InputClassification(
            category="authentication_attack",
            summary="Detected external SSH brute-force attempt leading to accepted login on web01.",
            confidence=0.95,
            initial_severity=Severity.HIGH,
            reasoning="Inbound SSH connections from public IP 203.0.113.55 targeted deploy account and succeeded.",
        ),
        entities=[
            ExtractedEntity(
                entity_type="ip",
                value="203.0.113.55",
                role="attacker",
                context="Source IP for SSH brute-force",
            ),
            ExtractedEntity(
                entity_type="user",
                value="deploy",
                role="compromised_user",
                context="Account with accepted SSH session",
            ),
            ExtractedEntity(
                entity_type="host",
                value="web01",
                role="target",
                context="Server targeted by connection",
            ),
        ],
        indicators=[
            IndicatorAssessment(
                indicator_type="ip",
                value="203.0.113.55",
                scope="global",
                threat_assessment="suspicious_inbound",
                is_malicious_candidate=True,
            )
        ],
        evidence_gaps=[
            EvidenceGap(
                description="Threat reputation and ISP attribution for 203.0.113.55 is unknown",
                required_source="threat_intelligence_enrichment",
                importance="high",
            ),
            EvidenceGap(
                description="Post-authentication command history / process activity not captured in auth log",
                required_source="auditd_or_process_logs",
                importance="high",
            ),
        ],
        investigation_plan=[
            PlannedTaskProposal(
                task_type="log_analysis",
                rationale="Evaluate brute-force and privilege escalation rules over full auth log",
                priority=1,
            ),
            PlannedTaskProposal(
                task_type="threat_intelligence",
                rationale="Check reputation of attacker IP 203.0.113.55",
                priority=2,
            ),
            PlannedTaskProposal(
                task_type="reporting",
                rationale="Compile synthesized findings and risk score",
                priority=3,
            ),
        ],
    )

    router = _make_triage_router(llm_analysis.model_dump_json())

    async with database.session() as session:
        inv = Investigation(
            title="Web01 Incident Triage",
            target_type="log",
            target_value="auth.log",
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv.id,
            kind="linux_auth_log",
            original_filename="auth.log",
            sha256="a" * 64,
            size_bytes=len(log_content),
            storage_path=str(art_file),
        )
        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t1",
            agent_name="triage",
            agent_version="2.0.0",
            status="running",
        )
        session.add_all([art, agent_run])
        await session.flush()

        store = EvidenceStore(session, inv.id)
        runner = ToolRunner(
            session=session,
            investigation_id=inv.id,
            registry=build_default_registry(),
            store=store,
            artifact_root=tmp_path / "artifacts",
        )
        ctx = AgentContext(
            investigation=inv,
            artifacts=[art],
            session=session,
            store=store,
            tools=runner,
            settings=settings,
            agent_run_id=agent_run.id,
            router=router,
        )

        agent = TriageAgent()
        result = await agent.run(ctx, {})

        assert result.succeeded
        assert "authentication_attack" in result.summary
        assert result.metrics["classification_category"] == "authentication_attack"
        assert result.metrics["entities_extracted"] == 3
        assert result.metrics["indicators_total"] >= 1
        assert len(result.next_actions) == 3
        assert "log_analysis" in result.next_actions[0]

        # Verify findings persisted in database
        findings = (
            await session.scalars(sa.select(Finding).where(Finding.investigation_id == inv.id))
        ).all()
        assert len(findings) >= 3  # Fact (IOCs), Inference (Classification), Unknown (Gaps)

        fact_findings = [f for f in findings if f.assertion_class == AssertionClass.FACT.value]
        inference_findings = [
            f for f in findings if f.assertion_class == AssertionClass.INFERENCE.value
        ]
        unknown_findings = [
            f for f in findings if f.assertion_class == AssertionClass.UNKNOWN.value
        ]

        assert len(fact_findings) >= 1
        assert fact_findings[0].detection_rule == "triage.ioc_inventory"
        assert len(fact_findings[0].evidence_ids) > 0

        assert len(inference_findings) >= 1
        assert "Authentication Attack" in inference_findings[0].title
        assert inference_findings[0].severity == Severity.INFO.value
        assert "203.0.113.55" in (inference_findings[0].reasoning or "")

        assert len(unknown_findings) >= 2
        for uf in unknown_findings:
            assert uf.severity == Severity.INFO.value  # G4 bounded

        # Verify LLM telemetry recorded
        traces = (
            await session.scalars(
                sa.select(ModelExecution).where(ModelExecution.investigation_id == inv.id)
            )
        ).all()
        assert len(traces) == 1
        assert traces[0].task_class == TaskClass.CLASSIFICATION.value
        assert traces[0].schema_valid is True


@pytest.mark.asyncio
async def test_triage_agent_phishing_url_representative_case(
    database: Database, tmp_path: Path
) -> None:
    """Representative Case 2: Phishing URL target triage."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=True,
    )
    target_url = "http://login-verify-account.bank-security.com/auth/login.php"

    llm_analysis = TriageAnalysis(
        classification=InputClassification(
            category="phishing_attempt",
            summary="Target URL mimics banking authentication portal on suspicious subdomain.",
            confidence=0.92,
            initial_severity=Severity.HIGH,
            reasoning="Domain bank-security.com is not authoritative for legitimate banking services.",
        ),
        entities=[
            ExtractedEntity(
                entity_type="url",
                value=target_url,
                role="infrastructure",
                context="Phishing landing page URL",
            ),
            ExtractedEntity(
                entity_type="domain",
                value="login-verify-account.bank-security.com",
                role="infrastructure",
                context="Deceptive hostname",
            ),
        ],
        indicators=[
            IndicatorAssessment(
                indicator_type="url",
                value=target_url,
                scope="global",
                threat_assessment="phishing_url_candidate",
                is_malicious_candidate=True,
            )
        ],
        evidence_gaps=[
            EvidenceGap(
                description="Domain WHOIS registration age and SSL certificate issuer unverified",
                required_source="threat_intelligence_enrichment",
                importance="high",
            )
        ],
        investigation_plan=[
            PlannedTaskProposal(
                task_type="threat_intelligence",
                rationale="Query domain reputation and passive DNS records",
                priority=1,
            ),
            PlannedTaskProposal(
                task_type="reporting",
                rationale="Document phishing indicator inventory",
                priority=2,
            ),
        ],
    )

    router = _make_triage_router(llm_analysis.model_dump_json())

    async with database.session() as session:
        inv = Investigation(
            title="Suspicious Phishing URL Investigation",
            target_type="url",
            target_value=target_url,
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t1",
            agent_name="triage",
            agent_version="2.0.0",
            status="running",
        )
        session.add(agent_run)
        await session.flush()

        store = EvidenceStore(session, inv.id)
        runner = ToolRunner(
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
            store=store,
            tools=runner,
            settings=settings,
            agent_run_id=agent_run.id,
            router=router,
        )

        agent = TriageAgent()
        result = await agent.run(ctx, {})

        assert result.succeeded
        assert "phishing_attempt" in result.summary
        assert result.metrics["indicators_total"] >= 1
        assert len(result.next_actions) == 2


@pytest.mark.asyncio
async def test_triage_agent_malware_hash_representative_case(
    database: Database, tmp_path: Path
) -> None:
    """Representative Case 3: Malware Hash target triage."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=True,
    )
    target_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    llm_analysis = TriageAnalysis(
        classification=InputClassification(
            category="malware_delivery",
            summary="Target SHA-256 hash submitted for suspicious payload triage.",
            confidence=0.88,
            initial_severity=Severity.MEDIUM,
            reasoning="Unverified binary sample hash requiring threat intel and YARA scanning.",
        ),
        entities=[
            ExtractedEntity(
                entity_type="hash",
                value=target_hash,
                role="suspicious_file",
                context="SHA-256 binary hash",
            )
        ],
        indicators=[
            IndicatorAssessment(
                indicator_type="hash",
                value=target_hash,
                scope="global",
                threat_assessment="unverified_reputation",
                is_malicious_candidate=True,
            )
        ],
        evidence_gaps=[
            EvidenceGap(
                description="AV detection engine verdicts and malware family attribution unknown",
                required_source="threat_intelligence_enrichment",
                importance="high",
            )
        ],
        investigation_plan=[
            PlannedTaskProposal(
                task_type="threat_intelligence",
                rationale="Lookup SHA-256 in threat intel engines",
                priority=1,
            )
        ],
    )

    router = _make_triage_router(llm_analysis.model_dump_json())

    async with database.session() as session:
        inv = Investigation(
            title="Malware Hash Triage",
            target_type="hash",
            target_value=target_hash,
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t1",
            agent_name="triage",
            agent_version="2.0.0",
            status="running",
        )
        session.add(agent_run)
        await session.flush()

        store = EvidenceStore(session, inv.id)
        runner = ToolRunner(
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
            store=store,
            tools=runner,
            settings=settings,
            agent_run_id=agent_run.id,
            router=router,
        )

        agent = TriageAgent()
        result = await agent.run(ctx, {})

        assert result.succeeded
        assert "malware_delivery" in result.summary
        assert result.metrics["indicators_total"] == 1


@pytest.mark.asyncio
async def test_triage_agent_deterministic_fallback_when_no_router(
    database: Database, tmp_path: Path
) -> None:
    """Representative Case 4: Graceful deterministic fallback when router is None."""
    settings = Settings(artifact_dir=tmp_path / "artifacts", secret_key=SecretStr("secret"))
    log_content = "Mar 10 03:10:55 web01 sshd[1230]: Failed password for root from 198.51.100.2 port 22 ssh2\n"
    art_file = tmp_path / "artifacts" / "auth.log"
    art_file.parent.mkdir(parents=True, exist_ok=True)
    art_file.write_text(log_content, encoding="utf-8")

    async with database.session() as session:
        inv = Investigation(
            title="Fallback Triage Test",
            target_type="log",
            target_value="auth.log",
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv.id,
            kind="linux_auth_log",
            original_filename="auth.log",
            sha256="b" * 64,
            size_bytes=len(log_content),
            storage_path=str(art_file),
        )
        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t1",
            agent_name="triage",
            agent_version="2.0.0",
            status="running",
        )
        session.add_all([art, agent_run])
        await session.flush()

        store = EvidenceStore(session, inv.id)
        runner = ToolRunner(
            session=session,
            investigation_id=inv.id,
            registry=build_default_registry(),
            store=store,
            artifact_root=tmp_path / "artifacts",
        )
        # Pass router=None
        ctx = AgentContext(
            investigation=inv,
            artifacts=[art],
            session=session,
            store=store,
            tools=runner,
            settings=settings,
            agent_run_id=agent_run.id,
            router=None,
        )

        agent = TriageAgent()
        result = await agent.run(ctx, {})

        assert result.succeeded
        assert "authentication_attack" in result.summary
        assert result.metrics["classification_category"] == "authentication_attack"
        assert result.metrics["indicators_total"] >= 1
        assert len(result.next_actions) >= 1

        findings = (
            await session.scalars(sa.select(Finding).where(Finding.investigation_id == inv.id))
        ).all()
        assert len(findings) >= 2


@pytest.mark.asyncio
async def test_triage_agent_structured_repair_retry(database: Database, tmp_path: Path) -> None:
    """Representative Case 5: Model output schema repair loop in Triage."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=True,
    )
    target_ip = "198.51.100.99"

    # First attempt: invalid (confidence > 1.0 violates schema ge=0.0, le=1.0)
    invalid_output = json.dumps(
        {
            "classification": {
                "category": "reconnaissance",
                "summary": "Port scanner",
                "confidence": 1.5,
                "initial_severity": "low",
                "reasoning": "Detected scan",
            },
            "entities": [],
            "indicators": [],
            "evidence_gaps": [],
            "investigation_plan": [],
        }
    )
    valid_output = json.dumps(
        {
            "classification": {
                "category": "reconnaissance",
                "summary": "Port scanner targeting external perimeter",
                "confidence": 0.85,
                "initial_severity": "low",
                "reasoning": "Detected repetitive probes",
            },
            "entities": [
                {
                    "entity_type": "ip",
                    "value": target_ip,
                    "role": "attacker",
                    "context": "Scan source",
                }
            ],
            "indicators": [],
            "evidence_gaps": [],
            "investigation_plan": [
                {"task_type": "reporting", "rationale": "Summarize recon", "priority": 1}
            ],
        }
    )

    replay = ReplayProvider(name="replay_repair")
    responses = [invalid_output, valid_output]

    async def mock_complete(req: LLMRequest, model: str) -> LLMResponse:
        content = responses.pop(0)
        return LLMResponse(
            content=content,
            usage=LLMUsage(prompt_tokens=20, completion_tokens=20, total_tokens=40),
            finish_reason=FinishReason.STOP,
            model=model,
            provider=replay.name,
        )

    replay.complete = mock_complete  # type: ignore[assignment,method-assign]

    rule = TaskRoutingRule(
        task_class=TaskClass.CLASSIFICATION,
        candidates=[CandidateModel(provider="replay_repair", model="test-repair-model")],
        schema_retries=2,
    )
    policy = RoutingPolicy({TaskClass.CLASSIFICATION: rule})
    router = ModelRouter(providers={"replay_repair": replay}, policy=policy)

    async with database.session() as session:
        inv = Investigation(
            title="Recon IP Triage",
            target_type="ip",
            target_value=target_ip,
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t1",
            agent_name="triage",
            agent_version="2.0.0",
            status="running",
        )
        session.add(agent_run)
        await session.flush()

        store = EvidenceStore(session, inv.id)
        runner = ToolRunner(
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
            store=store,
            tools=runner,
            settings=settings,
            agent_run_id=agent_run.id,
            router=router,
        )

        agent = TriageAgent()
        result = await agent.run(ctx, {})

        assert result.succeeded
        assert result.metrics["classification_category"] == "reconnaissance"
        assert result.metrics["classification_confidence"] == 0.85


@pytest.mark.asyncio
async def test_triage_agent_flag_disabled_uses_deterministic_fallback(
    database: Database, tmp_path: Path
) -> None:
    """When ACIP_ENABLE_LLM_TRIAGE=False (default), TriageAgent bypasses ModelRouter."""
    settings = Settings(
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("secret"),
        enable_llm_triage=False,
    )
    # Router whose complete() raises an error if called
    replay = ReplayProvider(
        name="failing_replay", simulated_errors=[LLMError("Should not be called")]
    )
    rule = TaskRoutingRule(
        task_class=TaskClass.CLASSIFICATION,
        candidates=[CandidateModel(provider="failing_replay", model="test-model")],
    )
    policy = RoutingPolicy({TaskClass.CLASSIFICATION: rule})
    router = ModelRouter(providers={"failing_replay": replay}, policy=policy)

    async with database.session() as session:
        inv = Investigation(
            title="Disabled Flag Test",
            target_type="ip",
            target_value="192.0.2.1",
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t1",
            agent_name="triage",
            agent_version="2.0.0",
            status="running",
        )
        session.add(agent_run)
        await session.flush()

        store = EvidenceStore(session, inv.id)
        runner = ToolRunner(
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
            store=store,
            tools=runner,
            settings=settings,
            agent_run_id=agent_run.id,
            router=router,
        )

        agent = TriageAgent()
        result = await agent.run(ctx, {})

        assert result.succeeded
        assert "incident_triage" in result.summary
        # Verify no LLM traces recorded
        traces = (
            await session.scalars(
                sa.select(ModelExecution).where(ModelExecution.investigation_id == inv.id)
            )
        ).all()
        assert len(traces) == 0
