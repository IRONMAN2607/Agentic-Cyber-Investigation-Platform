from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.base import AgentContext
from acip.agents.mitre import MitreMappingAgent
from acip.config import Settings
from acip.core.evidence.contracts import FindingDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AgentRun, Finding, Investigation, ToolRun, User
from acip.db.session import Database
from acip.tools.registry import build_default_registry
from acip.tools.runner import ToolRunner
from acip.types import AssertionClass, EvidenceKind, RunStatus, Severity


@pytest.mark.asyncio
async def test_mitre_mapping_agent_maps_rules_to_techniques(
    database: Database, tmp_path: Path
) -> None:
    settings = Settings(
        environment="test",
        database_url=database.url,
        artifact_dir=tmp_path,
        secret_key=SecretStr("test-secret-at-least-32-bytes-long-hs256"),
    )

    async with database.session() as session:
        user = await session.scalar(sa.select(User))
        assert user is not None

        # Create investigation
        inv = Investigation(
            title="MITRE Test Investigation",
            target_type="log",
            target_value="test.log",
            created_by=user.id,
        )
        session.add(inv)
        await session.flush()

        agent_run = AgentRun(
            investigation_id=inv.id,
            task_id="t-mitre",
            agent_name="mitre",
            agent_version="0.1.0",
            status=RunStatus.RUNNING.value,
        )
        session.add(agent_run)
        await session.flush()

        tool_run = ToolRun(
            investigation_id=inv.id,
            tool_name="test_tool",
            tool_version="0.1.0",
            sandbox_tier="t0_in_process",
            args={},
            status=RunStatus.SUCCEEDED.value,
        )
        session.add(tool_run)
        await session.flush()

        store = EvidenceStore(session, inv.id)

        # Add genuine tool evidence via EvidenceStore
        from acip.core.evidence.contracts import EvidenceDraft

        ev_draft = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={"attempt": 1},
        )
        created_evs = await store.add_evidence(
            [ev_draft],
            source_tool="test_tool",
            tool_run_id=tool_run.id,
        )
        ev = created_evs[0]
        await store.add_finding(
            FindingDraft(
                title="Brute force detected",
                description="Repeated failed authentications observed",
                assertion_class=AssertionClass.INFERENCE,
                severity=Severity.HIGH,
                confidence=0.9,
                evidence_ids=[ev.id],
                reasoning="Evidence shows multiple authentication failures within detection threshold.",
                detection_rule="R-AUTH-001",
            ),
            agent_run_id=agent_run.id,
        )
        # Add a web detection rule finding (e.g. SQLi R-WEB-001)
        await store.add_finding(
            FindingDraft(
                title="SQL injection detected",
                description="SQL syntax injected into URL parameter",
                assertion_class=AssertionClass.INFERENCE,
                severity=Severity.CRITICAL,
                confidence=0.95,
                evidence_ids=[ev.id],
                reasoning="HTTP query payload matched deterministic UNION SELECT signature.",
                detection_rule="R-WEB-001",
            ),
            agent_run_id=agent_run.id,
        )

        tools = ToolRunner(
            session=session,
            investigation_id=inv.id,
            registry=build_default_registry(),
            store=store,
            artifact_root=tmp_path,
        )

        ctx = AgentContext(
            investigation=inv,
            artifacts=[],
            session=session,
            store=store,
            tools=tools,
            settings=settings,
            agent_run_id=agent_run.id,
        )

        agent = MitreMappingAgent()
        result = await agent.run(ctx, {})

        assert result.status == RunStatus.SUCCEEDED
        assert len(result.finding_ids) == 2
        assert result.metrics["rules_mapped"] == 2
        assert "T1110.001" in result.metrics["techniques"]
        assert "T1190" in result.metrics["techniques"]

        # Verify created findings in DB
        mitre_findings = (
            await session.scalars(
                sa.select(Finding).where(
                    Finding.investigation_id == inv.id, Finding.detection_rule == "mitre.mapping"
                )
            )
        ).all()

        assert len(mitre_findings) == 2
        titles = {f.title for f in mitre_findings}
        assert any("T1110.001: Password Guessing" in t for t in titles)
        assert any("T1190: Exploit Public-Facing Application" in t for t in titles)
        for mf in mitre_findings:
            assert mf.assertion_class == AssertionClass.INFERENCE.value
            assert str(ev.id) in mf.evidence_ids
