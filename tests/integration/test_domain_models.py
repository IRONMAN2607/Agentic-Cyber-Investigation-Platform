from __future__ import annotations

import datetime as dt

import pytest
import sqlalchemy as sa

from acip.core.evidence.contracts import (
    EvidenceDraft,
    FindingDraft,
    HypothesisDraft,
    HypothesisGapDraft,
    ModelExecutionDraft,
)
from acip.core.evidence.store import EvidenceStore
from acip.db.models import (
    FindingEvidence,
    HypothesisEvidence,
    Investigation,
    ModelExecution,
    TaskRun,
    ToolRun,
)
from acip.db.session import Database
from acip.types import (
    AssertionClass,
    EvidenceKind,
    EvidenceRole,
    FinishReason,
    HypothesisStatus,
    RunStatus,
    Severity,
    TaskStatus,
)


async def test_task_run_lifecycle(database: Database) -> None:
    async with database.session() as session:
        inv = Investigation(title="Task Lifecycle Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()

        task = TaskRun(
            investigation_id=inv.id,
            task_id="task-001",
            task_type="triage",
            status=TaskStatus.RUNNING.value,
            rationale="Initial artifact triage and indicator extraction",
            inputs={"artifact_count": 1},
        )
        session.add(task)
        await session.commit()

    async with database.session() as session:
        loaded = await session.scalar(sa.select(TaskRun).where(TaskRun.task_id == "task-001"))
        assert loaded is not None
        assert loaded.status_enum == TaskStatus.RUNNING

        # Finish task
        loaded.status = TaskStatus.SUCCEEDED.value
        loaded.duration_ms = 450
        loaded.outputs = {"indicators_extracted": 3}
        await session.commit()

    async with database.session() as session:
        reloaded = await session.scalar(sa.select(TaskRun).where(TaskRun.task_id == "task-001"))
        assert reloaded is not None
        assert reloaded.status_enum == TaskStatus.SUCCEEDED
        assert reloaded.outputs["indicators_extracted"] == 3


async def test_hypotheses_and_evidence_citations(database: Database) -> None:
    async with database.session() as session:
        inv = Investigation(title="Hypo Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()

        store = EvidenceStore(session, inv.id)

        # 1. Add tool run and evidence
        tool_run = ToolRun(
            investigation_id=inv.id,
            tool_name="auth_log_parser",
            tool_version="1.0.0",
            sandbox_tier="t0_in_process",
            status=RunStatus.SUCCEEDED.value,
        )
        session.add(tool_run)
        await session.flush()

        evs = await store.add_evidence(
            [
                EvidenceDraft(
                    kind=EvidenceKind.AUTH_EVENT,
                    data={"event": "failed_login", "user": "admin", "src_ip": "203.0.113.195"},
                    observed_at=dt.datetime.now(dt.UTC),
                ),
                EvidenceDraft(
                    kind=EvidenceKind.AUTH_EVENT,
                    data={"event": "accepted_login", "user": "admin", "src_ip": "198.51.100.22"},
                    observed_at=dt.datetime.now(dt.UTC),
                ),
            ],
            source_tool="auth_log_parser",
            tool_run_id=tool_run.id,
        )
        assert len(evs) == 2

        # 2. Add hypothesis
        hypo = await store.add_hypothesis(
            HypothesisDraft(
                statement="External adversary brute forced admin account and gained unauthorized access",
                refutation_condition="Successful login originated from VPN gateway IP allocated to authorized admin user",
                confidence=0.75,
                supporting_evidence_ids=[evs[0].id],
                contradicting_evidence_ids=[evs[1].id],
            )
        )
        assert hypo.status_enum == HypothesisStatus.PROPOSED
        assert hypo.display_id.startswith("HYP-")

        # 3. Add hypothesis gap
        gap = await store.add_hypothesis_gap(
            hypo.id,
            HypothesisGapDraft(
                description="VPN authentication records for 198.51.100.22 during event window",
                required_tool="vpn_log_parser",
            ),
        )
        assert gap.required_tool == "vpn_log_parser"
        assert not gap.resolved

        # Query relational evidence links
        citations = list(
            (
                await session.scalars(
                    sa.select(HypothesisEvidence).where(HypothesisEvidence.hypothesis_id == hypo.id)
                )
            ).all()
        )
        assert len(citations) == 2
        roles = {c.evidence_id: c.role_enum for c in citations}
        assert roles[evs[0].id] == EvidenceRole.SUPPORTS
        assert roles[evs[1].id] == EvidenceRole.CONTRADICTS


async def test_finding_evidence_relational_citation(database: Database) -> None:
    async with database.session() as session:
        inv = Investigation(
            title="Finding Evidence Inv", target_type="log", target_value="auth.log"
        )
        session.add(inv)
        await session.flush()

        store = EvidenceStore(session, inv.id)

        tool_run = ToolRun(
            investigation_id=inv.id,
            tool_name="auth_log_parser",
            tool_version="1.0.0",
            sandbox_tier="t0_in_process",
            status=RunStatus.SUCCEEDED.value,
        )
        session.add(tool_run)
        await session.flush()

        evs = await store.add_evidence(
            [
                EvidenceDraft(
                    kind=EvidenceKind.AUTH_EVENT,
                    data={"event": "failed_login", "user": "root"},
                    observed_at=dt.datetime.now(dt.UTC),
                )
            ],
            source_tool="auth_log_parser",
            tool_run_id=tool_run.id,
        )

        finding = await store.add_finding(
            FindingDraft(
                title="Root SSH Login Attempt",
                description="Detected direct root login attempt",
                assertion_class=AssertionClass.FACT,
                severity=Severity.MEDIUM,
                evidence_ids=[evs[0].id],
            )
        )
        assert finding.display_id.startswith("FND-")

        fe = await session.scalar(
            sa.select(FindingEvidence).where(FindingEvidence.finding_id == finding.id)
        )
        assert fe is not None
        assert fe.evidence_id == evs[0].id
        assert fe.role_enum == EvidenceRole.SUPPORTS


async def test_model_execution_append_only(database: Database) -> None:
    async with database.session() as session:
        inv = Investigation(title="LLM Trace Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()

        store = EvidenceStore(session, inv.id)

        call = await store.record_model_execution(
            ModelExecutionDraft(
                task_class="reporting",
                provider="openai",
                model="gpt-4o",
                prompt_name="report_markdown",
                prompt_version="1.2.0",
                tokens_in=3200,
                tokens_out=600,
                latency_ms=1200,
                cost_estimate_usd=0.015,
                finish_reason=FinishReason.STOP,
            )
        )
        assert call.id is not None
        assert call.finish_reason_enum == FinishReason.STOP

        # Assert append-only: UPDATE and DELETE raise RuntimeError
        call.tokens_out = 9999
        with pytest.raises(RuntimeError, match="append-only"):
            await session.flush()

        await session.rollback()

        loaded = await session.scalar(sa.select(ModelExecution).where(ModelExecution.id == call.id))
        if loaded:
            await session.delete(loaded)
            with pytest.raises(RuntimeError, match="append-only"):
                await session.flush()
