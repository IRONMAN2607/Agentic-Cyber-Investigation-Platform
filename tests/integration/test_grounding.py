from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from acip.core.evidence.contracts import EntityRef, EvidenceDraft, FindingDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import Investigation, ToolRun
from acip.db.session import Database
from acip.errors import GroundingError
from acip.types import (
    AssertionClass,
    EntityType,
    EvidenceKind,
    RunStatus,
    SandboxTier,
    Severity,
    TimeConfidence,
)


def _draft_evidence(host: str = "web01") -> EvidenceDraft:
    return EvidenceDraft(
        kind=EvidenceKind.AUTH_EVENT,
        data={"host": host, "event": "test"},
        observed_at=dt.datetime.now(dt.UTC),
        time_confidence=TimeConfidence.EXACT,
        entities=[EntityRef(type=EntityType.HOST, value=host, role="target")],
    )


async def _create_tool_run(session: AsyncSession, investigation_id: uuid.UUID) -> ToolRun:
    tool_run = ToolRun(
        investigation_id=investigation_id,
        tool_name="test_tool",
        tool_version="1.0.0",
        sandbox_tier=SandboxTier.T0_IN_PROCESS.value,
        status=RunStatus.SUCCEEDED.value,
    )
    session.add(tool_run)
    await session.flush()
    return tool_run


async def test_grounding_invariant_g1_fact_requires_deterministic_tool_evidence(
    database: Database,
) -> None:
    async with database.session() as session:
        inv = Investigation(title="Test Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()
        store = EvidenceStore(session, inv.id)

        # G1: FACT with empty evidence_ids must fail
        f_draft_empty = FindingDraft(
            title="Claimed Fact Without Evidence",
            description="This should fail",
            assertion_class=AssertionClass.FACT,
            severity=Severity.HIGH,
            evidence_ids=[],
        )
        with pytest.raises(
            GroundingError, match="a FACT must cite evidence produced by a deterministic tool"
        ):
            await store.add_finding(f_draft_empty)

        # G1: FACT citing evidence without a tool_run_id must also fail
        ev_without_tool = await store.add_evidence(
            [_draft_evidence()], source_tool="manual", tool_run_id=None
        )
        f_draft_no_tool = FindingDraft(
            title="Fact Citing Non-Tool Evidence",
            description="This should fail",
            assertion_class=AssertionClass.FACT,
            severity=Severity.HIGH,
            evidence_ids=[ev_without_tool[0].id],
        )
        with pytest.raises(
            GroundingError, match="a FACT must cite evidence produced by a deterministic tool"
        ):
            await store.add_finding(f_draft_no_tool)


async def test_grounding_invariant_g2_inference_requires_evidence_and_reasoning(
    database: Database,
) -> None:
    async with database.session() as session:
        inv = Investigation(title="Test Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()
        store = EvidenceStore(session, inv.id)
        tr = await _create_tool_run(session, inv.id)

        # INFERENCE with no evidence must fail
        f_no_ev = FindingDraft(
            title="Inference Without Evidence",
            description="Invalid",
            assertion_class=AssertionClass.INFERENCE,
            severity=Severity.HIGH,
            evidence_ids=[],
            reasoning="Some reasoning",
        )
        with pytest.raises(
            GroundingError, match="an INFERENCE must cite at least one piece of evidence"
        ):
            await store.add_finding(f_no_ev)

        # INFERENCE with evidence but empty reasoning must fail
        ev_rows = await store.add_evidence(
            [_draft_evidence()], source_tool="test_tool", tool_run_id=tr.id
        )
        f_no_reasoning = FindingDraft(
            title="Inference Without Reasoning",
            description="Invalid",
            assertion_class=AssertionClass.INFERENCE,
            severity=Severity.HIGH,
            evidence_ids=[ev_rows[0].id],
            reasoning="",
        )
        with pytest.raises(GroundingError, match="an INFERENCE must state the reasoning"):
            await store.add_finding(f_no_reasoning)


async def test_grounding_invariant_g3_hypothesis_requires_falsification_criteria(
    database: Database,
) -> None:
    async with database.session() as session:
        inv = Investigation(title="Test Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()
        store = EvidenceStore(session, inv.id)

        f_hypo_no_reasoning = FindingDraft(
            title="Hypothesis Without Reasoning",
            description="Invalid",
            assertion_class=AssertionClass.HYPOTHESIS,
            severity=Severity.HIGH,
            reasoning="",
        )
        with pytest.raises(
            GroundingError, match="a HYPOTHESIS must state what would confirm or refute it"
        ):
            await store.add_finding(f_hypo_no_reasoning)


async def test_grounding_invariant_g4_unknown_severity_bounded(
    database: Database,
) -> None:
    async with database.session() as session:
        inv = Investigation(title="Test Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()
        store = EvidenceStore(session, inv.id)

        f_unknown_high = FindingDraft(
            title="Unknown With High Severity",
            description="Invalid",
            assertion_class=AssertionClass.UNKNOWN,
            severity=Severity.HIGH,
        )
        with pytest.raises(GroundingError, match="an UNKNOWN cannot carry a severity above INFO"):
            await store.add_finding(f_unknown_high)


async def test_grounding_invariant_cross_investigation_isolated(database: Database) -> None:
    async with database.session() as session:
        inv1 = Investigation(title="Inv 1", target_type="log", target_value="auth1.log")
        inv2 = Investigation(title="Inv 2", target_type="log", target_value="auth2.log")
        session.add_all([inv1, inv2])
        await session.flush()

        tr1 = await _create_tool_run(session, inv1.id)
        store1 = EvidenceStore(session, inv1.id)
        store2 = EvidenceStore(session, inv2.id)

        ev_rows1 = await store1.add_evidence(
            [_draft_evidence()], source_tool="test_tool", tool_run_id=tr1.id
        )
        ev1_id = ev_rows1[0].id

        # Attempt to cite inv1 evidence inside inv2
        f_draft = FindingDraft(
            title="Cross-cite fact",
            description="Invalid cross citation",
            assertion_class=AssertionClass.FACT,
            severity=Severity.MEDIUM,
            evidence_ids=[ev1_id],
        )
        with pytest.raises(GroundingError, match="does not exist in this investigation"):
            await store2.add_finding(f_draft)


async def test_valid_fact_with_evidence_persisted(database: Database) -> None:
    async with database.session() as session:
        inv = Investigation(title="Valid Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()
        store = EvidenceStore(session, inv.id)

        tr = await _create_tool_run(session, inv.id)
        ev_rows = await store.add_evidence(
            [_draft_evidence()], source_tool="test_tool", tool_run_id=tr.id
        )
        ev_id = ev_rows[0].id

        f_draft = FindingDraft(
            title="Valid Fact",
            description="Legitimate grounded finding",
            assertion_class=AssertionClass.FACT,
            severity=Severity.HIGH,
            evidence_ids=[ev_id],
        )
        finding = await store.add_finding(f_draft)
        assert finding.id is not None
        assert finding.title == "Valid Fact"
        assert finding.evidence_ids == [str(ev_id)]
