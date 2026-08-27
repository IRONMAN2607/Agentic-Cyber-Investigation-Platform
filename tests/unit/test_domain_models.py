from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from acip.core.evidence.contracts import (
    FindingEvidenceDraft,
    HypothesisDraft,
    HypothesisGapDraft,
    ModelExecutionDraft,
)
from acip.types import EvidenceRole, FinishReason, HypothesisStatus, TaskStatus


def test_hypothesis_draft_valid() -> None:
    e1 = uuid.uuid4()
    e2 = uuid.uuid4()
    draft = HypothesisDraft(
        statement="Attacker attempted credential stuffing against multiple accounts",
        refutation_condition="All failed logins originated from single internal service account with misconfigured cron",
        confidence=0.8,
        supporting_evidence_ids=[e1],
        contradicting_evidence_ids=[e2],
    )
    assert draft.statement.startswith("Attacker attempted")
    assert "service account" in draft.refutation_condition
    assert draft.confidence == 0.8
    assert len(draft.supporting_evidence_ids) == 1
    assert len(draft.contradicting_evidence_ids) == 1


def test_hypothesis_draft_invariant_g3_refutation_required() -> None:
    with pytest.raises(ValidationError):
        HypothesisDraft(
            statement="Valid statement",
            refutation_condition="   ",  # blank string must be rejected
        )


def test_finding_evidence_draft_roles() -> None:
    fid = uuid.uuid4()
    eid = uuid.uuid4()
    draft = FindingEvidenceDraft(
        finding_id=fid,
        evidence_id=eid,
        role=EvidenceRole.CONTRADICTS,
    )
    assert draft.role == EvidenceRole.CONTRADICTS
    assert draft.finding_id == fid


def test_model_execution_draft() -> None:
    draft = ModelExecutionDraft(
        task_class="triage",
        provider="anthropic",
        model="claude-3-5-sonnet",
        prompt_name="triage_initial",
        prompt_version="1.0.0",
        tokens_in=1500,
        tokens_out=300,
        latency_ms=850,
        cost_estimate_usd=0.009,
        finish_reason=FinishReason.STOP,
    )
    assert draft.tokens_in == 1500
    assert draft.finish_reason == FinishReason.STOP
    assert draft.cost_estimate_usd == 0.009


def test_hypothesis_gap_draft() -> None:
    gap = HypothesisGapDraft(
        description="Missing firewall egress log for destination port 4444",
        required_tool="zeek_conn_parser",
    )
    assert gap.required_tool == "zeek_conn_parser"


def test_status_enums() -> None:
    assert HypothesisStatus.PROPOSED.value == "proposed"
    assert HypothesisStatus.SUPPORTED.value == "supported"
    assert HypothesisStatus.REFUTED.value == "refuted"
    assert HypothesisStatus.UNRESOLVED.value == "unresolved"

    assert TaskStatus.PENDING.value == "pending"
    assert TaskStatus.RUNNING.value == "running"
    assert TaskStatus.SUCCEEDED.value == "succeeded"
    assert TaskStatus.FAILED.value == "failed"
    assert TaskStatus.CANCELLED.value == "cancelled"
