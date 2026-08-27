"""Append-only evidence store and grounding enforcement.

This module is where the platform's central design rule is made mechanical:

    LLMs reason over evidence. Deterministic tools produce evidence.

Evidence rows carry provenance. A non-NULL ``tool_run_id`` means the observation
came from a deterministic tool. The grounding invariants below use that to stop
an agent from asserting a FACT it merely believes.

Invariants (docs/evidence-model.md)
-----------------------------------
G0  Every cited evidence id must exist and belong to the same investigation.
G1  ``FACT`` requires at least one cited evidence row with ``tool_run_id`` set.
G2  ``INFERENCE`` requires at least one cited evidence row and stated reasoning.
G3  ``HYPOTHESIS`` requires stated reasoning describing what would confirm or
    refute it (enforced via refutation_condition).
G4  ``UNKNOWN`` must not claim a severity above ``INFO``.

A violation raises :class:`~acip.errors.GroundingError`. That is deliberate:
these are agent bugs, and silently downgrading them would hide exactly the
behaviour the research is trying to measure.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from acip.core.evidence.contracts import (
    EvidenceDraft,
    FindingDraft,
    HypothesisDraft,
    HypothesisGapDraft,
    ModelExecutionDraft,
)
from acip.db.models import (
    Evidence,
    Finding,
    FindingEvidence,
    Hypothesis,
    HypothesisEvidence,
    HypothesisGap,
    ModelExecution,
)
from acip.errors import GroundingError
from acip.logging import get_logger
from acip.types import AssertionClass, EvidenceRole, Severity

logger = get_logger(__name__)


class EvidenceStore:
    """Writes evidence and findings for a single investigation."""

    def __init__(self, session: AsyncSession, investigation_id: uuid.UUID) -> None:
        self._session = session
        self._investigation_id = investigation_id

    async def add_evidence(
        self,
        drafts: list[EvidenceDraft],
        *,
        source_tool: str,
        artifact_id: uuid.UUID | None = None,
        tool_run_id: uuid.UUID | None = None,
        agent_run_id: uuid.UUID | None = None,
    ) -> list[Evidence]:
        """Persist drafts, skipping observations already recorded.

        Deduplication is by content hash within the investigation, so re-running
        a tool over the same artifact does not inflate the evidence count.
        """
        if not drafts:
            return []

        hashed = [(draft, draft.content_hash(source_tool)) for draft in drafts]
        candidate_hashes = {content_hash for _, content_hash in hashed}

        existing: set[str] = set(
            (
                await self._session.scalars(
                    sa.select(Evidence.content_hash).where(
                        Evidence.investigation_id == self._investigation_id,
                        Evidence.content_hash.in_(candidate_hashes),
                    )
                )
            ).all()
        )

        created: list[Evidence] = []
        seen_in_batch: set[str] = set()
        for draft, content_hash in hashed:
            if content_hash in existing or content_hash in seen_in_batch:
                continue
            seen_in_batch.add(content_hash)

            row = Evidence(
                investigation_id=self._investigation_id,
                kind=draft.kind.value,
                source_tool=source_tool,
                observed_at=draft.observed_at,
                time_confidence=draft.time_confidence.value,
                data=draft.data,
                entities={
                    "refs": [
                        entity.model_dump(mode="json") for entity in draft.normalized_entities()
                    ]
                },
                confidence=draft.confidence,
                content_hash=content_hash,
                artifact_id=artifact_id,
                tool_run_id=tool_run_id,
                agent_run_id=agent_run_id,
            )
            self._session.add(row)
            created.append(row)

        await self._session.flush()
        logger.info(
            "evidence recorded",
            extra={
                "source_tool": source_tool,
                "created_count": len(created),
                "duplicates_skipped": len(drafts) - len(created),
            },
        )
        return created

    async def add_finding(
        self, draft: FindingDraft, *, agent_run_id: uuid.UUID | None = None
    ) -> Finding:
        """Validate a claim against the grounding invariants and persist it."""
        cited = await self._load_cited_evidence(draft.evidence_ids)
        self._enforce_grounding(draft, cited)

        row = Finding(
            investigation_id=self._investigation_id,
            title=draft.title,
            description=draft.description,
            assertion_class=draft.assertion_class.value,
            severity=draft.severity.value,
            confidence=draft.confidence,
            evidence_ids=[str(evidence_id) for evidence_id in draft.evidence_ids],
            reasoning=draft.reasoning,
            detection_rule=draft.detection_rule,
            agent_run_id=agent_run_id,
        )
        self._session.add(row)
        await self._session.flush()

        # Link finding citations in relational join table
        for evidence_id in draft.evidence_ids:
            fe = FindingEvidence(
                finding_id=row.id,
                evidence_id=evidence_id,
                role=EvidenceRole.SUPPORTS.value,
            )
            self._session.add(fe)
        await self._session.flush()

        logger.info(
            "finding recorded",
            extra={
                "finding": row.display_id,
                "assertion_class": draft.assertion_class.value,
                "severity": draft.severity.value,
                "evidence_count": len(draft.evidence_ids),
            },
        )
        return row

    async def add_hypothesis(
        self, draft: HypothesisDraft, *, agent_run_id: uuid.UUID | None = None
    ) -> Hypothesis:
        """Validate a hypothesis and persist it with supporting/contradicting links."""
        # Enforce G3: refutation condition must be non-empty
        if not (draft.refutation_condition or "").strip():
            raise GroundingError(
                "a HYPOTHESIS must state a refutation condition (Invariant G3)",
                detail={"invariant": "G3", "statement": draft.statement},
            )

        # Validate cited evidence exists
        all_cited = list(draft.supporting_evidence_ids) + list(draft.contradicting_evidence_ids)
        if all_cited:
            await self._load_cited_evidence(all_cited)

        row = Hypothesis(
            investigation_id=self._investigation_id,
            statement=draft.statement,
            confidence=draft.confidence,
            refutation_condition=draft.refutation_condition,
            agent_run_id=agent_run_id,
        )
        self._session.add(row)
        await self._session.flush()

        # Record relational links
        for eid in draft.supporting_evidence_ids:
            self._session.add(
                HypothesisEvidence(
                    hypothesis_id=row.id,
                    evidence_id=eid,
                    role=EvidenceRole.SUPPORTS.value,
                )
            )
        for eid in draft.contradicting_evidence_ids:
            self._session.add(
                HypothesisEvidence(
                    hypothesis_id=row.id,
                    evidence_id=eid,
                    role=EvidenceRole.CONTRADICTS.value,
                )
            )
        await self._session.flush()

        logger.info(
            "hypothesis recorded",
            extra={
                "hypothesis": row.display_id,
                "confidence": row.confidence,
            },
        )
        return row

    async def add_hypothesis_gap(
        self, hypothesis_id: uuid.UUID, draft: HypothesisGapDraft
    ) -> HypothesisGap:
        """Record an explicit knowledge gap preventing hypothesis resolution."""
        gap = HypothesisGap(
            hypothesis_id=hypothesis_id,
            description=draft.description,
            required_tool=draft.required_tool,
        )
        self._session.add(gap)
        await self._session.flush()
        return gap

    async def record_model_execution(
        self,
        draft: ModelExecutionDraft,
        *,
        agent_run_id: uuid.UUID | None = None,
        task_id: str | None = None,
    ) -> ModelExecution:
        """Record an immutable LLM execution trace."""
        call = ModelExecution(
            investigation_id=self._investigation_id,
            agent_run_id=agent_run_id,
            task_id=task_id,
            task_class=draft.task_class,
            provider=draft.provider,
            model=draft.model,
            prompt_name=draft.prompt_name,
            prompt_version=draft.prompt_version,
            tokens_in=draft.tokens_in,
            tokens_out=draft.tokens_out,
            latency_ms=draft.latency_ms,
            cost_estimate_usd=draft.cost_estimate_usd,
            finish_reason=draft.finish_reason.value,
            retries=draft.retries,
            schema_valid=draft.schema_valid,
            fallback_from=draft.fallback_from,
            temperature=draft.temperature,
            seed=draft.seed,
            nondeterminism_risk=draft.nondeterminism_risk,
            grounding_violations=draft.grounding_violations,
        )
        self._session.add(call)
        await self._session.flush()
        return call

    async def _load_cited_evidence(self, evidence_ids: list[uuid.UUID]) -> list[Evidence]:
        """Fetch cited evidence, enforcing G0."""
        if not evidence_ids:
            return []

        rows = list(
            (
                await self._session.scalars(
                    sa.select(Evidence).where(
                        Evidence.investigation_id == self._investigation_id,
                        Evidence.id.in_(evidence_ids),
                    )
                )
            ).all()
        )
        found = {row.id for row in rows}
        missing = [str(eid) for eid in evidence_ids if eid not in found]
        if missing:
            raise GroundingError(
                "finding cites evidence that does not exist in this investigation",
                detail={"missing_evidence_ids": missing},
            )
        return rows

    @staticmethod
    def _enforce_grounding(draft: FindingDraft, cited: list[Evidence]) -> None:
        """Apply G1-G4."""
        match draft.assertion_class:
            case AssertionClass.FACT:
                if not any(row.tool_run_id is not None for row in cited):
                    raise GroundingError(
                        "a FACT must cite evidence produced by a deterministic tool",
                        detail={
                            "invariant": "G1",
                            "finding": draft.title,
                            "cited_evidence": len(cited),
                        },
                    )
            case AssertionClass.INFERENCE:
                if not cited:
                    raise GroundingError(
                        "an INFERENCE must cite at least one piece of evidence",
                        detail={"invariant": "G2", "finding": draft.title},
                    )
                if not (draft.reasoning or "").strip():
                    raise GroundingError(
                        "an INFERENCE must state the reasoning connecting evidence to claim",
                        detail={"invariant": "G2", "finding": draft.title},
                    )
            case AssertionClass.HYPOTHESIS:
                if not (draft.reasoning or "").strip():
                    raise GroundingError(
                        "a HYPOTHESIS must state what would confirm or refute it",
                        detail={"invariant": "G3", "finding": draft.title},
                    )
            case AssertionClass.UNKNOWN:
                if draft.severity.rank > Severity.INFO.rank:
                    raise GroundingError(
                        "an UNKNOWN cannot carry a severity above INFO",
                        detail={
                            "invariant": "G4",
                            "finding": draft.title,
                            "severity": draft.severity.value,
                        },
                    )

    # --- Read paths ---------------------------------------------------------

    async def list_evidence(self, *, limit: int = 500, offset: int = 0) -> list[Evidence]:
        return list(
            (
                await self._session.scalars(
                    sa.select(Evidence)
                    .where(Evidence.investigation_id == self._investigation_id)
                    .order_by(
                        Evidence.observed_at.is_(None),
                        Evidence.observed_at,
                        Evidence.collected_at,
                    )
                    .limit(limit)
                    .offset(offset)
                )
            ).all()
        )

    async def list_findings(self) -> list[Finding]:
        return list(
            (
                await self._session.scalars(
                    sa.select(Finding)
                    .where(Finding.investigation_id == self._investigation_id)
                    .order_by(Finding.created_at)
                )
            ).all()
        )

    async def list_hypotheses(self) -> list[Hypothesis]:
        return list(
            (
                await self._session.scalars(
                    sa.select(Hypothesis)
                    .where(Hypothesis.investigation_id == self._investigation_id)
                    .order_by(Hypothesis.created_at)
                )
            ).all()
        )

    async def count_evidence(self) -> int:
        result = await self._session.scalar(
            sa.select(sa.func.count())
            .select_from(Evidence)
            .where(Evidence.investigation_id == self._investigation_id)
        )
        return int(result or 0)
