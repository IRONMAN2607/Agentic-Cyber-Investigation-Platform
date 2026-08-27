"""Provenance survives the deletion of everything it points at.

Regression tests for a defect found by running the code, not reading it: every
provenance foreign key on ``evidence`` used to be ``CASCADE`` or ``SET NULL``, so

* deleting an investigation silently destroyed all of its evidence, and
* deleting a single tool run nulled ``tool_run_id`` on every row it produced.

The second is the more insidious. ``tool_run_id`` being non-NULL is the marker of
deterministic origin that invariant G1 checks at write time, so erasing it
retroactively ungrounded every FACT that cited those rows — with no error, no
audit entry, and no way to tell afterwards. Both changes happened at the database
level, beneath the append-only mapper guards, which never fired.

The fix is ``RESTRICT`` on all four keys: destroying evidence now requires the
audited purge in the investigations router, which records what it removed.

Each case commits the chain first and attempts the deletion in a *separate*
transaction. Doing both in one transaction would let the rollback that follows the
expected ``IntegrityError`` discard the chain as well, and the assertion after it
would pass for the wrong reason.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acip.core.evidence.contracts import EvidenceDraft, FindingDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AgentRun, Artifact, Evidence, Investigation, ToolRun
from acip.db.session import Database
from acip.types import (
    AssertionClass,
    EvidenceKind,
    RunStatus,
    SandboxTier,
    Severity,
    TimeConfidence,
)


@dataclass(frozen=True, slots=True)
class ChainIds:
    """Identifiers for one evidence row with every provenance link populated."""

    investigation_id: uuid.UUID
    artifact_id: uuid.UUID
    tool_run_id: uuid.UUID
    agent_run_id: uuid.UUID
    evidence_id: uuid.UUID


async def _build_chain(database: Database) -> ChainIds:
    """Commit a complete provenance chain and return its ids."""
    async with database.session() as session:
        investigation = Investigation(title="Inv", target_type="log", target_value="auth.log")
        session.add(investigation)
        await session.flush()

        artifact = Artifact(
            investigation_id=investigation.id,
            kind="linux_auth_log",
            original_filename="auth.log",
            sha256="a" * 64,
            size_bytes=128,
            storage_path="artifacts/aa/auth.log",
        )
        agent_run = AgentRun(
            investigation_id=investigation.id,
            task_id="t1",
            agent_name="log_analysis",
            agent_version="1.0.0",
            status=RunStatus.SUCCEEDED.value,
        )
        session.add_all([artifact, agent_run])
        await session.flush()

        tool_run = ToolRun(
            investigation_id=investigation.id,
            agent_run_id=agent_run.id,
            tool_name="linux_auth_log_parser",
            tool_version="1.0.0",
            sandbox_tier=SandboxTier.T0_IN_PROCESS.value,
            status=RunStatus.SUCCEEDED.value,
        )
        session.add(tool_run)
        await session.flush()

        rows = await EvidenceStore(session, investigation.id).add_evidence(
            [
                EvidenceDraft(
                    kind=EvidenceKind.AUTH_EVENT,
                    data={"outcome": "failure"},
                    observed_at=dt.datetime(2026, 3, 10, 3, 11, tzinfo=dt.UTC),
                    time_confidence=TimeConfidence.EXACT,
                )
            ],
            source_tool="linux_auth_log_parser",
            artifact_id=artifact.id,
            tool_run_id=tool_run.id,
            agent_run_id=agent_run.id,
        )
        ids = ChainIds(
            investigation_id=investigation.id,
            artifact_id=artifact.id,
            tool_run_id=tool_run.id,
            agent_run_id=agent_run.id,
            evidence_id=rows[0].id,
        )
    return ids


async def _still_grounded(session: AsyncSession, evidence_id: uuid.UUID) -> bool:
    """Whether the row still carries the G1 deterministic-origin marker."""
    tool_run_id = await session.scalar(
        sa.select(Evidence.tool_run_id).where(Evidence.id == evidence_id)
    )
    return tool_run_id is not None


async def test_deleting_a_tool_run_cannot_erase_the_g1_marker(database: Database) -> None:
    """The defect this file exists for: SET NULL used to unground every citing FACT."""
    ids = await _build_chain(database)

    async with database.session() as session:
        assert await _still_grounded(session, ids.evidence_id)
        tool_run = await session.get(ToolRun, ids.tool_run_id)
        assert tool_run is not None
        with pytest.raises(IntegrityError):
            await session.delete(tool_run)
            await session.flush()
        await session.rollback()

    async with database.session() as session:
        assert await _still_grounded(session, ids.evidence_id), (
            "tool_run_id was erased; every FACT citing this row has silently lost its G1 grounding"
        )


async def test_deleting_a_source_artifact_is_refused(database: Database) -> None:
    """Evidence must stay traceable to the bytes it came from."""
    ids = await _build_chain(database)

    async with database.session() as session:
        artifact = await session.get(Artifact, ids.artifact_id)
        assert artifact is not None
        with pytest.raises(IntegrityError):
            await session.delete(artifact)
            await session.flush()
        await session.rollback()

    async with database.session() as session:
        assert await session.get(Artifact, ids.artifact_id) is not None


async def test_deleting_an_agent_run_is_refused(database: Database) -> None:
    ids = await _build_chain(database)

    async with database.session() as session:
        agent_run = await session.get(AgentRun, ids.agent_run_id)
        assert agent_run is not None
        with pytest.raises(IntegrityError):
            await session.delete(agent_run)
            await session.flush()
        await session.rollback()


async def test_deleting_an_investigation_no_longer_cascades_into_evidence(
    database: Database,
) -> None:
    """A routine-looking delete must not take the append-only record with it."""
    ids = await _build_chain(database)

    async with database.session() as session:
        investigation = await session.get(Investigation, ids.investigation_id)
        assert investigation is not None
        with pytest.raises(IntegrityError):
            await session.delete(investigation)
            await session.flush()
        await session.rollback()

    async with database.session() as session:
        remaining = await session.scalar(
            sa.select(sa.func.count())
            .select_from(Evidence)
            .where(Evidence.investigation_id == ids.investigation_id)
        )
        assert remaining == 1


async def test_a_fact_stays_grounded_after_a_refused_deletion(database: Database) -> None:
    """End to end: the invariant that depends on provenance still holds afterwards."""
    ids = await _build_chain(database)

    async with database.session() as session:
        finding = await EvidenceStore(session, ids.investigation_id).add_finding(
            FindingDraft(
                title="1 authentication failure observed",
                description="Parsed from the submitted log.",
                assertion_class=AssertionClass.FACT,
                severity=Severity.INFO,
                evidence_ids=[ids.evidence_id],
                detection_rule="test.parse_summary",
            ),
            agent_run_id=ids.agent_run_id,
        )
        assert finding.id is not None

    async with database.session() as session:
        tool_run = await session.get(ToolRun, ids.tool_run_id)
        assert tool_run is not None
        with pytest.raises(IntegrityError):
            await session.delete(tool_run)
            await session.flush()
        await session.rollback()

    # G1 would still accept the same claim, which is the property at stake: had
    # the marker been erased, this write would now raise GroundingError.
    async with database.session() as session:
        again = await EvidenceStore(session, ids.investigation_id).add_finding(
            FindingDraft(
                title="1 authentication failure observed (re-asserted)",
                description="Re-asserted to prove the cited row is still deterministic.",
                assertion_class=AssertionClass.FACT,
                severity=Severity.INFO,
                evidence_ids=[ids.evidence_id],
                detection_rule="test.parse_summary",
            ),
        )
        assert again.id is not None
