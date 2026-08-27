from __future__ import annotations

import datetime as dt

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from acip.core.audit import record
from acip.core.evidence.contracts import EntityRef, EvidenceDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AuditLog, Evidence, Investigation
from acip.db.session import Database, authorized_purge
from acip.types import EntityType, EvidenceKind, TimeConfidence


async def test_evidence_immutability(database: Database) -> None:
    async with database.session() as session:
        inv = Investigation(title="Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()

        store = EvidenceStore(session, inv.id)
        draft = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={"test": "initial"},
            observed_at=dt.datetime.now(dt.UTC),
            time_confidence=TimeConfidence.EXACT,
            entities=[EntityRef(type=EntityType.HOST, value="host1", role="target")],
        )
        ev_rows = await store.add_evidence([draft], source_tool="test")
        ev = ev_rows[0]

        # Attempt to modify evidence data
        ev.data = {"test": "tampered"}
        with pytest.raises(RuntimeError, match="Evidence is append-only"):
            await session.flush()
        await session.rollback()


async def test_audit_log_immutability(database: Database) -> None:
    async with database.session() as session:
        audit_entry = await record(
            session,
            actor="admin",
            action="test_action",
            resource_type="system",
            resource_id="0",
        )
        await session.flush()

        audit_entry.actor = "malicious_actor"
        with pytest.raises(RuntimeError, match="AuditLog is append-only"):
            await session.flush()
        await session.rollback()


async def _seed_evidence(
    session: AsyncSession, count: int = 3
) -> tuple[Investigation, list[Evidence]]:
    """An investigation with evidence, for the bulk-DML cases below."""
    inv = Investigation(title="Inv", target_type="log", target_value="auth.log")
    session.add(inv)
    await session.flush()
    store = EvidenceStore(session, inv.id)
    rows = await store.add_evidence(
        [
            EvidenceDraft(
                kind=EvidenceKind.AUTH_EVENT,
                data={"i": i},
                observed_at=dt.datetime(2026, 3, 10, 3, 10 + i, tzinfo=dt.UTC),
                time_confidence=TimeConfidence.EXACT,
                entities=[EntityRef(type=EntityType.HOST, value="host1", role="target")],
            )
            for i in range(count)
        ],
        source_tool="test",
    )
    return inv, rows


async def test_bulk_update_cannot_rewrite_evidence(database: Database) -> None:
    """The mapper guards never see bulk DML, so the session guard must.

    ``session.execute(update(Evidence))`` rewrites rows without constructing an
    Evidence object, which is how history could be edited while every
    instance-level immutability test still passed.
    """
    async with database.session() as session:
        _, rows = await _seed_evidence(session)
        await session.flush()

        with pytest.raises(RuntimeError, match="append-only"):
            await session.execute(
                sa.update(Evidence).where(Evidence.id == rows[0].id).values(data={"tampered": True})
            )
        await session.rollback()


async def test_bulk_delete_cannot_remove_evidence(database: Database) -> None:
    async with database.session() as session:
        _, rows = await _seed_evidence(session)
        await session.flush()

        with pytest.raises(RuntimeError, match="append-only"):
            await session.execute(sa.delete(Evidence).where(Evidence.id == rows[0].id))
        await session.rollback()


async def test_bulk_dml_blocked_on_audit_log(database: Database) -> None:
    async with database.session() as session:
        await record(session, actor="admin", action="a", resource_type="system", resource_id="0")
        await session.flush()

        with pytest.raises(RuntimeError, match="append-only"):
            await session.execute(sa.update(AuditLog).values(actor="attacker"))
        await session.rollback()


async def test_select_is_not_blocked(database: Database) -> None:
    """The guard must bound its own blast radius: reads stay unaffected."""
    async with database.session() as session:
        await _seed_evidence(session, count=2)
        await session.flush()

        total = await session.scalar(sa.select(sa.func.count()).select_from(Evidence))
        assert total == 2


async def test_authorized_purge_permits_the_sanctioned_path(database: Database) -> None:
    """One named escape hatch, so deliberate destruction is greppable."""
    async with database.session() as session:
        await _seed_evidence(session, count=2)
        await session.flush()

        with authorized_purge():
            await session.execute(sa.delete(Evidence))
        assert await session.scalar(sa.select(sa.func.count()).select_from(Evidence)) == 0

        # The exception is scoped to the block, not left switched on.
        await _seed_evidence(session, count=1)
        await session.flush()
        with pytest.raises(RuntimeError, match="append-only"):
            await session.execute(sa.delete(Evidence))
        await session.rollback()
