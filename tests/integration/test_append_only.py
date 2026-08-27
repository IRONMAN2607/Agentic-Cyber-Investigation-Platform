from __future__ import annotations

import datetime as dt

import pytest

from acip.core.audit import record
from acip.core.evidence.contracts import EntityRef, EvidenceDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import Investigation
from acip.db.session import Database
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
