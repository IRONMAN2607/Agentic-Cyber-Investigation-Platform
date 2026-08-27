from __future__ import annotations

import datetime as dt

from acip.core.evidence.contracts import EntityRef, EvidenceDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import Investigation
from acip.db.session import Database
from acip.types import EntityType, EvidenceKind, TimeConfidence


async def test_evidence_deduplication(database: Database) -> None:
    async with database.session() as session:
        inv = Investigation(title="Dedupe Inv", target_type="log", target_value="auth.log")
        session.add(inv)
        await session.flush()

        store = EvidenceStore(session, inv.id)
        now = dt.datetime(2026, 3, 10, 12, 0, 0, tzinfo=dt.UTC)
        draft = EvidenceDraft(
            kind=EvidenceKind.AUTH_EVENT,
            data={"ip": "203.0.113.1", "action": "login"},
            observed_at=now,
            time_confidence=TimeConfidence.EXACT,
            entities=[EntityRef(type=EntityType.IP, value="203.0.113.1", role="source")],
        )

        first_batch = await store.add_evidence([draft], source_tool="auth_parser")
        assert len(first_batch) == 1

        # Second batch with same intrinsic content must skip creating duplicate row
        second_batch = await store.add_evidence([draft], source_tool="auth_parser")
        assert len(second_batch) == 0

        page = await store.list_evidence()
        assert len(page.rows) == 1
        assert page.rows[0].id == first_batch[0].id
        assert page.next_cursor is None
