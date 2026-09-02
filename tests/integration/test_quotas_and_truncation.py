from __future__ import annotations

import datetime as dt
import uuid
from pathlib import Path

import pytest

from acip.core.evidence.contracts import EvidenceDraft
from acip.core.evidence.store import EvidenceStore
from acip.db.models import AgentRun, Artifact, Investigation
from acip.db.session import Database
from acip.tools.auth_log_parser import AuthLogParserArgs, LinuxAuthLogParser
from acip.tools.ioc_extractor import IOCExtractor, IOCExtractorArgs
from acip.tools.registry import ToolRegistry
from acip.tools.runner import ToolRunner
from acip.types import EvidenceKind, TimeConfidence

pytestmark = pytest.mark.asyncio


async def test_evidence_store_quota_and_truncation(database: Database) -> None:
    inv_id = uuid.uuid4()
    async with database.session() as session:
        inv = Investigation(id=inv_id, title="Quota Inv", target_type="log", target_value="test")
        session.add(inv)

    # Store with max_evidence = 3
    async with database.session() as session:
        store = EvidenceStore(session, inv_id, max_evidence=3)

        # Add 2 items (within quota)
        drafts_1 = [
            EvidenceDraft(
                kind=EvidenceKind.AUTH_EVENT,
                data={"event_id": 1},
                observed_at=dt.datetime(2026, 1, 1, 10, 0, tzinfo=dt.UTC),
                time_confidence=TimeConfidence.EXACT,
            ),
            EvidenceDraft(
                kind=EvidenceKind.AUTH_EVENT,
                data={"event_id": 2},
                observed_at=dt.datetime(2026, 1, 1, 10, 1, tzinfo=dt.UTC),
                time_confidence=TimeConfidence.EXACT,
            ),
        ]
        created_1 = await store.add_evidence(drafts_1, source_tool="test_tool")
        assert len(created_1) == 2
        assert store.last_quota_dropped == 0
        assert await store.count_evidence() == 2

        # Add 3 more items (headroom is 1, so 1 fits and 2 are dropped)
        drafts_2 = [
            EvidenceDraft(
                kind=EvidenceKind.AUTH_EVENT,
                data={"event_id": 3},
                observed_at=dt.datetime(2026, 1, 1, 10, 2, tzinfo=dt.UTC),
                time_confidence=TimeConfidence.EXACT,
            ),
            EvidenceDraft(
                kind=EvidenceKind.AUTH_EVENT,
                data={"event_id": 4},
                observed_at=dt.datetime(2026, 1, 1, 10, 3, tzinfo=dt.UTC),
                time_confidence=TimeConfidence.EXACT,
            ),
            EvidenceDraft(
                kind=EvidenceKind.AUTH_EVENT,
                data={"event_id": 5},
                observed_at=dt.datetime(2026, 1, 1, 10, 4, tzinfo=dt.UTC),
                time_confidence=TimeConfidence.EXACT,
            ),
        ]
        created_2 = await store.add_evidence(drafts_2, source_tool="test_tool")
        assert len(created_2) == 1
        assert store.last_quota_dropped == 2
        assert await store.count_evidence() == 3

        # Add more items when store is at full capacity (0 fit, all dropped)
        drafts_3 = [
            EvidenceDraft(
                kind=EvidenceKind.AUTH_EVENT,
                data={"event_id": 6},
                observed_at=dt.datetime(2026, 1, 1, 10, 5, tzinfo=dt.UTC),
                time_confidence=TimeConfidence.EXACT,
            )
        ]
        created_3 = await store.add_evidence(drafts_3, source_tool="test_tool")
        assert len(created_3) == 0
        assert store.last_quota_dropped == 1

        # all_evidence with cap
        ev_all, truncated = await store.all_evidence(cap=2)
        assert len(ev_all) == 2
        assert truncated is True

        ev_all_full, truncated_full = await store.all_evidence(cap=10)
        assert len(ev_all_full) == 3
        assert truncated_full is False


async def test_tool_runner_records_quota_drop_warning(database: Database, tmp_path: Path) -> None:
    inv_id = uuid.uuid4()
    art_file = tmp_path / "auth.log"
    art_file.write_text(
        "Mar 10 03:11:01 web01 sshd[123]: Failed password for root from 192.0.2.1 port 22 ssh2\n"
        "Mar 10 03:11:02 web01 sshd[124]: Failed password for admin from 192.0.2.2 port 22 ssh2\n"
        "Mar 10 03:11:03 web01 sshd[125]: Failed password for test from 192.0.2.3 port 22 ssh2\n"
    )

    async with database.session() as session:
        inv = Investigation(
            id=inv_id,
            title="Tool Runner Quota Inv",
            target_type="log",
            target_value="auth.log",
        )
        session.add(inv)
        await session.flush()

        art = Artifact(
            investigation_id=inv_id,
            kind="linux_auth_log",
            original_filename="auth.log",
            sha256="0" * 64,
            size_bytes=100,
            storage_path=str(art_file),
        )
        agent_run = AgentRun(
            investigation_id=inv_id,
            task_id="t1",
            agent_name="log_analysis",
            agent_version="1.0.0",
            status="running",
        )
        session.add_all([art, agent_run])
        await session.flush()

        # Quota of 1 item
        store = EvidenceStore(session, inv_id, max_evidence=1)
        registry = ToolRegistry()
        registry.register(LinuxAuthLogParser())
        runner = ToolRunner(
            session=session,
            investigation_id=inv_id,
            registry=registry,
            store=store,
            artifact_root=tmp_path,
        )

        invocation = await runner.run(
            "linux_auth_log_parser",
            AuthLogParserArgs(year_hint=2026),
            agent_run_id=agent_run.id,
            artifact_id=art.id,
            artifact_path=art_file,
        )

        assert len(invocation.evidence) == 1
        tool_run = invocation.tool_run
        assert any("evidence quota reached" in w for w in tool_run.warnings)


async def test_auth_log_parser_max_lines_truncation() -> None:
    lines = [
        f"Mar 10 03:11:{i:02d} web01 sshd[{100 + i}]: Failed password for user{i} from 192.0.2.{i} port 22 ssh2"
        for i in range(10)
    ]
    log_text = "\n".join(lines) + "\n"

    parser = LinuxAuthLogParser()
    result = parser.parse_text(log_text, AuthLogParserArgs(year_hint=2026, max_lines=4))

    assert len(result.evidence) == 4
    assert result.metrics["lines_matched"] == 4
    assert any("input truncated at max_lines=4" in w for w in result.warnings)


async def test_ioc_extractor_max_iocs_truncation() -> None:
    text = (
        "Found malicious IPs: 198.51.100.1, 198.51.100.2, 198.51.100.3, 198.51.100.4, 198.51.100.5"
    )
    extractor = IOCExtractor()
    result = extractor.extract(text, IOCExtractorArgs(max_iocs=2))

    assert len(result.evidence) == 2
    assert result.metrics["iocs_found"] == 2
    assert any("extraction truncated at max_iocs=2" in w for w in result.warnings)
