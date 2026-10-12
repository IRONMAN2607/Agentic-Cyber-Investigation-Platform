"""Integration tests for all investigation target and file types.

Verifies end-to-end execution of investigations submitted as:
1. Domain Name (e.g. evil-attacker.example.com)
2. IP Address (e.g. 198.51.100.23)
3. URL (e.g. http://evil-attacker.example.com/login)
4. PCAP packet capture (flow extraction and DNS query dissection)
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest
import sqlalchemy as sa
from pydantic import SecretStr

from acip.agents.registry import build_default_registry as build_agent_registry
from acip.bootstrap import bootstrap
from acip.config import Settings
from acip.core.llm.router import build_default_router
from acip.core.orchestration.orchestrator import Orchestrator
from acip.core.orchestration.runner import InvestigationRunner
from acip.core.security.files import store_bytes
from acip.db.models import (
    Artifact,
    Entity,
    Evidence,
    Finding,
    Investigation,
    Report,
)
from acip.db.session import Database
from acip.tools.registry import build_default_registry as build_tool_registry
from acip.types import (
    ArtifactKind,
    EvidenceKind,
    InvestigationStatus,
    Severity,
    TargetType,
)


def _build_test_pcap() -> bytes:
    """Build a deterministic in-memory libpcap byte sequence."""
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    eth_hdr = b"\x00" * 6 + b"\x11" * 6 + struct.pack("!H", 0x0800)
    src_ip_bytes = socket.inet_aton("192.168.1.50")
    dst_ip_bytes = socket.inet_aton("198.51.100.23")
    ip_hdr = (
        bytes([0x45, 0x00])
        + struct.pack("!H", 40)
        + b"\x00\x01\x00\x00\x40\x06\x00\x00"
        + src_ip_bytes
        + dst_ip_bytes
    )
    tcp_hdr = struct.pack("!HHIIHHHH", 44321, 22, 1000, 0, 0x5000, 64240, 0, 0)
    pkt1_data = eth_hdr + ip_hdr + tcp_hdr
    pkt1_hdr = struct.pack("<IIII", 1700000000, 100000, len(pkt1_data), len(pkt1_data))

    dns_src_ip = socket.inet_aton("192.168.1.50")
    dns_dst_ip = socket.inet_aton("8.8.8.8")
    ip_dns_hdr = (
        bytes([0x45, 0x00])
        + struct.pack("!H", 64)
        + b"\x00\x02\x00\x00\x40\x11\x00\x00"
        + dns_src_ip
        + dns_dst_ip
    )
    udp_hdr = struct.pack("!HHHH", 52100, 53, 44, 0)
    dns_payload = (
        struct.pack("!HHHH", 0x1234, 0x0100, 1, 0)
        + b"\x00\x00\x00\x00"
        + b"\x0devil-attacker\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )
    pkt2_data = eth_hdr + ip_dns_hdr + udp_hdr + dns_payload
    pkt2_hdr = struct.pack("<IIII", 1700000005, 200000, len(pkt2_data), len(pkt2_data))

    return global_hdr + pkt1_hdr + pkt1_data + pkt2_hdr + pkt2_data


async def _setup_test_env(tmp_path: Path) -> tuple[InvestigationRunner, Database, Settings]:
    db_file = tmp_path / "target_types_test.db"
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    settings = Settings(
        environment="dev",
        database_url=f"sqlite+aiosqlite:///{db_file.as_posix()}",
        artifact_dir=artifact_dir,
        secret_key=SecretStr("test-secret-key-that-is-at-least-32-bytes-long-for-hs256"),
        enable_llm_triage=False,
        enable_adaptive_planning=True,
    )
    database = Database(settings.database_url, echo=False)
    await bootstrap(database, settings)

    tools = build_tool_registry()
    agents = build_agent_registry()
    router = build_default_router(settings)
    orchestrator = Orchestrator(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
        planner=None,
        router=router,
    )
    runner = InvestigationRunner(orchestrator=orchestrator, database=database)
    return runner, database, settings


@pytest.mark.asyncio
async def test_domain_investigation_pipeline(tmp_path: Path) -> None:
    runner, database, _settings = await _setup_test_env(tmp_path)

    domain_target = "evil-attacker.example.com"
    async with database.session() as session:
        inv = Investigation(
            title="Domain Threat Intel Investigation",
            target_type=TargetType.DOMAIN.value,
            target_value=domain_target,
            status=InvestigationStatus.CREATED.value,
        )
        session.add(inv)
        await session.commit()
        inv_id = inv.id

    await runner.submit(inv_id)

    async with database.session() as session:
        # 1. Verify automatic artifact creation
        arts = list(
            (
                await session.scalars(
                    sa.select(Artifact).where(Artifact.investigation_id == inv_id)
                )
            ).all()
        )
        assert len(arts) >= 1
        assert any("domain" in a.original_filename for a in arts)

        # 2. Verify Threat Intel Evidence was produced
        ev_rows = list(
            (
                await session.scalars(
                    sa.select(Evidence).where(
                        Evidence.investigation_id == inv_id,
                        Evidence.kind == EvidenceKind.THREAT_INTEL.value,
                    )
                )
            ).all()
        )
        assert len(ev_rows) >= 1
        ti_data = ev_rows[0].data
        assert ti_data.get("indicator") == domain_target
        assert ti_data.get("is_malicious") is True
        assert ti_data.get("abuse_score") == 88

        # 3. Verify Threat Intelligence Alert Finding was generated
        findings = list(
            (
                await session.scalars(
                    sa.select(Finding).where(Finding.investigation_id == inv_id)
                )
            ).all()
        )
        assert len(findings) >= 2
        alert_finding = next(
            (f for f in findings if f.detection_rule == "threat_intel.reputation"),
            None,
        )
        assert alert_finding is not None
        assert alert_finding.severity in {Severity.HIGH.value, Severity.CRITICAL.value}
        assert str(ev_rows[0].id) in alert_finding.evidence_ids

        # 4. Verify canonical entity was resolved in graph
        entities = list(
            (
                await session.scalars(
                    sa.select(Entity).where(Entity.investigation_id == inv_id)
                )
            ).all()
        )
        domain_ent = next(
            (e for e in entities if e.value_normalized == domain_target.lower()),
            None,
        )
        assert domain_ent is not None

        # 5. Verify final report
        report = (
            await session.scalars(
                sa.select(Report).where(Report.investigation_id == inv_id)
            )
        ).first()
        assert report is not None
        assert len(report.content) > 0

        inv_row = await session.get(Investigation, inv_id)
        assert inv_row is not None
        assert inv_row.severity in {"medium", "high", "critical"}
        assert inv_row.risk_score is not None and inv_row.risk_score > 0


@pytest.mark.asyncio
async def test_ip_investigation_pipeline(tmp_path: Path) -> None:
    runner, database, _settings = await _setup_test_env(tmp_path)

    ip_target = "198.51.100.23"
    async with database.session() as session:
        inv = Investigation(
            title="Malicious IP Reputation Investigation",
            target_type=TargetType.IP.value,
            target_value=ip_target,
            status=InvestigationStatus.CREATED.value,
        )
        session.add(inv)
        await session.commit()
        inv_id = inv.id

    await runner.submit(inv_id)

    async with database.session() as session:
        # Verify artifact and threat intel evidence
        arts = list(
            (
                await session.scalars(
                    sa.select(Artifact).where(Artifact.investigation_id == inv_id)
                )
            ).all()
        )
        assert len(arts) >= 1
        assert any("ip" in a.original_filename for a in arts)

        ev_rows = list(
            (
                await session.scalars(
                    sa.select(Evidence).where(
                        Evidence.investigation_id == inv_id,
                        Evidence.kind == EvidenceKind.THREAT_INTEL.value,
                    )
                )
            ).all()
        )
        assert len(ev_rows) >= 1
        assert ev_rows[0].data.get("abuse_score") == 100
        assert ev_rows[0].data.get("is_malicious") is True

        findings = list(
            (
                await session.scalars(
                    sa.select(Finding).where(Finding.investigation_id == inv_id)
                )
            ).all()
        )
        crit_finding = next(
            (f for f in findings if f.detection_rule == "threat_intel.reputation"),
            None,
        )
        assert crit_finding is not None
        assert crit_finding.severity == Severity.CRITICAL.value


@pytest.mark.asyncio
async def test_url_investigation_pipeline(tmp_path: Path) -> None:
    runner, database, _settings = await _setup_test_env(tmp_path)

    url_target = "http://evil-attacker.example.com/login.php"
    async with database.session() as session:
        inv = Investigation(
            title="Suspicious URL Investigation",
            target_type=TargetType.URL.value,
            target_value=url_target,
            status=InvestigationStatus.CREATED.value,
        )
        session.add(inv)
        await session.commit()
        inv_id = inv.id

    await runner.submit(inv_id)

    async with database.session() as session:
        arts = list(
            (
                await session.scalars(
                    sa.select(Artifact).where(Artifact.investigation_id == inv_id)
                )
            ).all()
        )
        assert len(arts) >= 1

        ev_rows = list(
            (
                await session.scalars(
                    sa.select(Evidence).where(
                        Evidence.investigation_id == inv_id,
                        Evidence.kind == EvidenceKind.THREAT_INTEL.value,
                    )
                )
            ).all()
        )
        assert len(ev_rows) >= 1
        assert ev_rows[0].data.get("indicator") == "evil-attacker.example.com"


@pytest.mark.asyncio
async def test_pcap_investigation_pipeline(tmp_path: Path) -> None:
    runner, database, settings = await _setup_test_env(tmp_path)

    pcap_bytes = _build_test_pcap()
    stored = await store_bytes(
        pcap_bytes,
        dest_dir=settings.artifact_dir,
        max_bytes=settings.max_artifact_bytes,
        original_filename="capture_sample.pcap",
        declared_kind=ArtifactKind.PCAP,
    )

    async with database.session() as session:
        inv = Investigation(
            title="PCAP Network Flow Analysis",
            target_type=TargetType.PCAP.value,
            target_value="capture_sample.pcap",
            status=InvestigationStatus.CREATED.value,
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id

        art = Artifact(
            investigation_id=inv_id,
            kind=ArtifactKind.PCAP.value,
            original_filename="capture_sample.pcap",
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            storage_path=str(stored.path),
        )
        session.add(art)
        await session.commit()

    await runner.submit(inv_id)

    async with database.session() as session:
        flows = list(
            (
                await session.scalars(
                    sa.select(Evidence).where(
                        Evidence.investigation_id == inv_id,
                        Evidence.kind == EvidenceKind.NETWORK_FLOW.value,
                    )
                )
            ).all()
        )
        assert len(flows) >= 1

        dns_queries = list(
            (
                await session.scalars(
                    sa.select(Evidence).where(
                        Evidence.investigation_id == inv_id,
                        Evidence.kind == EvidenceKind.DNS_QUERY.value,
                    )
                )
            ).all()
        )
        assert len(dns_queries) >= 1

        # Check PCAP finding recorded
        findings = list(
            (
                await session.scalars(
                    sa.select(Finding).where(Finding.investigation_id == inv_id)
                )
            ).all()
        )
        pcap_finding = next(
            (f for f in findings if f.detection_rule == "pcap.traffic_inventory"),
            None,
        )
        assert pcap_finding is not None
        assert "flow(s)" in pcap_finding.title
