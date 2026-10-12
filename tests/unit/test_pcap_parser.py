from __future__ import annotations

import socket
import struct
import uuid
from pathlib import Path

import pytest

from acip.tools.base import ToolContext
from acip.tools.pcap_parser import PcapParser, PcapParserArgs
from acip.types import EvidenceKind


def _build_test_pcap(include_dns: bool = True) -> bytes:
    """Build a deterministic, valid in-memory libpcap byte sequence."""
    # Global header (24 bytes, little-endian)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # 1. Packet: TCP packet between 192.168.1.50 and 203.0.113.10
    eth_hdr = b"\x00" * 6 + b"\x11" * 6 + struct.pack("!H", 0x0800)
    src_ip_bytes = socket.inet_aton("192.168.1.50")
    dst_ip_bytes = socket.inet_aton("203.0.113.10")
    ip_hdr = (
        bytes([0x45, 0x00])
        + struct.pack("!H", 40)
        + b"\x00\x01\x00\x00\x40\x06\x00\x00"  # proto 6 (TCP)
        + src_ip_bytes
        + dst_ip_bytes
    )
    tcp_hdr = struct.pack("!HHIIHHHH", 44321, 80, 1000, 0, 0x5000, 64240, 0, 0)
    pkt1_data = eth_hdr + ip_hdr + tcp_hdr

    pkt1_hdr = struct.pack("<IIII", 1700000000, 100000, len(pkt1_data), len(pkt1_data))

    packets = [pkt1_hdr + pkt1_data]

    # 2. Packet: DNS query packet for "evil-c2.attacker.com"
    if include_dns:
        dns_src_ip = socket.inet_aton("192.168.1.50")
        dns_dst_ip = socket.inet_aton("8.8.8.8")
        ip_dns_hdr = (
            bytes([0x45, 0x00])
            + struct.pack("!H", 64)
            + b"\x00\x02\x00\x00\x40\x11\x00\x00"  # proto 17 (UDP)
            + dns_src_ip
            + dns_dst_ip
        )
        udp_hdr = struct.pack("!HHHH", 52100, 53, 44, 0)
        # DNS query payload: QNAME evil-c2.attacker.com
        dns_payload = (
            struct.pack("!HHHH", 0x1234, 0x0100, 1, 0)
            + b"\x00\x00\x00\x00"
            + b"\x07evil-c2\x08attacker\x03com\x00"
            + struct.pack("!HH", 1, 1)  # Type A, Class IN
        )
        pkt2_data = eth_hdr + ip_dns_hdr + udp_hdr + dns_payload
        pkt2_hdr = struct.pack("<IIII", 1700000005, 200000, len(pkt2_data), len(pkt2_data))
        packets.append(pkt2_hdr + pkt2_data)

    return global_hdr + b"".join(packets)


@pytest.mark.asyncio
async def test_pcap_parser_extracts_flows_and_dns(tmp_path: Path) -> None:
    pcap_bytes = _build_test_pcap(include_dns=True)
    pcap_file = tmp_path / "traffic.pcap"
    pcap_file.write_bytes(pcap_bytes)

    parser = PcapParser()
    ctx = ToolContext(
        investigation_id=uuid.uuid4(),
        artifact_id=uuid.uuid4(),
        artifact_path=pcap_file,
    )

    result = await parser.execute(PcapParserArgs(), ctx)
    assert result.exit_status == 0
    assert result.metrics["packets_parsed"] == 2
    assert result.metrics["flows_extracted"] >= 2
    assert result.metrics["dns_queries_extracted"] == 1
    assert result.metrics["unique_ips"] >= 3

    # Verify extracted DNS evidence
    dns_items = [e for e in result.evidence if e.kind == EvidenceKind.DNS_QUERY]
    assert len(dns_items) == 1
    assert dns_items[0].data["query_domain"] == "evil-c2.attacker.com"
    assert dns_items[0].data["client_ip"] == "192.168.1.50"
    assert dns_items[0].data["server_ip"] == "8.8.8.8"

    # Verify IOC extraction
    ioc_items = [
        e
        for e in result.evidence
        if e.kind == EvidenceKind.IOC and e.data.get("value") == "evil-c2.attacker.com"
    ]
    assert len(ioc_items) == 1


@pytest.mark.asyncio
async def test_pcap_parser_degrades_gracefully_on_corrupt_input(tmp_path: Path) -> None:
    pcap_file = tmp_path / "corrupt.pcap"
    pcap_file.write_bytes(b"NOT_A_VALID_PCAP_HEADER_DATA")

    parser = PcapParser()
    ctx = ToolContext(
        investigation_id=uuid.uuid4(),
        artifact_path=pcap_file,
    )

    result = await parser.execute(PcapParserArgs(), ctx)
    assert result.exit_status == 1
    assert len(result.warnings) > 0
    assert result.metrics["packets_parsed"] == 0
