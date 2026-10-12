"""Deterministic PCAP and packet capture parser adapter.

Parses libpcap packet capture files into normalised network flows, DNS queries,
and indicators of compromise (IOCs). Purely deterministic and safe: operates
over byte buffers with strict bounds and does not execute untrusted binaries.
"""

from __future__ import annotations

import datetime as dt
import socket
import struct
from typing import ClassVar

import anyio
from pydantic import BaseModel, Field

from acip.core.evidence.contracts import EntityRef, EvidenceDraft
from acip.errors import ToolError
from acip.logging import get_logger
from acip.tools.base import ToolAdapter, ToolAvailability, ToolContext, ToolResult
from acip.types import EntityType, EvidenceKind, SandboxTier, TimeConfidence

logger = get_logger(__name__)

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NANO_LE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NANO_BE = b"\xa1\xb2\x3c\x4d"
PCAPNG_MAGIC = b"\n\r\r\n"

_PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


class PcapParserArgs(BaseModel):
    """Execution options for packet capture parsing."""

    max_packets: int = Field(default=500, ge=1, le=10_000)
    extract_dns: bool = True
    extract_flows: bool = True


def _parse_dns_qname(payload: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS domain name from packet payload starting at offset."""
    labels: list[str] = []
    curr = offset
    length = len(payload)
    while curr < length:
        label_len = payload[curr]
        if label_len == 0:
            curr += 1
            break
        if label_len & 0xC0 == 0xC0:
            # Compression pointer, not following pointers in simple extraction
            curr += 2
            break
        curr += 1
        if curr + label_len > length:
            break
        try:
            labels.append(payload[curr : curr + label_len].decode("ascii", errors="replace"))
        except Exception:
            labels.append("unknown")
        curr += label_len
    return ".".join(labels), curr


class PcapParser(ToolAdapter):
    """Deterministic parser for PCAP packet captures."""

    name: ClassVar[str] = "pcap_parser"
    version: ClassVar[str] = "0.1.0"
    tier: ClassVar[SandboxTier] = SandboxTier.T1_SUBPROCESS
    args_model: ClassVar[type[BaseModel]] = PcapParserArgs
    requires_artifact: ClassVar[bool] = True

    def probe(self) -> ToolAvailability:
        return ToolAvailability(
            name=self.name,
            version=self.version,
            tier=self.tier,
            available=True,
            reason="Pure deterministic packet parsing engine active.",
        )

    async def execute(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        if not isinstance(args, PcapParserArgs):
            raise ToolError(f"expected PcapParserArgs, got {type(args).__name__}")

        if ctx.artifact_path is None:
            raise ToolError("PCAP parser requires an artifact_path")

        path = anyio.Path(ctx.artifact_path)
        try:
            raw_data = await path.read_bytes()
        except OSError as exc:
            raise ToolError(f"could not read PCAP file {path.name}: {exc}") from exc

        if len(raw_data) < 24:
            return ToolResult(
                evidence=[],
                metrics={"packets_parsed": 0, "status": "file_too_small"},
                warnings=["File too small to contain a valid PCAP header."],
                exit_status=1,
            )

        magic = raw_data[:4]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NANO_LE):
            endian = "<"
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NANO_BE):
            endian = ">"
        elif magic == PCAPNG_MAGIC:
            return self._parse_pcapng(raw_data, args)
        else:
            return ToolResult(
                evidence=[],
                metrics={"packets_parsed": 0, "status": "unsupported_magic"},
                warnings=[f"Unrecognised PCAP magic header {magic.hex()}"],
                exit_status=1,
            )

        return self._parse_libpcap(raw_data, endian, args)

    def _parse_libpcap(self, data: bytes, endian: str, args: PcapParserArgs) -> ToolResult:
        offset = 24
        total_len = len(data)
        packets_parsed = 0
        evidence: list[EvidenceDraft] = []
        warnings: list[str] = []
        observed_ips: set[str] = set()
        observed_domains: set[str] = set()

        while offset + 16 <= total_len and packets_parsed < args.max_packets:
            header = data[offset : offset + 16]
            offset += 16
            ts_sec, _ts_usec, caplen, origlen = struct.unpack(f"{endian}IIII", header)

            if offset + caplen > total_len:
                warnings.append(f"Packet {packets_parsed + 1} truncated at end of file.")
                caplen = total_len - offset

            pkt_bytes = data[offset : offset + caplen]
            offset += caplen
            packets_parsed += 1

            observed_time: dt.datetime | None = None
            try:
                observed_time = dt.datetime.fromtimestamp(ts_sec, dt.UTC)
            except (ValueError, OSError):
                observed_time = None

            # Link type Ethernet check (min 14 bytes)
            if len(pkt_bytes) < 14:
                continue

            eth_proto = struct.unpack("!H", pkt_bytes[12:14])[0]
            ip_data = pkt_bytes[14:]

            if eth_proto == 0x0800:  # IPv4
                if len(ip_data) < 20:
                    continue
                ihl = (ip_data[0] & 0x0F) * 4
                proto_num = ip_data[9]
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])
                observed_ips.add(src_ip)
                observed_ips.add(dst_ip)
                proto_name = _PROTO_MAP.get(proto_num, f"IP-{proto_num}")

                transport_data = ip_data[ihl:]
                src_port: int | None = None
                dst_port: int | None = None

                if proto_num in (6, 17) and len(transport_data) >= 4:  # TCP or UDP
                    src_port, dst_port = struct.unpack("!HH", transport_data[:4])

                if args.extract_flows:
                    evidence.append(
                        EvidenceDraft(
                            kind=EvidenceKind.NETWORK_FLOW,
                            data={
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "protocol": proto_name,
                                "packet_size": origlen,
                            },
                            entities=[
                                EntityRef(type=EntityType.IP, value=src_ip),
                                EntityRef(type=EntityType.IP, value=dst_ip),
                            ],
                            observed_at=observed_time,
                            time_confidence=TimeConfidence.EXACT
                            if observed_time
                            else TimeConfidence.UNKNOWN,
                        )
                    )

                # Check for DNS traffic (UDP port 53)
                if args.extract_dns and proto_num == 17 and (src_port == 53 or dst_port == 53):
                    udp_payload = transport_data[8:]
                    if len(udp_payload) >= 12:
                        dns_id, _flags, qdcount, _ancount = struct.unpack("!HHHH", udp_payload[:8])
                        if qdcount > 0:
                            qname, _ = _parse_dns_qname(udp_payload, 12)
                            if qname and "." in qname and not qname.startswith("in-addr"):
                                observed_domains.add(qname)
                                evidence.append(
                                    EvidenceDraft(
                                        kind=EvidenceKind.DNS_QUERY,
                                        data={
                                            "client_ip": src_ip if dst_port == 53 else dst_ip,
                                            "server_ip": dst_ip if dst_port == 53 else src_ip,
                                            "query_domain": qname,
                                            "dns_id": dns_id,
                                        },
                                        entities=[
                                            EntityRef(type=EntityType.DOMAIN, value=qname),
                                            EntityRef(type=EntityType.IP, value=src_ip),
                                        ],
                                        observed_at=observed_time,
                                        time_confidence=TimeConfidence.EXACT
                                        if observed_time
                                        else TimeConfidence.UNKNOWN,
                                    )
                                )

        # Add IOCs for discovered domains
        for dom in observed_domains:
            evidence.append(
                EvidenceDraft(
                    kind=EvidenceKind.IOC,
                    data={"type": "domain", "value": dom, "context": "DNS query in capture"},
                    entities=[EntityRef(type=EntityType.DOMAIN, value=dom)],
                    time_confidence=TimeConfidence.DERIVED,
                )
            )

        return ToolResult(
            evidence=evidence,
            metrics={
                "packets_parsed": packets_parsed,
                "flows_extracted": sum(1 for e in evidence if e.kind == EvidenceKind.NETWORK_FLOW),
                "dns_queries_extracted": sum(
                    1 for e in evidence if e.kind == EvidenceKind.DNS_QUERY
                ),
                "unique_ips": len(observed_ips),
                "unique_domains": len(observed_domains),
            },
            warnings=warnings,
            exit_status=0,
        )

    def _parse_pcapng(self, data: bytes, args: PcapParserArgs) -> ToolResult:
        """Parse basic PCAPNG blocks."""
        offset = 0
        total_len = len(data)
        packets_parsed = 0
        evidence: list[EvidenceDraft] = []
        warnings: list[str] = []

        while offset + 8 <= total_len and packets_parsed < args.max_packets:
            block_type, block_len = struct.unpack("<II", data[offset : offset + 8])
            if block_len < 12 or offset + block_len > total_len:
                break

            # Enhanced Packet Block (EPB) is type 0x00000006
            if block_type == 6 and block_len >= 32:
                packets_parsed += 1
                pkt_data_len = struct.unpack("<I", data[offset + 20 : offset + 24])[0]
                pkt_start = offset + 28
                pkt_end = pkt_start + pkt_data_len
                if pkt_end <= offset + block_len and pkt_data_len >= 14:
                    pkt_bytes = data[pkt_start:pkt_end]
                    eth_proto = struct.unpack("!H", pkt_bytes[12:14])[0]
                    if eth_proto == 0x0800 and len(pkt_bytes) >= 34:  # IPv4
                        src_ip = socket.inet_ntoa(pkt_bytes[26:30])
                        dst_ip = socket.inet_ntoa(pkt_bytes[30:34])
                        proto_num = pkt_bytes[23]
                        if args.extract_flows:
                            evidence.append(
                                EvidenceDraft(
                                    kind=EvidenceKind.NETWORK_FLOW,
                                    data={
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                        "protocol": _PROTO_MAP.get(proto_num, str(proto_num)),
                                    },
                                    entities=[
                                        EntityRef(type=EntityType.IP, value=src_ip),
                                        EntityRef(type=EntityType.IP, value=dst_ip),
                                    ],
                                    time_confidence=TimeConfidence.UNKNOWN,
                                )
                            )

            offset += block_len

        return ToolResult(
            evidence=evidence,
            metrics={"packets_parsed": packets_parsed, "format": "pcapng"},
            warnings=warnings,
            exit_status=0,
        )
