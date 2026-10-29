"""Synthetic investigations used by the local demo-data seed command.

The values in this module are documentation addresses, reserved test hashes, or
small synthetic artifacts.  They are intentionally safe to process: the
platform's deterministic parsers inspect bytes and never execute an artifact.
Each supported :class:`~acip.types.TargetType` has one high-risk and one
low-risk example so a fresh local deployment can demonstrate both outcomes.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Literal

from acip.types import ArtifactKind, TargetType

RiskBand = Literal["high", "low"]


@dataclass(frozen=True, slots=True)
class DemoArtifact:
    """An artifact to attach to a synthetic investigation."""

    filename: str
    content: bytes
    kind: ArtifactKind


@dataclass(frozen=True, slots=True)
class DemoInvestigation:
    """Seed definition for one high- or low-risk investigation."""

    key: str
    title: str
    target_type: TargetType
    target_value: str
    risk_band: RiskBand
    artifacts: tuple[DemoArtifact, ...] = ()


HIGH_RISK_MD5 = "44d88612fea8a8f36de82e1278abb02f"  # pragma: allowlist secret
LOW_RISK_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855"  # pragma: allowlist secret
)


HIGH_RISK_AUTH_LOG = (
    "Mar 10 03:11:01 web01 sshd[1234]: Failed password for "
    "invalid user admin from 203.0.113.55 port 44120 ssh2\n"
    "Mar 10 03:11:05 web01 sshd[1235]: Failed password for "
    "invalid user root from 203.0.113.55 port 44122 ssh2\n"
    "Mar 10 03:11:09 web01 sshd[1236]: Failed password for "
    "invalid user test from 203.0.113.55 port 44124 ssh2\n"
    "Mar 10 03:11:12 web01 sshd[1237]: Failed password for "
    "invalid user guest from 203.0.113.55 port 44126 ssh2\n"
    "Mar 10 03:11:15 web01 sshd[1238]: Failed password for "
    "deploy from 203.0.113.55 port 44128 ssh2\n"
    "Mar 10 03:11:18 web01 sshd[1239]: Failed password for "
    "deploy from 203.0.113.55 port 44130 ssh2\n"
    "Mar 10 03:11:20 web01 sshd[1240]: Accepted password for deploy "
    "from 203.0.113.55 port 44132 ssh2\n"
    "Mar 10 03:11:25 web01 sudo[1245]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; "
    "USER=root ; COMMAND=/bin/cat /etc/shadow\n"
)

LOW_RISK_AUTH_LOG = (
    "Mar 10 08:00:01 web01 sshd[5001]: Accepted publickey for backup from "
    "10.0.0.99 port 41000 ssh2: RSA SHA256:abc1234\n"
    "Mar 10 08:05:02 web01 CRON[5005]: (root) CMD (/usr/local/bin/check_disk.sh)\n"
    "Mar 10 08:10:01 web01 sshd[5010]: Accepted publickey for sysadmin from "
    "10.0.0.100 port 41002 ssh2: RSA SHA256:def5678\n"
)


def build_demo_pcap(*, malicious: bool) -> bytes:
    """Build a tiny deterministic PCAP containing one DNS query and one flow."""
    query_domain = "evil-attacker.example.com" if malicious else "safe.example.com"
    destination_ip = "203.0.113.195" if malicious else "192.0.2.1"

    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    ethernet_header = b"\x00" * 6 + b"\x11" * 6 + struct.pack("!H", 0x0800)

    source_ip = socket.inet_aton("192.0.2.10")
    destination_ip_bytes = socket.inet_aton(destination_ip)
    ip_header = (
        bytes([0x45, 0x00])
        + struct.pack("!H", 40)
        + b"\x00\x01\x00\x00\x40\x06\x00\x00"
        + source_ip
        + destination_ip_bytes
    )
    tcp_header = struct.pack("!HHIIHHHH", 44321, 443, 1000, 0, 0x5000, 64240, 0, 0)
    flow = ethernet_header + ip_header + tcp_header
    flow_record = struct.pack("<IIII", 1_700_000_000, 100_000, len(flow), len(flow)) + flow

    dns_labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in query_domain.split(".")
    )
    dns_payload = (
        struct.pack("!HHHH", 0x1234, 0x0100, 1, 0)
        + b"\x00\x00\x00\x00"
        + dns_labels
        + b"\x00"
        + struct.pack("!HH", 1, 1)
    )
    dns_ip_header = (
        bytes([0x45, 0x00])
        + struct.pack("!H", 20 + 8 + len(dns_payload))
        + b"\x00\x02\x00\x00\x40\x11\x00\x00"
        + source_ip
        + socket.inet_aton("8.8.8.8")
    )
    udp_header = struct.pack("!HHHH", 52100, 53, 8 + len(dns_payload), 0)
    dns_packet = ethernet_header + dns_ip_header + udp_header + dns_payload
    dns_record = (
        struct.pack("<IIII", 1_700_000_005, 200_000, len(dns_packet), len(dns_packet)) + dns_packet
    )

    return global_header + flow_record + dns_record


_HIGH_URL_ARTIFACT = DemoArtifact(
    filename="high-risk-url-response.txt",
    content=(
        b"HTTP/1.1 200 OK\n"
        b"Content-Type: text/html\n\n"
        b"Synthetic response for https://evil-attacker.example.com/login\n"
    ),
    kind=ArtifactKind.URL_RESPONSE,
)

_LOW_URL_ARTIFACT = DemoArtifact(
    filename="low-risk-url-response.txt",
    content=(
        b"HTTP/1.1 200 OK\n"
        b"Content-Type: text/plain\n\n"
        b"Synthetic health-check response from https://safe.example.com/status\n"
    ),
    kind=ArtifactKind.URL_RESPONSE,
)

_HIGH_FILE_ARTIFACT = DemoArtifact(
    filename="high-risk-synthetic-sample.txt",
    content=(
        b"Synthetic quarantined sample; do not execute.\n"
        b"Known test indicator: " + HIGH_RISK_MD5.encode("ascii") + b"\n"
    ),
    kind=ArtifactKind.GENERIC_TEXT,
)

_LOW_FILE_ARTIFACT = DemoArtifact(
    filename="low-risk-routine-report.txt",
    content=b"Routine backup inventory completed successfully; no indicators were observed.\n",
    kind=ArtifactKind.GENERIC_TEXT,
)

_HIGH_PCAP_ARTIFACT = DemoArtifact(
    filename="high-risk-dns-capture.pcap",
    content=build_demo_pcap(malicious=True),
    kind=ArtifactKind.PCAP,
)

_LOW_PCAP_ARTIFACT = DemoArtifact(
    filename="low-risk-dns-capture.pcap",
    content=build_demo_pcap(malicious=False),
    kind=ArtifactKind.PCAP,
)


DEMO_INVESTIGATIONS: tuple[DemoInvestigation, ...] = (
    DemoInvestigation(
        key="domain_high",
        title="Demo HIGH: Malicious Domain Reputation",
        target_type=TargetType.DOMAIN,
        target_value="evil-attacker.example.com",
        risk_band="high",
    ),
    DemoInvestigation(
        key="domain_low",
        title="Demo LOW: Benign Domain Reputation",
        target_type=TargetType.DOMAIN,
        target_value="safe.example.com",
        risk_band="low",
    ),
    DemoInvestigation(
        key="url_high",
        title="Demo HIGH: Suspicious Login URL",
        target_type=TargetType.URL,
        target_value="https://evil-attacker.example.com/login",
        risk_band="high",
        artifacts=(_HIGH_URL_ARTIFACT,),
    ),
    DemoInvestigation(
        key="url_low",
        title="Demo LOW: Routine Health URL",
        target_type=TargetType.URL,
        target_value="https://safe.example.com/status",
        risk_band="low",
        artifacts=(_LOW_URL_ARTIFACT,),
    ),
    DemoInvestigation(
        key="ip_high",
        title="Demo HIGH: Malicious Source IP",
        target_type=TargetType.IP,
        target_value="198.51.100.23",
        risk_band="high",
    ),
    DemoInvestigation(
        key="ip_low",
        title="Demo LOW: Documentation Source IP",
        target_type=TargetType.IP,
        target_value="192.0.2.1",
        risk_band="low",
    ),
    DemoInvestigation(
        key="hash_high",
        title="Demo HIGH: Known Malicious Test Hash",
        target_type=TargetType.HASH,
        target_value=HIGH_RISK_MD5,
        risk_band="high",
    ),
    DemoInvestigation(
        key="hash_low",
        title="Demo LOW: Empty File Test Hash",
        target_type=TargetType.HASH,
        target_value=LOW_RISK_SHA256,
        risk_band="low",
    ),
    DemoInvestigation(
        key="file_high",
        title="Demo HIGH: Quarantined Suspicious File",
        target_type=TargetType.FILE,
        target_value="high-risk-synthetic-sample.txt",
        risk_band="high",
        artifacts=(_HIGH_FILE_ARTIFACT,),
    ),
    DemoInvestigation(
        key="file_low",
        title="Demo LOW: Routine Text File",
        target_type=TargetType.FILE,
        target_value="low-risk-routine-report.txt",
        risk_band="low",
        artifacts=(_LOW_FILE_ARTIFACT,),
    ),
    DemoInvestigation(
        key="log_high",
        title="Demo HIGH: SSH Guessing and Root Sudo",
        target_type=TargetType.LOG,
        target_value="high-risk-auth.log",
        risk_band="high",
        artifacts=(
            DemoArtifact(
                filename="high-risk-auth.log",
                content=HIGH_RISK_AUTH_LOG.encode("utf-8"),
                kind=ArtifactKind.LINUX_AUTH_LOG,
            ),
        ),
    ),
    DemoInvestigation(
        key="log_low",
        title="Demo LOW: Routine Authentication",
        target_type=TargetType.LOG,
        target_value="low-risk-auth.log",
        risk_band="low",
        artifacts=(
            DemoArtifact(
                filename="low-risk-auth.log",
                content=LOW_RISK_AUTH_LOG.encode("utf-8"),
                kind=ArtifactKind.LINUX_AUTH_LOG,
            ),
        ),
    ),
    DemoInvestigation(
        key="pcap_high",
        title="Demo HIGH: DNS Resolution to Suspicious Domain",
        target_type=TargetType.PCAP,
        target_value="high-risk-dns-capture.pcap",
        risk_band="high",
        artifacts=(_HIGH_PCAP_ARTIFACT,),
    ),
    DemoInvestigation(
        key="pcap_low",
        title="Demo LOW: Routine DNS Capture",
        target_type=TargetType.PCAP,
        target_value="low-risk-dns-capture.pcap",
        risk_band="low",
        artifacts=(_LOW_PCAP_ARTIFACT,),
    ),
    DemoInvestigation(
        key="description_high",
        title="Demo HIGH: Confirmed Suspicious Connection Report",
        target_type=TargetType.DESCRIPTION,
        target_value=(
            "Incident report: repeated administrative connections were observed from "
            "evil-attacker.example.com against the perimeter service."
        ),
        risk_band="high",
    ),
    DemoInvestigation(
        key="description_low",
        title="Demo LOW: Routine Maintenance Report",
        target_type=TargetType.DESCRIPTION,
        target_value=(
            "Routine maintenance completed successfully; scheduled backups and health checks "
            "reported no anomalies."
        ),
        risk_band="low",
    ),
)


def demo_investigations_by_type() -> dict[TargetType, tuple[DemoInvestigation, DemoInvestigation]]:
    """Return the catalog grouped by target type for validation and documentation."""
    grouped: dict[TargetType, dict[RiskBand, DemoInvestigation]] = {}
    for sample in DEMO_INVESTIGATIONS:
        grouped.setdefault(sample.target_type, {})[sample.risk_band] = sample

    return {
        target_type: (samples["high"], samples["low"]) for target_type, samples in grouped.items()
    }


__all__ = [
    "DEMO_INVESTIGATIONS",
    "HIGH_RISK_MD5",
    "LOW_RISK_SHA256",
    "DemoArtifact",
    "DemoInvestigation",
    "build_demo_pcap",
    "demo_investigations_by_type",
]
