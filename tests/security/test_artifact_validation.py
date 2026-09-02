from __future__ import annotations

from pathlib import Path

import pytest

from acip.core.security.files import (
    detect_artifact_kind,
    detect_magic_bytes,
    store_bytes,
)
from acip.core.security.validation import (
    validate_domain,
    validate_hash,
    validate_ip,
    validate_target_value,
    validate_url,
)
from acip.errors import PayloadTooLargeError, ValidationError
from acip.types import ArtifactKind, TargetType


def test_validate_ip() -> None:
    assert validate_ip("192.0.2.1") == "192.0.2.1"
    assert validate_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    with pytest.raises(ValidationError, match="invalid IP address"):
        validate_ip("999.999.999.999")
    with pytest.raises(ValidationError, match="IP address must not be empty"):
        validate_ip("   ")


def test_validate_hash() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    assert validate_hash(md5.upper()) == md5
    assert validate_hash(sha1.upper()) == sha1
    assert validate_hash(sha256.upper()) == sha256

    with pytest.raises(ValidationError, match="invalid cryptographic hash"):
        validate_hash("not_a_hash")
    with pytest.raises(ValidationError, match="invalid cryptographic hash"):
        validate_hash("123456")


def test_validate_domain() -> None:
    assert validate_domain("example.com") == "example.com"
    assert validate_domain("SUB.EXAMPLE.ORG.") == "sub.example.org"
    with pytest.raises(ValidationError, match=r"domain label.*contains invalid characters"):
        validate_domain("ex ample.com")
    with pytest.raises(ValidationError, match="domain name must not be empty"):
        validate_domain("")


def test_validate_url() -> None:
    assert validate_url("https://example.com/feed") == "https://example.com/feed"
    assert validate_url("http://EXAMPLE.COM:8080/test") == "http://example.com:8080/test"
    with pytest.raises(ValidationError, match="disallowed URL scheme"):
        validate_url("file:///etc/shadow")


def test_validate_target_value_routing() -> None:
    assert validate_target_value(TargetType.IP, "1.1.1.1") == "1.1.1.1"
    assert validate_target_value(TargetType.URL, "https://example.org") == "https://example.org/"
    assert (
        validate_target_value(
            TargetType.HASH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert validate_target_value(TargetType.LOG, "auth.log") == "auth.log"


def test_detect_magic_bytes_pcap() -> None:
    # Standard PCAP microsecond
    header_pcap = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20
    kind, mime = detect_magic_bytes(header_pcap)
    assert kind == ArtifactKind.PCAP
    assert "pcap" in mime

    # PCAPNG
    header_pcapng = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20
    kind_ng, mime_ng = detect_magic_bytes(header_pcapng)
    assert kind_ng == ArtifactKind.PCAP_NG
    assert "pcapng" in mime_ng


def test_detect_magic_bytes_executables() -> None:
    # ELF binary
    elf = b"\x7fELF" + b"\x01\x01\x01\x00"
    kind_elf, _ = detect_magic_bytes(elf)
    assert kind_elf == ArtifactKind.BINARY_FILE

    # Windows PE binary
    pe = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
    kind_pe, _ = detect_magic_bytes(pe)
    assert kind_pe == ArtifactKind.BINARY_FILE


def test_detect_artifact_kind_pcap_mismatch_rejected() -> None:
    # Non-pcap data declared as PCAP
    text_data = b"Jan 1 00:00:00 server sshd[123]: Failed password"
    with pytest.raises(ValidationError, match="does not contain valid PCAP/PCAPNG magic bytes"):
        detect_artifact_kind(text_data, "capture.pcap", declared_kind=ArtifactKind.PCAP)


def test_detect_artifact_kind_executable_disguised_as_log_rejected() -> None:
    # ELF executable disguised as auth.log
    elf_data = b"\x7fELF\x02\x01\x01\x00"
    with pytest.raises(ValidationError, match="binary executable payload rejected"):
        detect_artifact_kind(elf_data, "auth.log", declared_kind=ArtifactKind.LINUX_AUTH_LOG)


@pytest.mark.asyncio
async def test_store_bytes_enforces_size_limit(tmp_path: Path) -> None:
    large_payload = b"A" * 1024
    with pytest.raises(PayloadTooLargeError, match="exceeds maximum size of 512 bytes"):
        await store_bytes(large_payload, dest_dir=tmp_path, max_bytes=512)


@pytest.mark.asyncio
async def test_store_bytes_successful_intake(tmp_path: Path) -> None:
    pcap_data = b"\xa1\xb2\xc3\xd4" + b"\x00" * 32
    stored = await store_bytes(
        pcap_data,
        dest_dir=tmp_path,
        max_bytes=1024,
        original_filename="../../../evil/network_dump.pcap",
        declared_kind=ArtifactKind.PCAP,
    )
    assert stored.safe_filename == "network_dump.pcap"
    assert stored.detected_kind == ArtifactKind.PCAP
    assert stored.path.is_file()
    assert stored.path.is_relative_to(tmp_path)
    assert stored.size_bytes == len(pcap_data)
