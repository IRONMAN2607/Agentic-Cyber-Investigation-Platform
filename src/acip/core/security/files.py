"""Safe artifact intake.

Uploaded artifacts are untrusted by definition — in later phases they include
live malware samples. Four properties are enforced here:

1. **No client-controlled paths.** Storage is content-addressed by SHA-256, so
   the client filename never reaches the filesystem. This removes path
   traversal as a category rather than filtering for it.
2. **Bounded size.** The stream is capped while reading, so an oversized upload
   is rejected without first being buffered to disk or memory.
3. **Magic byte inspection and type verification.** Artifact headers are sniffed
   to verify declared types (e.g. PCAP vs log vs executable binary) and block
   type-confusion attacks.
4. **No execute bit.** Files are written 0o600 on POSIX. Nothing in the
   platform ever hands an artifact to the operating system to execute; tools
   read bytes.

Stronger isolation (dedicated uid, read-only mounts, container execution) lands
in Phase 4 when binaries and real samples are introduced. M1 handles text logs.
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

from acip.errors import PayloadTooLargeError, ValidationError
from acip.types import ArtifactKind

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_FILENAME = 128
# Cap decoded text so a large artifact cannot exhaust memory inside a parser.
DEFAULT_MAX_TEXT_BYTES = 32 * 1024 * 1024

# PCAP Magic Numbers
_PCAP_MAGIC_MICRO_NATIVE = b"\xa1\xb2\xc3\xd4"
_PCAP_MAGIC_MICRO_SWAPPED = b"\xd4\xc3\xb2\xa1"
_PCAP_MAGIC_NANO_NATIVE = b"\xa1\xb2\x3c\x4d"
_PCAP_MAGIC_NANO_SWAPPED = b"\x4d\x3c\xb2\xa1"
_PCAP_NG_MAGIC = b"\x0a\x0d\x0d\x0a"  # Section Header Block

# Executable / Binary Magic Numbers
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00"


@dataclass(frozen=True)
class StoredArtifact:
    """Result of a successful intake."""

    sha256: str
    size_bytes: int
    path: Path
    safe_filename: str
    detected_kind: ArtifactKind = ArtifactKind.UNKNOWN
    mime_type: str = "application/octet-stream"


def sanitize_filename(name: str) -> str:
    """Reduce a client-supplied filename to a safe display label.

    The result is used for display and logging only, never for path
    construction, but it is still normalised so it cannot inject control
    characters or separators into logs and reports.
    """
    candidate = unicodedata.normalize("NFKD", name or "")
    candidate = candidate.replace("\\", "/").rsplit("/", 1)[-1]
    candidate = _UNSAFE_CHARS.sub("_", candidate).strip("._-")
    if not candidate:
        candidate = "artifact"
    return candidate[:_MAX_FILENAME]


def detect_magic_bytes(header: bytes) -> tuple[ArtifactKind | None, str]:
    """Inspect the first bytes of a file to detect its format and MIME type."""
    if len(header) >= 4:
        magic4 = header[:4]
        if (
            magic4 == _PCAP_MAGIC_MICRO_NATIVE
            or magic4 == _PCAP_MAGIC_MICRO_SWAPPED
            or magic4 == _PCAP_MAGIC_NANO_NATIVE
            or magic4 == _PCAP_MAGIC_NANO_SWAPPED
        ):
            return ArtifactKind.PCAP, "application/vnd.tcpdump.pcap"
        if magic4 == _PCAP_NG_MAGIC:
            return ArtifactKind.PCAP_NG, "application/x-pcapng"
        if magic4 == _ELF_MAGIC:
            return ArtifactKind.BINARY_FILE, "application/x-executable"
        if magic4 in _MACHO_MAGICS:
            return ArtifactKind.BINARY_FILE, "application/x-mach-binary"

    if len(header) >= 2 and header[:2] == _PE_MAGIC:
        return ArtifactKind.BINARY_FILE, "application/x-dosexec"

    if len(header) >= 8 and header[:8] == _LNK_MAGIC:
        return ArtifactKind.BINARY_FILE, "application/x-ms-shortcut"

    # Check if text
    if not header:
        return None, "application/octet-stream"

    # Heuristic text check: low percentage of non-printable / control bytes
    null_count = header.count(b"\x00")
    if null_count == 0:
        try:
            text_snippet = header.decode("utf-8")
            if any(k in text_snippet for k in ("sshd[", "sudo:", "pam_unix", "systemd-logind")):
                return ArtifactKind.LINUX_AUTH_LOG, "text/plain"
            if any(k in text_snippet for k in ("GET /", "POST /", "HTTP/1.", "HTTP/2.")):
                return ArtifactKind.WEB_SERVER_LOG, "text/plain"
            return ArtifactKind.GENERIC_TEXT, "text/plain"
        except UnicodeDecodeError:
            return None, "application/octet-stream"

    return None, "application/octet-stream"


def detect_artifact_kind(
    header_bytes: bytes,
    filename: str = "",
    declared_kind: ArtifactKind = ArtifactKind.UNKNOWN,
) -> tuple[ArtifactKind, str]:
    """Classify an artifact based on header magic bytes, filename, and declared kind.

    Enforces strict type verification when specific kinds are declared.
    """
    detected_kind, mime_type = detect_magic_bytes(header_bytes)

    # 1. Enforce PCAP integrity
    if declared_kind in {ArtifactKind.PCAP, ArtifactKind.PCAP_NG}:
        if detected_kind not in {ArtifactKind.PCAP, ArtifactKind.PCAP_NG}:
            raise ValidationError(
                f"artifact declared as '{declared_kind.value}' does not contain "
                "valid PCAP/PCAPNG magic bytes"
            )
        return declared_kind, mime_type

    # 2. Reject binary executables disguised as text logs
    if declared_kind in {
        ArtifactKind.LINUX_AUTH_LOG,
        ArtifactKind.SYS_LOG,
        ArtifactKind.WEB_SERVER_LOG,
        ArtifactKind.GENERIC_LOG,
        ArtifactKind.GENERIC_TEXT,
    }:
        if detected_kind == ArtifactKind.BINARY_FILE:
            raise ValidationError(
                f"binary executable payload rejected: declared as '{declared_kind.value}'"
            )
        return declared_kind, mime_type

    # 3. Infer from magic bytes if declared is UNKNOWN
    if declared_kind is ArtifactKind.UNKNOWN:
        if detected_kind is not None:
            return detected_kind, mime_type

        # Check filename extension hints
        fn_lower = filename.lower()
        if fn_lower.endswith((".pcap", ".cap")):
            return ArtifactKind.PCAP, "application/vnd.tcpdump.pcap"
        if fn_lower.endswith(".pcapng"):
            return ArtifactKind.PCAP_NG, "application/x-pcapng"
        if fn_lower.endswith((".log", ".txt")):
            return ArtifactKind.GENERIC_TEXT, "text/plain"

        return ArtifactKind.UNKNOWN, mime_type

    return declared_kind, mime_type


async def store_stream(
    chunks: AsyncIterator[bytes],
    *,
    dest_dir: Path,
    max_bytes: int,
    original_filename: str = "",
    declared_kind: ArtifactKind = ArtifactKind.UNKNOWN,
) -> StoredArtifact:
    """Consume ``chunks`` into content-addressed storage under ``dest_dir``.

    Raises :class:`PayloadTooLargeError` as soon as the cap is exceeded, and
    :class:`ValidationError` for an empty upload or type mismatch.
    """
    dest_dir = dest_dir.resolve()  # noqa: ASYNC240
    staging_dir = dest_dir / "_staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256()
    size = 0
    header_bytes = b""
    # Unique staging name so concurrent uploads cannot collide before hashing.
    staging_path = staging_dir / f"upload-{os.urandom(12).hex()}"

    try:
        with staging_path.open("wb") as handle:
            async for chunk in chunks:
                if not chunk:
                    continue
                if len(header_bytes) < 4096:
                    header_bytes += chunk[: 4096 - len(header_bytes)]
                size += len(chunk)
                if size > max_bytes:
                    raise PayloadTooLargeError(
                        f"artifact exceeds maximum size of {max_bytes} bytes",
                        detail={"max_bytes": max_bytes},
                    )
                digest.update(chunk)
                handle.write(chunk)

        if size == 0:
            raise ValidationError("artifact is empty")

        # Sniff magic bytes and validate artifact kind
        resolved_kind, mime_type = detect_artifact_kind(
            header_bytes, original_filename, declared_kind
        )

        sha256 = digest.hexdigest()
        final_dir = dest_dir / sha256[:2]
        final_dir.mkdir(parents=True, exist_ok=True)
        final_path = final_dir / sha256

        # Defence in depth: the path is derived from a hex digest, but assert the
        # invariant anyway so a future refactor cannot silently escape the dir.
        if not final_path.resolve().is_relative_to(dest_dir):
            raise ValidationError("resolved artifact path escapes storage directory")

        if final_path.exists():
            # Identical content already stored; keep the original copy.
            staging_path.unlink(missing_ok=True)
        else:
            staging_path.replace(final_path)
            _restrict_permissions(final_path)

        return StoredArtifact(
            sha256=sha256,
            size_bytes=size,
            path=final_path,
            safe_filename=sanitize_filename(original_filename),
            detected_kind=resolved_kind,
            mime_type=mime_type,
        )
    except BaseException:
        staging_path.unlink(missing_ok=True)
        raise


async def store_bytes(
    data: bytes,
    *,
    dest_dir: Path,
    max_bytes: int,
    original_filename: str = "",
    declared_kind: ArtifactKind = ArtifactKind.UNKNOWN,
) -> StoredArtifact:
    """Convenience helper to store an in-memory byte buffer into quarantine storage."""

    async def _byte_gen() -> AsyncIterator[bytes]:
        yield data

    return await store_stream(
        _byte_gen(),
        dest_dir=dest_dir,
        max_bytes=max_bytes,
        original_filename=original_filename,
        declared_kind=declared_kind,
    )


def _restrict_permissions(path: Path) -> None:
    """Remove group/other access and any execute bit where the OS supports it."""
    if os.name == "posix":
        path.chmod(0o600)


def read_text(path: Path, *, max_bytes: int = DEFAULT_MAX_TEXT_BYTES) -> tuple[str, bool]:
    """Read an artifact as text.

    Returns ``(text, lossy)``. Log files are frequently not valid UTF-8, so a
    latin-1 fallback is used rather than failing the investigation; ``lossy``
    records that a fallback happened so evidence can note it.
    """
    raw = path.read_bytes()[:max_bytes]
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw.decode("latin-1"), True
