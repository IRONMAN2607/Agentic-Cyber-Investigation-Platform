"""Safe artifact intake.

Uploaded artifacts are untrusted by definition — in later phases they include
live malware samples. Three properties are enforced here:

1. **No client-controlled paths.** Storage is content-addressed by SHA-256, so
   the client filename never reaches the filesystem. This removes path
   traversal as a category rather than filtering for it.
2. **Bounded size.** The stream is capped while reading, so an oversized upload
   is rejected without first being buffered to disk or memory.
3. **No execute bit.** Files are written 0o600 on POSIX. Nothing in the
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

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_FILENAME = 128
# Cap decoded text so a large artifact cannot exhaust memory inside a parser.
DEFAULT_MAX_TEXT_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class StoredArtifact:
    """Result of a successful intake."""

    sha256: str
    size_bytes: int
    path: Path
    safe_filename: str


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


async def store_stream(
    chunks: AsyncIterator[bytes],
    *,
    dest_dir: Path,
    max_bytes: int,
    original_filename: str = "",
) -> StoredArtifact:
    """Consume ``chunks`` into content-addressed storage under ``dest_dir``.

    Raises :class:`PayloadTooLargeError` as soon as the cap is exceeded, and
    :class:`ValidationError` for an empty upload.
    """
    dest_dir = dest_dir.resolve()  # noqa: ASYNC240
    staging_dir = dest_dir / "_staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256()
    size = 0
    # Unique staging name so concurrent uploads cannot collide before hashing.
    staging_path = staging_dir / f"upload-{os.urandom(12).hex()}"

    try:
        with staging_path.open("wb") as handle:
            async for chunk in chunks:
                if not chunk:
                    continue
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
        )
    except BaseException:
        staging_path.unlink(missing_ok=True)
        raise


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
