from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from acip.core.security.files import (
    read_text,
    sanitize_filename,
    store_stream,
)
from acip.errors import PayloadTooLargeError, ValidationError


def test_sanitize_filename() -> None:
    assert sanitize_filename("../../../etc/passwd") == "passwd"
    assert sanitize_filename("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("   ") == "artifact"
    assert sanitize_filename("---leading-dashes.log") == "leading-dashes.log"
    assert sanitize_filename("evil\x00file.log") == "evil_file.log"


async def test_store_stream_success(tmp_path: Path) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"line 1\n"
        yield b"line 2\n"

    stored = await store_stream(
        chunks(), dest_dir=tmp_path, max_bytes=1024, original_filename="test.log"
    )
    assert stored.size_bytes == 14
    assert stored.path.exists()
    assert stored.safe_filename == "test.log"
    assert stored.path.is_relative_to(tmp_path)


async def test_store_stream_oversized_rejected(tmp_path: Path) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"A" * 100
        yield b"B" * 100

    with pytest.raises(PayloadTooLargeError):
        await store_stream(chunks(), dest_dir=tmp_path, max_bytes=150)


async def test_store_stream_empty_rejected(tmp_path: Path) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b""

    with pytest.raises(ValidationError, match="empty"):
        await store_stream(chunks(), dest_dir=tmp_path, max_bytes=1024)


def test_read_text_utf8_and_latin1(tmp_path: Path) -> None:
    p_utf8 = tmp_path / "valid.txt"
    p_utf8.write_text("hello world 🚀", encoding="utf-8")
    text, lossy = read_text(p_utf8)
    assert text == "hello world 🚀"
    assert not lossy

    # Write invalid UTF-8 bytes that are valid Latin-1
    p_latin1 = tmp_path / "invalid_utf8.txt"
    p_latin1.write_bytes(b"hello \xff\xfe world")
    text, lossy = read_text(p_latin1)
    assert lossy
    assert "hello" in text
