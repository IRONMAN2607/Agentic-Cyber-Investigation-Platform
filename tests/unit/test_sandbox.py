from __future__ import annotations

import sys
from pathlib import Path

import pytest

from acip.errors import ToolExecutionError
from acip.tools.sandbox import run_subprocess_sandboxed


@pytest.mark.asyncio
async def test_sandbox_exec_success(tmp_path: Path) -> None:
    res = await run_subprocess_sandboxed(
        [sys.executable, "-c", "import sys; sys.stdout.write('hello sandboxed world')"],
        cwd=tmp_path,
        timeout_seconds=5.0,
    )
    assert res.returncode == 0
    assert res.stdout == b"hello sandboxed world"
    assert res.duration_ms >= 0


@pytest.mark.asyncio
async def test_sandbox_environment_stripped() -> None:
    import os

    os.environ["SECRET_API_KEY_TEST"] = "super-secret"

    res = await run_subprocess_sandboxed(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('SECRET_API_KEY_TEST', 'NOT_FOUND'))",
        ],
        timeout_seconds=5.0,
    )
    assert b"NOT_FOUND" in res.stdout


@pytest.mark.asyncio
async def test_sandbox_timeout_killed() -> None:
    with pytest.raises(ToolExecutionError, match="exceeded deadline"):
        await run_subprocess_sandboxed(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout_seconds=0.2,
        )


@pytest.mark.asyncio
async def test_sandbox_empty_args_rejected() -> None:
    with pytest.raises(ToolExecutionError, match="empty"):
        await run_subprocess_sandboxed([])
