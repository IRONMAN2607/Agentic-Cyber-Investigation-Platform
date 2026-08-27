"""Tier 1 tool execution sandbox.

Executes external tools as isolated subprocesses with stripped environments,
deadlines, and bounded output capture, strictly avoiding shell=True.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from pathlib import Path

from acip.errors import ToolExecutionError

# Essential platform environment variables permitted into the sandbox
_DEFAULT_ALLOWED_ENV = frozenset(
    {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "USER", "USERNAME", "LANG", "LC_ALL"}
)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    duration_ms: int


async def run_subprocess_sandboxed(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: float = 30.0,
    max_output_bytes: int = 10 * 1024 * 1024,
    extra_env: dict[str, str] | None = None,
    allowed_env_keys: frozenset[str] = _DEFAULT_ALLOWED_ENV,
) -> SandboxResult:
    """Execute a command in Tier 1 subprocess isolation.

    Guarantees:
    - Never uses shell=True.
    - Strips ambient environment variables except those explicitly allowed.
    - Enforces a hard execution timeout.
    - Limits stdout and stderr byte size.
    """
    if not args:
        raise ToolExecutionError("command argument list cannot be empty")

    # Construct minimal environment
    sandboxed_env: dict[str, str] = {}
    for key, val in os.environ.items():
        if key.upper() in allowed_env_keys:
            sandboxed_env[key] = val
    if extra_env:
        sandboxed_env.update(extra_env)

    start_time = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=sandboxed_env,
        )
    except Exception as exc:
        raise ToolExecutionError(f"failed to spawn sandboxed process {args[0]}: {exc}") from exc

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds
        )
    except TimeoutError as exc:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        duration_ms = int((time.monotonic() - start_time) * 1000)
        raise ToolExecutionError(
            f"command {args[0]} exceeded deadline of {timeout_seconds}s (killed)",
            detail={"args": args, "timeout_seconds": timeout_seconds, "duration_ms": duration_ms},
        ) from exc

    duration_ms = int((time.monotonic() - start_time) * 1000)

    # Check output size limits
    if len(stdout_bytes) > max_output_bytes:
        stdout_bytes = stdout_bytes[:max_output_bytes]
    if len(stderr_bytes) > max_output_bytes:
        stderr_bytes = stderr_bytes[:max_output_bytes]

    return SandboxResult(
        stdout=stdout_bytes,
        stderr=stderr_bytes,
        returncode=proc.returncode or 0,
        duration_ms=duration_ms,
    )
