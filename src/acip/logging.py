"""Structured logging with investigation correlation.

Every log record emitted while handling an investigation carries the
investigation id, so a complete execution trace can be reconstructed from logs
alone (spec s28). Implemented on the standard library to avoid a dependency;
the context is propagated with :mod:`contextvars` so it survives ``await``.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_log_context: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "acip_log_context", default=None
)

# Attributes present on every LogRecord; anything else was added by the caller
# and should be surfaced as structured data.
_RESERVED = frozenset(
    """args asctime created exc_info exc_text filename funcName levelname levelno
    lineno module msecs message msg name pathname process processName relativeCreated
    stack_info thread threadName taskName""".split()
)


def bind_context(**values: Any) -> None:
    """Add values to the ambient logging context for the current task."""
    current = _log_context.get() or {}
    _log_context.set({**current, **values})


@contextmanager
def log_context(**values: Any) -> Iterator[None]:
    """Temporarily bind values to the logging context."""
    current = _log_context.get() or {}
    token = _log_context.set({**current, **values})
    try:
        yield
    finally:
        _log_context.reset(token)


class ContextFilter(logging.Filter):
    """Merge the ambient context into each record."""

    def filter(self, record: logging.LogRecord) -> bool:
        current = _log_context.get() or {}
        for key, value in current.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


class JSONFormatter(logging.Formatter):
    """One JSON object per line, suitable for ingestion by a log pipeline."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = _coerce(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable single-line format for local development."""

    def format(self, record: logging.LogRecord) -> str:
        extras = {
            key: _coerce(value)
            for key, value in record.__dict__.items()
            if key not in _RESERVED and not key.startswith("_")
        }
        suffix = " ".join(f"{k}={v}" for k, v in extras.items())
        base = (
            f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<7} "
            f"{record.name:<28} {record.getMessage()}"
        )
        line = f"{base}  {suffix}" if suffix else base
        if record.exc_info:
            line = f"{line}\n{self.formatException(record.exc_info)}"
        return line


def _coerce(value: Any) -> Any:
    if isinstance(value, str | int | float | bool | type(None)):
        return value
    return str(value)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Install the root handler. Idempotent, so it is safe to call in tests."""
    formatter: logging.Formatter = JSONFormatter() if fmt == "json" else ConsoleFormatter()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    handler.addFilter(ContextFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    # Uvicorn duplicates access logs through its own handlers; let ours own output.
    for noisy in ("uvicorn.access", "uvicorn.error"):
        logging.getLogger(noisy).handlers = []
        logging.getLogger(noisy).propagate = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
