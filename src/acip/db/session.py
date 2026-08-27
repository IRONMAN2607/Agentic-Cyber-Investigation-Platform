"""Async engine and session management.

Exposed as a class rather than module globals so tests can stand up isolated
databases without monkeypatching, and so the API can own a single instance
through its lifespan.
"""

from __future__ import annotations

import contextvars
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import ORMExecuteState
from sqlalchemy.orm import Session as SyncSession
from sqlalchemy.pool import StaticPool

from acip.db.base import Base
from acip.logging import get_logger

logger = get_logger(__name__)


def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    """SQLite ignores foreign keys unless asked, and defaults to slow sync writes."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


# --- Append-only enforcement at the session boundary -------------------------
# The mapper events in acip.db.models reject mutation of a *loaded instance*.
# They never fire for bulk DML: ``session.execute(update(Evidence))`` rewrites
# history without constructing an Evidence object at all. This guard closes
# that path for every session in the process.
#
# The boundary is worth stating plainly rather than implying the guarantee is
# total: raw ``session.execute(text("UPDATE evidence ..."))`` bypasses the ORM
# and is still not covered. Database-level enforcement — revoking grants on
# PostgreSQL — is Phase 5, and that is what makes the guarantee hold against
# code that does not go through SQLAlchemy at all.

APPEND_ONLY_TABLES = frozenset({"evidence", "audit_log", "llm_calls"})

_purge_authorized: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "acip_purge_authorized", default=False
)


@contextmanager
def authorized_purge() -> Iterator[None]:
    """Permit append-only deletion within this block.

    The single sanctioned destructive path — an audited investigation purge that
    records what it removed — has to delete evidence. It opts in by name so the
    exception stays narrow and greppable: one search shows every place the
    append-only guarantee is deliberately set aside.
    """
    token = _purge_authorized.set(True)
    try:
        yield
    finally:
        _purge_authorized.reset(token)


def _forbid_bulk_dml(state: ORMExecuteState) -> None:
    """Reject bulk UPDATE/DELETE against an append-only table."""
    if not (state.is_update or state.is_delete):
        return
    if _purge_authorized.get():
        return

    for mapper in state.all_mappers:
        table = mapper.local_table
        name = getattr(table, "name", None)
        if name in APPEND_ONLY_TABLES:
            verb = "updated" if state.is_update else "deleted"
            raise RuntimeError(
                f"{name} is append-only and cannot be {verb} in bulk; "
                "record a superseding row instead"
            )


event.listen(SyncSession, "do_orm_execute", _forbid_bulk_dml)


class Database:
    """Owns the engine and session factory for one database URL."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        self.url = url
        kwargs: dict[str, Any] = {"echo": echo, "future": True}

        if url.startswith("sqlite"):
            # An in-memory SQLite database lives inside a single connection, so
            # the pool must hand out that same connection everywhere.
            if ":memory:" in url:
                kwargs["poolclass"] = StaticPool
                kwargs["connect_args"] = {"check_same_thread": False}

        self._engine: AsyncEngine = create_async_engine(url, **kwargs)

        if url.startswith("sqlite"):
            event.listen(self._engine.sync_engine, "connect", _sqlite_pragmas)

        self._sessionmaker = async_sessionmaker(
            self._engine, expire_on_commit=False, autoflush=False
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    async def create_all(self) -> None:
        """Create the schema.

        M1 uses ``create_all`` deliberately: there is no deployed data yet, and
        the schema changes substantially when PostgreSQL becomes mandatory in
        Phase 5. Alembic is introduced there with a single baseline revision.
        """
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("schema ready", extra={"database": _redact(self.url)})

    async def dispose(self) -> None:
        await self._engine.dispose()

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session, committing on success and rolling back on error."""
        async with self._sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._sessionmaker


def _redact(url: str) -> str:
    """Strip credentials before a URL reaches the logs."""
    if "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    return f"{scheme}://***@{rest.rpartition('@')[2]}"
