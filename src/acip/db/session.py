"""Async engine and session management.

Exposed as a class rather than module globals so tests can stand up isolated
databases without monkeypatching, and so the API can own a single instance
through its lifespan.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
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
