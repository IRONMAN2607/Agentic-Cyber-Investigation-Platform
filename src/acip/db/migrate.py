"""Schema creation, through Alembic and only through Alembic.

The migration chain in ``migrations/`` is the single source of truth for the
schema. ``Base.metadata.create_all`` used to be a second one, and two sources
of truth for a schema is a drift bug that waits for the first environment where
they disagree — most likely production, since that is the only place the
migrations would have run.

Every path that needs a schema goes through :func:`upgrade_to_head`: the API
lifespan, ``acip init``, ``acip create-user``, and every test fixture. That is
deliberate. It means the migrations are exercised by the whole test suite
rather than by a manual command nobody runs, and a revision that fails to
apply fails ``pytest`` instead of a deployment.

Migrations run on a dedicated short-lived engine rather than the application's
own. Two reasons, both load-bearing:

* The application engine attaches ``PRAGMA foreign_keys=ON``. Alembic's SQLite
  batch mode implements an altered constraint as a table rebuild — create,
  copy, drop, rename — and dropping a referenced table with enforcement on is
  a hazard the rebuild does not need. ``0003`` is exactly such a rebuild.
* ``PRAGMA foreign_keys`` is a no-op inside a transaction, so enforcement
  cannot simply be toggled around the upgrade on a connection already in one.

The consequence is that in-memory SQLite cannot be migrated: a second engine
opening ``:memory:`` gets a second, empty database. That is raised rather than
worked around, because the alternative is a schema that silently is not there.
``docs/testing.md`` §1 records that tests use file-backed SQLite on purpose.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from acip.errors import ConfigurationError
from acip.logging import get_logger

logger = get_logger(__name__)

#: Repository root, from ``<root>/src/acip/db/migrate.py``.
_ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS_DIR = _ROOT / "migrations"


def alembic_config(url: str) -> Config:
    """Build an Alembic config without reading ``alembic.ini``.

    The ini file carries a hardcoded development URL. Constructing the config
    in code means the URL always comes from settings, so no caller can migrate
    a database it did not mean to.
    """
    if not MIGRATIONS_DIR.is_dir():
        raise ConfigurationError(
            "migrations directory not found; the package must be installed from a checkout",
            detail={"expected": str(MIGRATIONS_DIR)},
        )
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", url)
    return config


def _upgrade(connection: Connection, url: str, revision: str) -> None:
    config = alembic_config(url)
    config.attributes["connection"] = connection
    command.upgrade(config, revision)


async def upgrade_to_head(url: str, revision: str = "head") -> None:
    """Bring the database at ``url`` up to ``revision``, creating it if absent."""
    if ":memory:" in url:
        raise ConfigurationError(
            "in-memory SQLite cannot be migrated; use a file-backed database",
            detail={"url": url},
        )

    engine = create_async_engine(url, poolclass=pool.NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(_upgrade, url, revision)
    finally:
        await engine.dispose()
    logger.info("schema migrated", extra={"revision": revision})
