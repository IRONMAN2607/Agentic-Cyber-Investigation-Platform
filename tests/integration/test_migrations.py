"""The migration chain is the schema, so the suite runs on it.

Every fixture reaches its schema through ``bootstrap`` → ``upgrade_to_head``, so
all 97 tests already exercise the migrations. These tests close the loop by
asserting the two things that silent drift would break:

* the database ends up stamped at the chain's head, and
* the head schema still matches ``Base.metadata``.

The second one is the point. A model gains a column, nobody writes a revision,
and the application keeps working right up until it runs somewhere the schema
was built by Alembic. Making that a test failure is cheaper than making it a
deployment failure.
"""

from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection

from acip.config import Settings
from acip.db.migrate import alembic_config, upgrade_to_head
from acip.db.models import Base
from acip.db.session import Database
from acip.errors import ConfigurationError

pytestmark = pytest.mark.asyncio


def _current_revision(connection: Connection) -> str | None:
    return MigrationContext.configure(connection).get_current_revision()


def _schema_diff(connection: Connection) -> list[object]:
    context = MigrationContext.configure(connection)
    return list(compare_metadata(context, Base.metadata))


async def test_bootstrap_stamps_the_database_at_head(database: Database) -> None:
    """The fixture's schema came from Alembic, not from ``create_all``."""
    head = ScriptDirectory.from_config(alembic_config(database.url)).get_current_head()
    assert head is not None

    async with database.engine.connect() as conn:
        stamped = await conn.run_sync(_current_revision)

    assert stamped == head


async def test_models_and_migrations_do_not_drift(database: Database) -> None:
    """``Base.metadata`` describes exactly what the migrations build."""
    async with database.engine.connect() as conn:
        diff = await conn.run_sync(_schema_diff)

    assert diff == [], f"models and migrations disagree; a revision is missing: {diff}"


async def test_in_memory_is_refused_rather_than_silently_unmigrated(
    settings: Settings,
) -> None:
    """A second engine on ``:memory:`` would migrate a different database."""
    with pytest.raises(ConfigurationError, match="in-memory SQLite cannot be migrated"):
        await upgrade_to_head("sqlite+aiosqlite:///:memory:")
