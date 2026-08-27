"""Application bootstrap.

Migrates the schema to head and, outside production, seeds an initial
administrator so a fresh checkout is usable without manual SQL.

The seed refuses to run in production. A default credential that reaches a
deployed system is a real vulnerability, and "we documented that you should
change it" is not a control.
"""

from __future__ import annotations

import sqlalchemy as sa

from acip.config import Settings
from acip.core.security.passwords import hash_password
from acip.db.migrate import upgrade_to_head
from acip.db.models import User
from acip.db.session import Database
from acip.logging import get_logger
from acip.types import Role

logger = get_logger(__name__)


async def bootstrap(database: Database, settings: Settings) -> None:
    """Prepare storage and seed development data."""
    settings.ensure_directories()
    await upgrade_to_head(database.url)
    if not settings.is_prod:
        await seed_admin(database, settings)


async def seed_admin(database: Database, settings: Settings) -> User | None:
    """Create the bootstrap admin if it does not already exist.

    Returns ``None`` when nothing was created, so callers can log truthfully.
    """
    if settings.is_prod:
        logger.info("admin seeding skipped in production")
        return None

    username = settings.bootstrap_admin_username
    async with database.session() as session:
        existing = await session.scalar(sa.select(User).where(User.username == username))
        if existing is not None:
            return None

        user = User(
            username=username,
            password_hash=hash_password(settings.bootstrap_admin_password.get_secret_value()),
            role=Role.ADMIN.value,
        )
        session.add(user)
        await session.flush()
        logger.warning(
            "seeded development administrator; change this password before any non-local use",
            extra={"username": username},
        )
        return user
