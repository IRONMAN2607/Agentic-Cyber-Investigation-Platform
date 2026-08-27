from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from acip.api.app import create_app
from acip.bootstrap import bootstrap
from acip.config import Settings
from acip.core.security.passwords import hash_password
from acip.core.security.tokens import create_access_token
from acip.db.models import User
from acip.db.session import Database
from acip.types import Role


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    db_file = tmp_path / "test.db"
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{db_file.as_posix()}",
        artifact_dir=artifact_dir,
        secret_key=SecretStr("test-secret-key-that-is-at-least-32-bytes-long-for-hs256"),
        bootstrap_admin_username="admin",
        bootstrap_admin_password=SecretStr("admin-password-123"),
        access_token_ttl_minutes=60,
    )


@pytest.fixture
async def database(settings: Settings) -> AsyncIterator[Database]:
    db = Database(settings.database_url, echo=False)
    await bootstrap(db, settings)
    try:
        yield db
    finally:
        await db.dispose()


@pytest.fixture
async def app(settings: Settings, database: Database) -> AsyncIterator[FastAPI]:
    app_instance = create_app(settings=settings, database=database, run_bootstrap=False)
    async with app_instance.router.lifespan_context(app_instance):
        yield app_instance


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def users(database: Database, settings: Settings) -> dict[Role, tuple[User, str]]:
    """Create test users for each role and generate their valid tokens."""
    result: dict[Role, tuple[User, str]] = {}
    async with database.session() as session:
        for role in (Role.ADMIN, Role.INVESTIGATOR, Role.VIEWER):
            user = User(
                username=f"test_{role.value}",
                password_hash=hash_password(f"password-12345-{role.value}"),
                role=role.value,
            )
            session.add(user)
            await session.flush()
            token = create_access_token(
                user_id=user.id,
                role=role,
                secret=settings.secret_key.get_secret_value(),
                ttl_minutes=settings.access_token_ttl_minutes,
            )
            result[role] = (user, token)
    return result


@pytest.fixture
def auth_headers(users: dict[Role, tuple[User, str]]) -> dict[Role, dict[str, str]]:
    return {role: {"Authorization": f"Bearer {token}"} for role, (_, token) in users.items()}
