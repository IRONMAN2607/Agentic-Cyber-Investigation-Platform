"""Shared test fixtures.

Each test gets a file-backed SQLite database in a temporary directory rather than
``:memory:``. The orchestrator deliberately opens several short-lived sessions per
task, and an in-memory database pinned to one connection would hide exactly the
cross-transaction visibility problems worth catching.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from acip.agents.registry import build_default_registry as build_agent_registry
from acip.api.app import create_app
from acip.bootstrap import seed_admin
from acip.config import Settings
from acip.core.evidence.store import EvidenceStore
from acip.core.orchestration.orchestrator import Orchestrator
from acip.core.orchestration.planner import StaticPlanner
from acip.core.orchestration.runner import InvestigationRunner
from acip.db.models import Investigation
from acip.db.session import Database
from acip.tools.registry import build_default_registry as build_tool_registry
from acip.types import InvestigationStatus, TargetType

ADMIN_PASSWORD = "test-admin-password"

# A brute-force burst followed by a success and a root sudo, so the fixture
# exercises all four R-AUTH rules. Values use RFC 5737 documentation ranges.
AUTH_LOG_SAMPLE = """\
Mar 10 03:11:01 web01 sshd[2011]: Failed password for invalid user admin from 203.0.113.55 port 51001 ssh2
Mar 10 03:11:04 web01 sshd[2012]: Failed password for invalid user oracle from 203.0.113.55 port 51002 ssh2
Mar 10 03:11:08 web01 sshd[2013]: Failed password for invalid user postgres from 203.0.113.55 port 51003 ssh2
Mar 10 03:11:12 web01 sshd[2014]: Failed password for deploy from 203.0.113.55 port 51004 ssh2
Mar 10 03:11:16 web01 sshd[2015]: Failed password for deploy from 203.0.113.55 port 51005 ssh2
Mar 10 03:11:21 web01 sshd[2016]: Failed password for deploy from 203.0.113.55 port 51006 ssh2
Mar 10 03:11:30 web01 sshd[2017]: Accepted password for deploy from 203.0.113.55 port 51007 ssh2
Mar 10 03:12:02 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Mar 10 03:12:03 web01 sshd[2018]: Connection closed by 198.51.100.9 port 40222
"""


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        secret_key=SecretStr("unit-test-secret-key-that-is-long-enough"),
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'acip.db').as_posix()}",
        artifact_dir=tmp_path / "artifacts",
        log_level="WARNING",
        log_format="console",
        bootstrap_admin_password=SecretStr(ADMIN_PASSWORD),
        max_investigation_seconds=60,
        cors_origins=[],
    )


@pytest.fixture
async def database(settings: Settings) -> AsyncIterator[Database]:
    settings.ensure_directories()
    db = Database(settings.database_url)
    await db.create_all()
    try:
        yield db
    finally:
        await db.dispose()


@pytest.fixture
async def seeded_admin(database: Database, settings: Settings) -> None:
    await seed_admin(database, settings)


@pytest.fixture
async def app_client(
    settings: Settings, database: Database, seeded_admin: None
) -> AsyncIterator[AsyncClient]:
    """An HTTP client bound to the app, sharing the test's database."""
    app = create_app(settings, database=database, run_bootstrap=False)
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=30.0
        ) as client:
            yield client


@pytest.fixture
async def auth_client(app_client: AsyncClient, settings: Settings) -> AsyncClient:
    """``app_client`` with an admin bearer token already attached."""
    response = await app_client.post(
        f"{settings.api_prefix}/auth/login",
        json={"username": settings.bootstrap_admin_username, "password": ADMIN_PASSWORD},
    )
    assert response.status_code == 200, response.text
    app_client.headers["Authorization"] = f"Bearer {response.json()['access_token']}"
    return app_client


@pytest.fixture
def orchestrator(settings: Settings, database: Database) -> Orchestrator:
    agents = build_agent_registry()
    return Orchestrator(
        database=database,
        settings=settings,
        agents=agents,
        tools=build_tool_registry(),
        planner=StaticPlanner(agents),
    )


@pytest.fixture
def runner(orchestrator: Orchestrator, database: Database) -> InvestigationRunner:
    return InvestigationRunner(orchestrator=orchestrator, database=database)


@pytest.fixture
async def investigation(database: Database) -> Investigation:
    """A persisted investigation with a description target and no artifacts."""
    async with database.session() as session:
        row = Investigation(
            title="Test investigation",
            target_type=TargetType.DESCRIPTION.value,
            target_value="Suspicious logins from 203.0.113.55 against web01",
            status=InvestigationStatus.CREATED.value,
        )
        session.add(row)
        await session.flush()
        return row


@pytest.fixture
async def store(
    database: Database, investigation: Investigation
) -> AsyncIterator[EvidenceStore]:
    async with database.session() as session:
        yield EvidenceStore(session, investigation.id)


@pytest.fixture
def auth_log(tmp_path: Path) -> Path:
    path = tmp_path / "auth.log"
    path.write_text(AUTH_LOG_SAMPLE, encoding="utf-8")
    return path
