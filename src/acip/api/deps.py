"""FastAPI dependencies.

Shared services (database, registries, orchestrator, runner) are constructed once
during lifespan and stored on ``app.state``. Dependencies read them from the
request rather than from module globals, which is what lets a test build an app
against an isolated database without patching anything.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated

import sqlalchemy as sa
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from acip.agents.registry import AgentRegistry
from acip.config import Settings
from acip.core.orchestration.planner import Planner
from acip.core.orchestration.runner import InvestigationRunner
from acip.core.security.authz import require_role
from acip.core.security.tokens import decode_access_token
from acip.db.models import Investigation, User
from acip.db.session import Database
from acip.errors import AuthenticationError, NotFoundError
from acip.logging import bind_context
from acip.tools.registry import ToolRegistry
from acip.types import Role

if TYPE_CHECKING:
    from acip.core.llm.router import ModelRouter

# auto_error=False so a missing header produces our own error envelope rather
# than FastAPI's, keeping every 401 shaped the same.
_bearer = HTTPBearer(auto_error=False)


@dataclass
class Services:
    """Everything built once at startup."""

    settings: Settings
    database: Database
    tools: ToolRegistry
    agents: AgentRegistry
    planner: Planner
    runner: InvestigationRunner
    router: ModelRouter | None = None


def get_services(request: Request) -> Services:
    services: Services | None = getattr(request.app.state, "services", None)
    if services is None:  # pragma: no cover - lifespan always sets this
        raise RuntimeError("application services are not initialised")
    return services


def get_settings_dep(services: Annotated[Services, Depends(get_services)]) -> Settings:
    return services.settings


async def get_session(
    services: Annotated[Services, Depends(get_services)],
) -> AsyncIterator[AsyncSession]:
    """One transaction per request, committed on a clean response."""
    async with services.database.session() as session:
        yield session


async def get_current_user(
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    """Resolve the bearer token to an active user."""
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("missing bearer token")

    payload = decode_access_token(
        credentials.credentials,
        secret=services.settings.secret_key.get_secret_value(),
        algorithm=services.settings.jwt_algorithm,
    )
    user = await session.get(User, payload.user_id)
    if user is None or not user.is_active:
        # A valid signature over a deleted or disabled account must still fail.
        raise AuthenticationError("account is not active")

    # The role in the token is not trusted over the database: a demotion takes
    # effect immediately rather than at token expiry.
    bind_context(actor=user.username)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_investigator(user: CurrentUser) -> User:
    require_role(user.role_enum, Role.INVESTIGATOR, action="modify investigations")
    return user


def require_admin(user: CurrentUser) -> User:
    require_role(user.role_enum, Role.ADMIN, action="perform administrative actions")
    return user


Investigator = Annotated[User, Depends(require_investigator)]
Admin = Annotated[User, Depends(require_admin)]


async def get_investigation(
    investigation_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    _user: CurrentUser,
) -> Investigation:
    """Load an investigation or 404.

    M1 has no per-investigation ownership: any authenticated user may read any
    investigation. That is a stated limitation, not an omission — multi-tenant
    scoping is a Phase 5 concern and belongs in one place, not sprinkled here.
    """
    investigation = await session.scalar(
        sa.select(Investigation).where(Investigation.id == investigation_id)
    )
    if investigation is None:
        raise NotFoundError(f"investigation {investigation_id} not found")
    bind_context(investigation_id=str(investigation_id))
    return investigation


LoadedInvestigation = Annotated[Investigation, Depends(get_investigation)]
