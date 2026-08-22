"""Authentication endpoints."""

from __future__ import annotations

from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from acip.api.deps import CurrentUser, Services, get_services, get_session
from acip.api.schemas import LoginRequest, TokenResponse, UserResponse
from acip.core import audit
from acip.core.security.passwords import hash_password, verify_password
from acip.core.security.tokens import create_access_token
from acip.db.models import User
from acip.errors import AuthenticationError
from acip.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["auth"])

# Verifying against a real hash on a missing username keeps the response time
# for "no such user" and "wrong password" comparable, so the endpoint does not
# enumerate valid usernames by timing.
_DUMMY_HASH = hash_password("timing-equalisation-placeholder")


@router.post("/auth/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> TokenResponse:
    """Exchange credentials for a short-lived access token."""
    settings = services.settings
    user = await session.scalar(sa.select(User).where(User.username == payload.username))

    if user is None:
        verify_password(payload.password, _DUMMY_HASH)
        await audit.record(
            session,
            actor=payload.username,
            action=audit.LOGIN_FAILED,
            resource_type="user",
            outcome=audit.FAILURE,
            detail={"reason": "unknown_user"},
        )
        raise AuthenticationError("invalid credentials")

    if not user.is_active or not verify_password(payload.password, user.password_hash):
        await audit.record(
            session,
            actor=user.username,
            action=audit.LOGIN_FAILED,
            resource_type="user",
            resource_id=str(user.id),
            outcome=audit.FAILURE,
            detail={"reason": "inactive" if not user.is_active else "bad_password"},
        )
        # The same message for both cases: the client learns nothing about which
        # part was wrong.
        raise AuthenticationError("invalid credentials")

    token = create_access_token(
        user_id=user.id,
        role=user.role_enum,
        secret=settings.secret_key.get_secret_value(),
        ttl_minutes=settings.access_token_ttl_minutes,
        algorithm=settings.jwt_algorithm,
    )
    await audit.record(
        session,
        actor=user.username,
        action=audit.LOGIN_SUCCEEDED,
        resource_type="user",
        resource_id=str(user.id),
    )
    return TokenResponse(
        access_token=token,
        expires_in_seconds=settings.access_token_ttl_minutes * 60,
        user=UserResponse.model_validate(user),
    )


@router.get("/auth/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def me(user: CurrentUser) -> UserResponse:
    return UserResponse.model_validate(user)
