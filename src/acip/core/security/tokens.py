"""JWT access tokens.

Short-lived bearer tokens signed with HS256. Refresh tokens and revocation are
deliberately out of scope for M1; the token type claim is present so adding a
refresh flow later cannot accidentally accept an access token in its place.
"""

from __future__ import annotations

import datetime as dt
import uuid

import jwt
from pydantic import BaseModel, Field

from acip.errors import AuthenticationError
from acip.types import Role

TOKEN_TYPE_ACCESS = "access"  # noqa: S105


class TokenPayload(BaseModel):
    """Validated token claims."""

    sub: str
    role: Role
    typ: str = TOKEN_TYPE_ACCESS
    jti: str = Field(default_factory=lambda: str(uuid.uuid4()))
    iat: int
    exp: int

    @property
    def user_id(self) -> uuid.UUID:
        return uuid.UUID(self.sub)


def create_access_token(
    *,
    user_id: uuid.UUID,
    role: Role,
    secret: str,
    ttl_minutes: int,
    algorithm: str = "HS256",
    now: dt.datetime | None = None,
) -> str:
    issued = now or dt.datetime.now(dt.UTC)
    expires = issued + dt.timedelta(minutes=ttl_minutes)
    claims = {
        "sub": str(user_id),
        "role": role.value,
        "typ": TOKEN_TYPE_ACCESS,
        "jti": str(uuid.uuid4()),
        "iat": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
    }
    return jwt.encode(claims, secret, algorithm=algorithm)


def decode_access_token(token: str, *, secret: str, algorithm: str = "HS256") -> TokenPayload:
    """Decode and validate a token, or raise :class:`AuthenticationError`."""
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[algorithm],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("invalid token") from exc

    payload = TokenPayload.model_validate(claims)
    if payload.typ != TOKEN_TYPE_ACCESS:
        raise AuthenticationError("wrong token type")
    return payload
