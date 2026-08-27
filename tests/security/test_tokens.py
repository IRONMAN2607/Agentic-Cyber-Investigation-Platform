from __future__ import annotations

import datetime as dt
import uuid

import jwt
import pytest

from acip.core.security.tokens import create_access_token, decode_access_token
from acip.errors import AuthenticationError
from acip.types import Role

SECRET = "super-secret-key-that-is-at-least-32-bytes-long-for-testing"


def test_token_tampered_rejected() -> None:
    token = create_access_token(
        user_id=uuid.uuid4(),
        role=Role.INVESTIGATOR,
        secret=SECRET,
        ttl_minutes=15,
    )
    # Tamper with the payload part
    parts = token.split(".")
    tampered = f"{parts[0]}.eyJyYW5kb20iOiAidmFsdWUifQ.{parts[2]}"
    with pytest.raises(AuthenticationError, match="invalid"):
        decode_access_token(tampered, secret=SECRET)


def test_token_unsigned_algorithm_none_rejected() -> None:
    # Attempt to forge an unsigned token with alg: none
    claims = {
        "sub": str(uuid.uuid4()),
        "role": Role.ADMIN.value,
        "typ": "access",
        "iat": int(dt.datetime.now(dt.UTC).timestamp()),
        "exp": int((dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15)).timestamp()),
    }
    # Manually craft an unencoded or raw header
    token_none = jwt.encode(claims, key="", algorithm="none")
    with pytest.raises(AuthenticationError):
        decode_access_token(token_none, secret=SECRET, algorithm="HS256")


def test_token_wrong_type_claim_rejected() -> None:
    claims = {
        "sub": str(uuid.uuid4()),
        "role": Role.ADMIN.value,
        "typ": "refresh",  # Not access
        "iat": int(dt.datetime.now(dt.UTC).timestamp()),
        "exp": int((dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15)).timestamp()),
    }
    token = jwt.encode(claims, SECRET, algorithm="HS256")
    with pytest.raises(AuthenticationError, match="wrong token type"):
        decode_access_token(token, secret=SECRET)
