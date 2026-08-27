from __future__ import annotations

import datetime as dt
import uuid

import pytest

from acip.core.security.tokens import create_access_token, decode_access_token
from acip.errors import AuthenticationError
from acip.types import Role

SECRET = "super-secret-key-that-is-sufficiently-long-for-testing-at-least-32-bytes"


def test_token_lifecycle() -> None:
    user_id = uuid.uuid4()
    token = create_access_token(
        user_id=user_id,
        role=Role.INVESTIGATOR,
        secret=SECRET,
        ttl_minutes=15,
    )
    payload = decode_access_token(token, secret=SECRET)
    assert payload.user_id == user_id
    assert payload.role == Role.INVESTIGATOR


def test_expired_token_rejected() -> None:
    user_id = uuid.uuid4()
    past = dt.datetime(2020, 1, 1, 0, 0, 0, tzinfo=dt.UTC)
    token = create_access_token(
        user_id=user_id,
        role=Role.VIEWER,
        secret=SECRET,
        ttl_minutes=1,
        now=past,
    )
    with pytest.raises(AuthenticationError, match="expired"):
        decode_access_token(token, secret=SECRET)


def test_wrong_secret_rejected() -> None:
    user_id = uuid.uuid4()
    token = create_access_token(
        user_id=user_id,
        role=Role.ADMIN,
        secret=SECRET,
        ttl_minutes=15,
    )
    with pytest.raises(AuthenticationError, match="invalid"):
        decode_access_token(token, secret="different-secret-key-at-least-32-bytes-long")
