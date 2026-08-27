from __future__ import annotations

import pytest

from acip.core.security.passwords import hash_password, needs_rehash, verify_password
from acip.errors import ValidationError


def test_password_hash_and_verify() -> None:
    raw = "correct-horse-battery-staple"
    hashed = hash_password(raw)
    assert hashed.startswith("$argon2id$")
    assert verify_password(raw, hashed)
    assert not verify_password("wrong-password", hashed)


def test_verify_password_invalid_hash_safe() -> None:
    # Must return False, not raise
    assert not verify_password("some_password", "not-a-valid-argon2-hash")
    assert not verify_password("some_password", "")


def test_password_min_length_enforced() -> None:
    with pytest.raises(ValidationError, match="at least"):
        hash_password("short")


def test_needs_rehash() -> None:
    raw = "correct-horse-battery-staple"
    hashed = hash_password(raw)
    assert not needs_rehash(hashed)
    assert needs_rehash("corrupted-hash")
