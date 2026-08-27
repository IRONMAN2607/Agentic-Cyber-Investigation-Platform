"""Password hashing.

Argon2id via ``argon2-cffi``, which is the current OWASP recommendation and
handles salting and parameter encoding internally.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from acip.errors import ValidationError

# Defaults from argon2-cffi (Argon2id, 64 MiB, t=3, p=4) are appropriate for a
# server-side interactive login; pinned here so a library change is a visible diff.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters long",
            detail={"min_length": MIN_PASSWORD_LENGTH},
        )
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return whether the password matches. Never raises on a bad password."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the hash was produced with weaker parameters than current."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
