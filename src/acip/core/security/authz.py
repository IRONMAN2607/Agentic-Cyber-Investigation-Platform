"""Role-based authorization.

Roles are ordered: an admin can do anything an investigator can, and so on.
Kept separate from the API layer so the same check is available to background
workers, which have no request context.
"""

from __future__ import annotations

from acip.errors import AuthorizationError
from acip.types import Role

_ORDER: dict[Role, int] = {Role.VIEWER: 0, Role.INVESTIGATOR: 1, Role.ADMIN: 2}


def has_role(actual: Role, required: Role) -> bool:
    return _ORDER[actual] >= _ORDER[required]


def require_role(actual: Role, required: Role, *, action: str) -> None:
    """Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``."""
    if not has_role(actual, required):
        raise AuthorizationError(
            f"role '{actual.value}' may not {action}",
            detail={"required_role": required.value, "actual_role": actual.value},
        )
