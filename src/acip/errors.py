"""Typed application errors.

Each error carries an HTTP status and a stable machine-readable ``code`` so the
API can return consistent bodies without scattering ``HTTPException`` through
the domain layer. Domain modules raise these; the API layer translates them.
"""

from __future__ import annotations

from typing import Any


class ACIPError(Exception):
    """Base class for all application errors."""

    status_code: int = 500
    code: str = "internal_error"

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class ConfigurationError(ACIPError):
    code = "configuration_error"


class NotFoundError(ACIPError):
    status_code = 404
    code = "not_found"


class ValidationError(ACIPError):
    status_code = 422
    code = "validation_error"


class AuthenticationError(ACIPError):
    status_code = 401
    code = "authentication_failed"


class AuthorizationError(ACIPError):
    status_code = 403
    code = "not_authorized"


class ConflictError(ACIPError):
    status_code = 409
    code = "conflict"


class RateLimitExceededError(ACIPError):
    status_code = 429
    code = "rate_limit_exceeded"

    def __init__(self, retry_after: int, message: str | None = None) -> None:
        super().__init__(
            message or f"Rate limit exceeded. Try again in {retry_after} seconds.",
            detail={"retry_after": retry_after},
        )
        self.retry_after = retry_after


class PayloadTooLargeError(ACIPError):
    status_code = 413
    code = "payload_too_large"


class GroundingError(ACIPError):
    """Raised when a claim violates an evidence-grounding invariant.

    This is a programming/agent error, not a user error: it means an agent tried
    to assert something the evidence does not support. See
    docs/evidence-model.md for the invariants.
    """

    status_code = 500
    code = "grounding_violation"


class ToolError(ACIPError):
    """A tool adapter failed. Recorded against the tool run, not hidden."""

    code = "tool_error"


class ToolUnavailableError(ToolError):
    status_code = 503
    code = "tool_unavailable"


class ToolExecutionError(ToolError):
    status_code = 500
    code = "tool_execution_failed"


class AgentError(ACIPError):
    code = "agent_error"
