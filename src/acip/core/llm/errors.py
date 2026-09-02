"""Typed errors for LLM providers and model routing.

Enforces the fallback taxonomy specified in docs/model-abstraction.md:
- Retryable / Fallback errors: QuotaExceeded, RateLimited, Unavailable, Timeout
- Non-fallback errors: Refused, SchemaValidationFailed, AuthError
"""

from __future__ import annotations

from typing import Any

from acip.errors import ACIPError


class LLMError(ACIPError):
    """Base exception for all LLM provider and routing failures."""

    status_code: int = 500
    code: str = "llm_error"
    can_fallback: bool = False

    def __init__(
        self,
        message: str,
        *,
        provider: str = "",
        model: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, detail=detail)
        self.provider = provider
        self.model = model


class ProviderQuotaExceeded(LLMError):
    """The provider quota/credits are exhausted. Safe to fall back to secondary."""

    status_code = 429
    code = "provider_quota_exceeded"
    can_fallback = True


class ProviderRateLimited(LLMError):
    """Transient rate limit hit. Retry once, then fall back."""

    status_code = 429
    code = "provider_rate_limited"
    can_fallback = True

    def __init__(
        self,
        message: str,
        *,
        provider: str = "",
        model: str = "",
        retry_after: float = 1.0,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, provider=provider, model=model, detail=detail)
        self.retry_after = retry_after


class ProviderUnavailable(LLMError):
    """Network connection failure or 5xx error from provider. Safe to fall back."""

    status_code = 503
    code = "provider_unavailable"
    can_fallback = True


class ProviderTimeout(LLMError):
    """Provider exceeded request timeout. Safe to fall back."""

    status_code = 504
    code = "provider_timeout"
    can_fallback = True


class ProviderRefused(LLMError):
    """Model refused to process request (e.g. content policy). DO NOT fall back."""

    status_code = 400
    code = "provider_refused"
    can_fallback = False


class SchemaValidationFailed(LLMError):
    """Structured output failed Pydantic validation after repair retries. DO NOT fall back."""

    status_code = 422
    code = "schema_validation_failed"
    can_fallback = False


class ProviderAuthError(LLMError):
    """Authentication or permissions failed with provider. DO NOT fall back."""

    status_code = 401
    code = "provider_auth_error"
    can_fallback = False


class NoAvailableProviderError(LLMError):
    """All candidate models for a task class failed."""

    status_code = 503
    code = "no_available_provider"
    can_fallback = False


class BudgetExceededError(LLMError):
    """Investigation token or cost ceiling exceeded."""

    status_code = 400
    code = "llm_budget_exceeded"
    can_fallback = False


__all__ = [
    "BudgetExceededError",
    "LLMError",
    "NoAvailableProviderError",
    "ProviderAuthError",
    "ProviderQuotaExceeded",
    "ProviderRateLimited",
    "ProviderRefused",
    "ProviderTimeout",
    "ProviderUnavailable",
    "SchemaValidationFailed",
]
