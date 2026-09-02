"""Model abstraction and routing layer for ACIP.

Provides provider-agnostic model routing, candidate fallback chains, NVIDIA NIM
integration (Nemotron, DeepSeek), error handling, and structured outputs.
"""

from __future__ import annotations

from acip.core.llm.contracts import (
    ChatMessage,
    FinishReason,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    MessageRole,
    ProviderAvailability,
    TaskClass,
)
from acip.core.llm.errors import (
    BudgetExceededError,
    LLMError,
    NoAvailableProviderError,
    ProviderAuthError,
    ProviderQuotaExceeded,
    ProviderRateLimited,
    ProviderRefused,
    ProviderTimeout,
    ProviderUnavailable,
    SchemaValidationFailed,
)
from acip.core.llm.policy import CandidateModel, RoutingPolicy, TaskRoutingRule
from acip.core.llm.provider import LLMProvider
from acip.core.llm.providers.nvidia import NvidiaNIMProvider
from acip.core.llm.router import ModelRouter, build_default_router

__all__ = [
    "BudgetExceededError",
    "CandidateModel",
    "ChatMessage",
    "FinishReason",
    "LLMError",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "LLMUsage",
    "MessageRole",
    "ModelRouter",
    "NoAvailableProviderError",
    "NvidiaNIMProvider",
    "ProviderAuthError",
    "ProviderAvailability",
    "ProviderQuotaExceeded",
    "ProviderRateLimited",
    "ProviderRefused",
    "ProviderTimeout",
    "ProviderUnavailable",
    "ReplayProvider",
    "RoutingPolicy",
    "SchemaValidationFailed",
    "TaskClass",
    "TaskRoutingRule",
    "build_default_router",
]
