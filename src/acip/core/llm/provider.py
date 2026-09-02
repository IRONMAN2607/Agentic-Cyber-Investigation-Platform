"""LLMProvider protocol definition."""

from __future__ import annotations

from typing import Protocol

from acip.core.llm.contracts import LLMRequest, LLMResponse, ProviderAvailability


class LLMProvider(Protocol):
    """Abstract protocol for all LLM backend adapters."""

    name: str

    async def complete(self, request: LLMRequest, model: str) -> LLMResponse:
        """Send a completion request to the provider for a specific model."""
        ...

    async def probe(self) -> ProviderAvailability:
        """Probe provider connectivity, authentication, and available models."""
        ...


__all__ = ["LLMProvider"]
