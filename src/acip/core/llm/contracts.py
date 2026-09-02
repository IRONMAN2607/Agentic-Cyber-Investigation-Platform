"""Contracts and data models for model-provider abstraction.

Defines the message shapes, request/response formats, token usage telemetry,
and provider metadata used by the LLM routing subsystem.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from acip.types import FinishReason, TaskClass


class MessageRole(StrEnum):
    """Role of a message sender in a chat conversation."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True)
class ChatMessage:
    """A single conversation turn."""

    role: MessageRole
    content: str
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"role": self.role.value, "content": self.content}
        if self.name:
            data["name"] = self.name
        return data


@dataclass(frozen=True)
class LLMRequest:
    """Request payload sent to an LLM provider."""

    messages: list[ChatMessage]
    temperature: float = 0.0
    max_tokens: int | None = None
    seed: int | None = None
    response_format: dict[str, Any] | None = None
    timeout_seconds: float = 60.0


@dataclass(frozen=True)
class LLMUsage:
    """Token accounting telemetry returned by a provider."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True)
class LLMResponse:
    """Standardized response received from an LLM provider."""

    content: str
    usage: LLMUsage
    finish_reason: FinishReason
    model: str
    provider: str
    latency_ms: int = 0
    raw_response: dict[str, Any] | None = None


@dataclass(frozen=True)
class ProviderAvailability:
    """Health and model discovery status for an LLM provider."""

    available: bool
    message: str
    models: list[str] = field(default_factory=list)


__all__ = [
    "ChatMessage",
    "FinishReason",
    "LLMRequest",
    "LLMResponse",
    "LLMUsage",
    "MessageRole",
    "ProviderAvailability",
    "TaskClass",
]
