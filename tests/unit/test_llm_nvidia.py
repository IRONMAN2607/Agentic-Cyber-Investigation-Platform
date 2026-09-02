from __future__ import annotations

import httpx
import pytest

from acip.core.llm.contracts import ChatMessage, FinishReason, LLMRequest, MessageRole
from acip.core.llm.errors import (
    ProviderAuthError,
    ProviderQuotaExceeded,
    ProviderRateLimited,
    ProviderUnavailable,
)
from acip.core.llm.providers.nvidia import NvidiaNIMProvider


@pytest.mark.asyncio
async def test_nvidia_provider_missing_api_key() -> None:
    provider = NvidiaNIMProvider(api_key="")
    request = LLMRequest(messages=[ChatMessage(role=MessageRole.USER, content="hello")])
    with pytest.raises(ProviderAuthError, match="NVIDIA NIM API key is not configured"):
        await provider.complete(request, model="nvidia/llama-3.1-nemotron-70b-instruct")


@pytest.mark.asyncio
async def test_nvidia_provider_successful_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = NvidiaNIMProvider(api_key="test-key")

    mock_resp_data = {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": '{"summary": "SSH brute force detected"}',
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 30,
            "total_tokens": 150,
        },
    }

    async def mock_post(self: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(status_code=200, json=mock_resp_data)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    request = LLMRequest(messages=[ChatMessage(role=MessageRole.USER, content="Analyze auth log")])
    response = await provider.complete(request, model="nvidia/llama-3.1-nemotron-70b-instruct")

    assert response.content == '{"summary": "SSH brute force detected"}'
    assert response.usage.prompt_tokens == 120
    assert response.usage.completion_tokens == 30
    assert response.usage.total_tokens == 150
    assert response.finish_reason == FinishReason.STOP
    assert response.provider == "nvidia"


@pytest.mark.asyncio
async def test_nvidia_provider_error_translations(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = NvidiaNIMProvider(api_key="test-key")
    request = LLMRequest(messages=[ChatMessage(role=MessageRole.USER, content="test")])

    # 1. 401 Auth error
    async def mock_401(self: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(status_code=401, text="Invalid API Key")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_401)
    with pytest.raises(ProviderAuthError, match="authentication failed"):
        await provider.complete(request, model="test-model")

    # 2. 429 Rate limited
    async def mock_429_rate(self: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(
            status_code=429, headers={"retry-after": "5"}, text="Rate limit exceeded"
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_429_rate)
    with pytest.raises(ProviderRateLimited) as exc_info:
        await provider.complete(request, model="test-model")
    assert exc_info.value.retry_after == 5.0

    # 3. 429 Quota exhausted
    async def mock_429_quota(self: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(status_code=429, text="Insufficient credit balance / quota exceeded")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_429_quota)
    with pytest.raises(ProviderQuotaExceeded, match="quota exceeded"):
        await provider.complete(request, model="test-model")

    # 4. 503 Service unavailable
    async def mock_503(self: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(status_code=503, text="Service Unavailable")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_503)
    with pytest.raises(ProviderUnavailable, match="server error"):
        await provider.complete(request, model="test-model")

    # 5. Content filter refusal
    mock_refusal = {"choices": [{"message": {"content": ""}, "finish_reason": "content_filter"}]}

    async def mock_refused(self: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(status_code=200, json=mock_refusal)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_refused)
    response = await provider.complete(request, model="test-model")
    assert response.finish_reason == FinishReason.CONTENT_FILTER
