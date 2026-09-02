"""NVIDIA NIM LLM provider implementation.

Communicates with NVIDIA NIM endpoints via the OpenAI-compatible chat completions API
(supporting Nemotron, DeepSeek, and other hosted models on integrate.api.nvidia.com).
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from acip.core.llm.contracts import (
    FinishReason,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    ProviderAvailability,
)
from acip.core.llm.errors import (
    ProviderAuthError,
    ProviderQuotaExceeded,
    ProviderRateLimited,
    ProviderRefused,
    ProviderTimeout,
    ProviderUnavailable,
)
from acip.logging import get_logger

logger = get_logger(__name__)


class NvidiaNIMProvider:
    """Provider interface for NVIDIA NIM endpoints."""

    name: str = "nvidia"

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://integrate.api.nvidia.com/v1",
        default_timeout: float = 60.0,
    ) -> None:
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.default_timeout = default_timeout

    async def complete(self, request: LLMRequest, model: str) -> LLMResponse:
        """Send completion request to NVIDIA NIM."""
        if not self.api_key:
            raise ProviderAuthError(
                "NVIDIA NIM API key is not configured",
                provider=self.name,
                model=model,
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        body: dict[str, Any] = {
            "model": model,
            "messages": [m.to_dict() for m in request.messages],
            "temperature": request.temperature,
        }
        if request.max_tokens is not None:
            body["max_tokens"] = request.max_tokens
        if request.seed is not None:
            body["seed"] = request.seed
        if request.response_format is not None:
            body["response_format"] = request.response_format

        timeout_sec = request.timeout_seconds or self.default_timeout
        client_timeout = httpx.Timeout(
            connect=10.0,
            read=timeout_sec,
            write=10.0,
            pool=10.0,
        )

        start_time = time.perf_counter()

        async with httpx.AsyncClient(timeout=client_timeout) as client:
            try:
                resp = await client.post(endpoint, headers=headers, json=body)
            except httpx.TimeoutException as exc:
                latency_ms = int((time.perf_counter() - start_time) * 1000)
                raise ProviderTimeout(
                    f"NVIDIA NIM timed out after {timeout_sec}s: {exc}",
                    provider=self.name,
                    model=model,
                    detail={"latency_ms": latency_ms},
                ) from exc
            except (httpx.ConnectError, httpx.NetworkError) as exc:
                latency_ms = int((time.perf_counter() - start_time) * 1000)
                raise ProviderUnavailable(
                    f"NVIDIA NIM network connection error: {exc}",
                    provider=self.name,
                    model=model,
                    detail={"latency_ms": latency_ms},
                ) from exc
            except httpx.RequestError as exc:
                latency_ms = int((time.perf_counter() - start_time) * 1000)
                raise ProviderUnavailable(
                    f"NVIDIA NIM request error: {exc}",
                    provider=self.name,
                    model=model,
                    detail={"latency_ms": latency_ms},
                ) from exc

        latency_ms = int((time.perf_counter() - start_time) * 1000)

        # Handle HTTP error responses
        if resp.status_code != 200:
            err_text = resp.text
            if resp.status_code in {401, 403}:
                raise ProviderAuthError(
                    f"NVIDIA NIM authentication failed ({resp.status_code}): {err_text}",
                    provider=self.name,
                    model=model,
                    detail={"status_code": resp.status_code},
                )
            if resp.status_code == 429:
                retry_header = resp.headers.get("retry-after")
                retry_after = (
                    float(retry_header) if retry_header and retry_header.isdigit() else 2.0
                )
                if "quota" in err_text.lower() or "credit" in err_text.lower():
                    raise ProviderQuotaExceeded(
                        f"NVIDIA NIM quota exceeded: {err_text}",
                        provider=self.name,
                        model=model,
                    )
                raise ProviderRateLimited(
                    f"NVIDIA NIM rate limited: {err_text}",
                    provider=self.name,
                    model=model,
                    retry_after=retry_after,
                )
            if resp.status_code >= 500:
                raise ProviderUnavailable(
                    f"NVIDIA NIM server error ({resp.status_code}): {err_text}",
                    provider=self.name,
                    model=model,
                    detail={"status_code": resp.status_code},
                )
            if resp.status_code == 400:
                if "content" in err_text.lower() and "filter" in err_text.lower():
                    raise ProviderRefused(
                        f"NVIDIA NIM refused request (safety filter): {err_text}",
                        provider=self.name,
                        model=model,
                    )
                raise ProviderUnavailable(
                    f"NVIDIA NIM bad request ({resp.status_code}): {err_text}",
                    provider=self.name,
                    model=model,
                )

        try:
            data = resp.json()
            choice = data["choices"][0]
            content = choice["message"].get("content") or ""
            raw_reason = choice.get("finish_reason") or "stop"
        except Exception as exc:
            raise ProviderUnavailable(
                f"failed to parse NVIDIA NIM JSON response: {exc}",
                provider=self.name,
                model=model,
                detail={"raw_text": resp.text},
            ) from exc

        # Map finish reason
        match raw_reason:
            case "stop":
                finish_reason = FinishReason.STOP
            case "length":
                finish_reason = FinishReason.LENGTH
            case "content_filter":
                finish_reason = FinishReason.CONTENT_FILTER
            case "tool_calls":
                finish_reason = FinishReason.TOOL_CALLS
            case _:
                finish_reason = FinishReason.STOP

        usage_data = data.get("usage", {})
        usage = LLMUsage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )

        return LLMResponse(
            content=content,
            usage=usage,
            finish_reason=finish_reason,
            model=model,
            provider=self.name,
            latency_ms=latency_ms,
            raw_response=data,
        )

    async def probe(self) -> ProviderAvailability:
        """Probe NVIDIA NIM endpoint to verify API key and model availability."""
        if not self.api_key:
            return ProviderAvailability(
                available=False,
                message="NVIDIA NIM API key is not configured",
                models=[],
            )

        endpoint = f"{self.base_url}/models"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("id", "") for m in data.get("data", []) if m.get("id")]
                    return ProviderAvailability(
                        available=True,
                        message="NVIDIA NIM is reachable and authorized",
                        models=models,
                    )
                if resp.status_code in {401, 403}:
                    return ProviderAvailability(
                        available=False,
                        message=f"NVIDIA NIM authentication failed ({resp.status_code})",
                        models=[],
                    )
                return ProviderAvailability(
                    available=False,
                    message=f"NVIDIA NIM returned status {resp.status_code}",
                    models=[],
                )
        except Exception as exc:
            return ProviderAvailability(
                available=False,
                message=f"NVIDIA NIM probe failed: {exc}",
                models=[],
            )


__all__ = ["NvidiaNIMProvider"]
