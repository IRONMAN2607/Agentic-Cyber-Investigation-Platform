from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import BaseModel, Field

from acip.core.llm.contracts import (
    ChatMessage,
    FinishReason,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    MessageRole,
)
from acip.core.llm.errors import (
    ProviderAuthError,
    ProviderUnavailable,
    SchemaValidationFailed,
)
from acip.core.llm.policy import CandidateModel, RoutingPolicy, TaskRoutingRule
from acip.core.llm.providers.replay import ReplayProvider
from acip.core.llm.router import ModelRouter
from acip.types import TaskClass


class StructuredAnalysis(BaseModel):
    verdict: str = Field(description="Verdict label")
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


@pytest.mark.asyncio
async def test_router_transparent_fallback_on_unavailable() -> None:
    # Provider 1 fails with ProviderUnavailable; Provider 2 succeeds
    p1 = ReplayProvider(
        name="p1",
        simulated_errors=[ProviderUnavailable("Service degraded", provider="p1")],
    )
    p2 = ReplayProvider(name="p2", default_response='{"analysis": "success from secondary"}')

    rule = TaskRoutingRule(
        task_class=TaskClass.HYPOTHESIS,
        candidates=[
            CandidateModel(provider="p1", model="primary-model"),
            CandidateModel(provider="p2", model="secondary-model"),
        ],
    )
    policy = RoutingPolicy({TaskClass.HYPOTHESIS: rule})
    router = ModelRouter(providers={"p1": p1, "p2": p2}, policy=policy)

    messages = [ChatMessage(role=MessageRole.USER, content="Generate hypothesis")]
    parsed, resp = await router.complete(TaskClass.HYPOTHESIS, messages)

    assert parsed is None
    assert resp.content == '{"analysis": "success from secondary"}'
    assert resp.provider == "p2"
    assert resp.model == "secondary-model"
    assert len(p1.call_history) == 1
    assert len(p2.call_history) == 1


@pytest.mark.asyncio
async def test_router_non_fallback_on_auth_error() -> None:
    # Auth error should fail loudly and immediately without model shopping
    p1 = ReplayProvider(
        name="p1",
        simulated_errors=[ProviderAuthError("Bad API Key", provider="p1")],
    )
    p2 = ReplayProvider(name="p2", default_response="should not be reached")

    rule = TaskRoutingRule(
        task_class=TaskClass.PLANNING,
        candidates=[
            CandidateModel(provider="p1", model="primary-model"),
            CandidateModel(provider="p2", model="secondary-model"),
        ],
    )
    policy = RoutingPolicy({TaskClass.PLANNING: rule})
    router = ModelRouter(providers={"p1": p1, "p2": p2}, policy=policy)

    messages = [ChatMessage(role=MessageRole.USER, content="Plan tasks")]
    with pytest.raises(ProviderAuthError, match="Bad API Key"):
        await router.complete(TaskClass.PLANNING, messages)

    # Ensure secondary was NOT called
    assert len(p2.call_history) == 0


@pytest.mark.asyncio
async def test_router_structured_output_success() -> None:
    valid_json = (
        '{"verdict": "malicious", "confidence": 0.95, "reasons": ["Multiple failed logins"]}'
    )
    p1 = ReplayProvider(name="p1", default_response=valid_json)

    rule = TaskRoutingRule(
        task_class=TaskClass.CLASSIFICATION,
        candidates=[CandidateModel(provider="p1", model="classify-model")],
    )
    policy = RoutingPolicy({TaskClass.CLASSIFICATION: rule})
    router = ModelRouter(providers={"p1": p1}, policy=policy)

    messages = [ChatMessage(role=MessageRole.USER, content="Classify event")]
    parsed, _resp = await router.complete(
        TaskClass.CLASSIFICATION, messages, schema=StructuredAnalysis
    )

    assert isinstance(parsed, StructuredAnalysis)
    assert parsed.verdict == "malicious"
    assert parsed.confidence == 0.95
    assert parsed.reasons == ["Multiple failed logins"]


@pytest.mark.asyncio
async def test_router_structured_output_repair_retry() -> None:
    # First response is invalid JSON; second response is valid JSON after repair prompt
    invalid_json = '{"verdict": "malicious", "confidence": 1.5}'  # confidence > 1.0 violates schema
    valid_json = '{"verdict": "malicious", "confidence": 0.85, "reasons": ["Repaired"]}'

    p1 = ReplayProvider(name="p1")
    responses = [invalid_json, valid_json]

    async def mock_complete(req: LLMRequest, model: str) -> LLMResponse:
        content = responses.pop(0)
        return LLMResponse(
            content=content,
            usage=LLMUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            finish_reason=FinishReason.STOP,
            model=model,
            provider=p1.name,
        )

    p1.complete = mock_complete  # type: ignore[assignment,method-assign]

    rule = TaskRoutingRule(
        task_class=TaskClass.CLASSIFICATION,
        candidates=[CandidateModel(provider="p1", model="classify-model")],
        schema_retries=2,
    )
    policy = RoutingPolicy({TaskClass.CLASSIFICATION: rule})
    router = ModelRouter(providers={"p1": p1}, policy=policy)

    messages = [ChatMessage(role=MessageRole.USER, content="Classify event")]
    parsed, _resp = await router.complete(
        TaskClass.CLASSIFICATION, messages, schema=StructuredAnalysis
    )

    assert isinstance(parsed, StructuredAnalysis)
    assert parsed.confidence == 0.85
    assert parsed.reasons == ["Repaired"]


@pytest.mark.asyncio
async def test_router_structured_output_fails_after_retries() -> None:
    # Model consistently returns invalid schema data
    invalid_json = '{"verdict": "malicious", "confidence": 5.0}'
    p1 = ReplayProvider(default_response=invalid_json)

    rule = TaskRoutingRule(
        task_class=TaskClass.CLASSIFICATION,
        candidates=[CandidateModel(provider="p1", model="classify-model")],
        schema_retries=1,
    )
    policy = RoutingPolicy({TaskClass.CLASSIFICATION: rule})
    router = ModelRouter(providers={"p1": p1}, policy=policy)

    messages = [ChatMessage(role=MessageRole.USER, content="Classify event")]
    with pytest.raises(SchemaValidationFailed, match="failed Pydantic schema validation"):
        await router.complete(TaskClass.CLASSIFICATION, messages, schema=StructuredAnalysis)


def test_no_agents_import_provider_sdks() -> None:
    """Architectural invariant: agents must never import specific provider SDKs."""
    agents_dir = Path("src/acip/agents")
    forbidden_imports = {"openai", "anthropic", "google.generativeai", "mistralai", "cohere"}

    for py_file in agents_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in forbidden_imports, (
                        f"{py_file.name} directly imports forbidden SDK '{alias.name}'"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                top_pkg = node.module.split(".")[0]
                assert top_pkg not in forbidden_imports, (
                    f"{py_file.name} directly imports from forbidden SDK '{top_pkg}'"
                )
