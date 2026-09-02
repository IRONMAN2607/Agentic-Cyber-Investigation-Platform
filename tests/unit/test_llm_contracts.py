from __future__ import annotations

from acip.core.llm.contracts import (
    ChatMessage,
    FinishReason,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    MessageRole,
)
from acip.core.llm.policy import RoutingPolicy
from acip.types import TaskClass


def test_chat_message_serialization() -> None:
    msg = ChatMessage(role=MessageRole.USER, content="Hello", name="analyst")
    assert msg.to_dict() == {"role": "user", "content": "Hello", "name": "analyst"}

    sys_msg = ChatMessage(role=MessageRole.SYSTEM, content="System prompt")
    assert sys_msg.to_dict() == {"role": "system", "content": "System prompt"}


def test_llm_request_and_response_dataclasses() -> None:
    req = LLMRequest(
        messages=[ChatMessage(role=MessageRole.USER, content="Explain event")],
        temperature=0.2,
        max_tokens=1000,
        seed=42,
    )
    assert req.temperature == 0.2
    assert req.max_tokens == 1000
    assert req.seed == 42

    resp = LLMResponse(
        content='{"status": "ok"}',
        usage=LLMUsage(prompt_tokens=50, completion_tokens=15, total_tokens=65),
        finish_reason=FinishReason.STOP,
        model="nvidia/llama-3.1-nemotron-70b-instruct",
        provider="nvidia",
        latency_ms=120,
    )
    assert resp.content == '{"status": "ok"}'
    assert resp.usage.total_tokens == 65
    assert resp.finish_reason == FinishReason.STOP
    assert resp.latency_ms == 120


def test_routing_policy_defaults() -> None:
    policy = RoutingPolicy.create_default()

    hyp_rule = policy.get_rule(TaskClass.HYPOTHESIS)
    assert len(hyp_rule.candidates) == 2
    assert hyp_rule.candidates[0].model == "meta/llama-3.2-11b-vision-instruct"
    assert hyp_rule.candidates[1].model == "openai/gpt-oss-20b"

    plan_rule = policy.get_rule(TaskClass.PLANNING)
    assert len(plan_rule.candidates) == 2
    assert plan_rule.candidates[0].model == "meta/llama-3.2-11b-vision-instruct"
    assert plan_rule.candidates[1].model == "openai/gpt-oss-20b"
