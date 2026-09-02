"""ModelRouter: Provider-agnostic model routing, fallback chains, and structured outputs."""

from __future__ import annotations

import json
import uuid
from typing import Any, TypeVar

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from acip.core.llm.contracts import (
    ChatMessage,
    FinishReason,
    LLMRequest,
    LLMResponse,
    MessageRole,
)
from acip.core.llm.errors import (
    LLMError,
    NoAvailableProviderError,
    ProviderAuthError,
    ProviderRefused,
    SchemaValidationFailed,
)
from acip.core.llm.policy import CandidateModel, RoutingPolicy
from acip.core.llm.provider import LLMProvider
from acip.db.models import ModelExecution
from acip.logging import get_logger
from acip.types import TaskClass

logger = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)


def _schema_to_template(schema: type[BaseModel]) -> dict[str, Any]:
    """Generate a clean example JSON structure from a Pydantic model for prompt guidance."""
    raw_schema = schema.model_json_schema()
    defs = raw_schema.get("$defs", {})

    def resolve(node: Any) -> Any:
        if not isinstance(node, dict):
            return "value"
        if "$ref" in node:
            ref_name = node["$ref"].split("/")[-1]
            return resolve(defs.get(ref_name, {}))
        if "anyOf" in node:
            return resolve(node["anyOf"][0])
        if "allOf" in node:
            return resolve(node["allOf"][0])

        if "properties" in node:
            props = node.get("properties", {})
            return {k: resolve(v) for k, v in props.items()}

        node_type = node.get("type")
        if node_type == "object":
            props = node.get("properties", {})
            return {k: resolve(v) for k, v in props.items()}
        elif node_type == "array":
            items = node.get("items", {})
            return [resolve(items)]
        elif node_type == "string":
            if "enum" in node:
                return " | ".join(str(e) for e in node["enum"])
            return node.get("description") or "string"
        elif node_type == "integer":
            return 1
        elif node_type == "number":
            return 0.95
        elif node_type == "boolean":
            return True
        return "value"

    result = resolve(raw_schema)
    return result if isinstance(result, dict) else {}


class ModelRouter:
    """Central entry point for all agent reasoning and model completions.

    Guarantees:
    1. Agents depend on abstract TaskClasses, never on specific LLM providers or models.
    2. Transparent fallback across candidates on quota exhaustion, timeouts, and 5xx errors.
    3. No fallback shopping on refusals or schema failures (integrity preservation).
    4. Pydantic-validated structured outputs with automatic schema-repair retry loops.
    5. Comprehensive execution tracing into the llm_calls table.
    """

    def __init__(
        self,
        providers: dict[str, LLMProvider],
        policy: RoutingPolicy,
        *,
        max_investigation_tokens: int = 200_000,
        request_timeout_seconds: float = 60.0,
    ) -> None:
        self.providers: dict[str, LLMProvider] = dict(providers)
        self.policy = policy
        self.max_investigation_tokens = max_investigation_tokens
        self.request_timeout_seconds = request_timeout_seconds

    async def complete(
        self,
        task_class: TaskClass,
        messages: list[ChatMessage],
        *,
        schema: type[T] | None = None,
        investigation_id: uuid.UUID | None = None,
        agent_run_id: uuid.UUID | None = None,
        task_id: str | None = None,
        prompt_name: str = "default",
        prompt_version: str = "v1",
        session: AsyncSession | None = None,
    ) -> tuple[T | None, LLMResponse]:
        """Execute a completion for a TaskClass with optional structured schema validation.

        Returns ``(parsed_schema_instance, llm_response)``.
        """
        rule = self.policy.get_rule(task_class)
        if not rule.candidates:
            raise NoAvailableProviderError(
                f"no candidate models configured for task class '{task_class.value}'"
            )

        fallback_from: str | None = None
        last_error: Exception | None = None

        for candidate in rule.candidates:
            provider = self.providers.get(candidate.provider)
            if not provider:
                logger.warning(
                    "configured provider '%s' not registered in router; skipping candidate",
                    candidate.provider,
                )
                continue

            try:
                parsed_obj, response = await self._execute_candidate(
                    provider=provider,
                    candidate=candidate,
                    messages=messages,
                    schema=schema,
                    max_tokens=rule.max_output_tokens,
                    schema_retries=rule.schema_retries,
                )

                # Record successful trace if session is active
                if session and investigation_id:
                    await self._record_trace(
                        session=session,
                        investigation_id=investigation_id,
                        agent_run_id=agent_run_id,
                        task_id=task_id,
                        task_class=task_class,
                        candidate=candidate,
                        prompt_name=prompt_name,
                        prompt_version=prompt_version,
                        response=response,
                        schema_valid=True,
                        fallback_from=fallback_from,
                    )

                return parsed_obj, response

            except (ProviderAuthError, ProviderRefused, SchemaValidationFailed) as exc:
                # Non-fallback errors fail immediately to preserve measurement integrity
                logger.error(
                    "non-fallback error from %s:%s for task %s: %s",
                    candidate.provider,
                    candidate.model,
                    task_class.value,
                    exc,
                )
                if session and investigation_id:
                    await self._record_trace(
                        session=session,
                        investigation_id=investigation_id,
                        agent_run_id=agent_run_id,
                        task_id=task_id,
                        task_class=task_class,
                        candidate=candidate,
                        prompt_name=prompt_name,
                        prompt_version=prompt_version,
                        response=None,
                        schema_valid=not isinstance(exc, SchemaValidationFailed),
                        fallback_from=fallback_from,
                    )
                raise exc

            except LLMError as exc:
                # Fallback on retryable / quota / connection errors
                if exc.can_fallback:
                    logger.warning(
                        "candidate %s:%s failed with %s (%s); attempting fallback",
                        candidate.provider,
                        candidate.model,
                        type(exc).__name__,
                        exc,
                    )
                    fallback_from = f"{candidate.provider}:{candidate.model}"
                    last_error = exc
                    continue
                raise exc

        raise NoAvailableProviderError(
            f"all candidate models exhausted for task class '{task_class.value}'; "
            f"last error: {last_error}"
        )

    async def _execute_candidate(
        self,
        provider: LLMProvider,
        candidate: CandidateModel,
        messages: list[ChatMessage],
        schema: type[T] | None,
        max_tokens: int,
        schema_retries: int,
    ) -> tuple[T | None, LLMResponse]:
        """Execute a candidate model, handling structured output repair retries."""
        current_messages = list(messages)
        response_format: dict[str, Any] | None = None

        if schema is not None:
            response_format = {"type": "json_object"}
            template_obj = _schema_to_template(schema)
            template_json = json.dumps(template_obj, indent=2)
            schema_instruction = (
                "\nYou must respond with a valid JSON data object strictly matching "
                "this structure:\n"
                f"```json\n{template_json}\n```\n"
                "CRITICAL: Output ONLY the populated data JSON object "
                "(starting with '{' and ending with '}'). "
                "Do NOT output schema definitions, '$defs', or conversational explanations."
            )
            # Inject schema instruction into messages if not present
            has_instruction = any(schema_instruction in m.content for m in current_messages)
            if not has_instruction:
                if current_messages and current_messages[0].role == MessageRole.SYSTEM:
                    sys_msg = current_messages[0]
                    current_messages[0] = ChatMessage(
                        role=MessageRole.SYSTEM,
                        content=sys_msg.content + schema_instruction,
                        name=sys_msg.name,
                    )
                else:
                    current_messages.insert(
                        0,
                        ChatMessage(
                            role=MessageRole.SYSTEM,
                            content=(
                                "You are a specialized security AI assistant." + schema_instruction
                            ),
                        ),
                    )

        retries_remaining = schema_retries if schema is not None else 0

        while True:
            request = LLMRequest(
                messages=current_messages,
                temperature=candidate.temperature,
                max_tokens=candidate.max_tokens or max_tokens,
                seed=candidate.seed,
                response_format=response_format,
                timeout_seconds=self.request_timeout_seconds,
            )

            response = await provider.complete(request, candidate.model)

            if schema is None:
                return None, response

            # Parse and validate structured output
            raw_text = response.content.strip()
            # Strip markdown code blocks if the model wrapped JSON
            if raw_text.startswith("```json"):
                raw_text = raw_text.removeprefix("```json").strip()
            if raw_text.startswith("```"):
                raw_text = raw_text.removeprefix("```").strip()
            if raw_text.endswith("```"):
                raw_text = raw_text.removesuffix("```").strip()

            try:
                parsed_data = schema.model_validate_json(raw_text)
                return parsed_data, response
            except Exception as exc:
                if retries_remaining > 0:
                    retries_remaining -= 1
                    logger.warning(
                        "schema validation failed for %s:%s (retrying with repair prompt): %s",
                        candidate.provider,
                        candidate.model,
                        exc,
                    )
                    current_messages.append(
                        ChatMessage(role=MessageRole.ASSISTANT, content=response.content)
                    )
                    current_messages.append(
                        ChatMessage(
                            role=MessageRole.USER,
                            content=(
                                "The previous response failed schema validation with error:\n"
                                f"{exc}\n"
                                "Please return ONLY valid JSON matching the exact schema."
                            ),
                        )
                    )
                    continue

                raise SchemaValidationFailed(
                    f"model response failed Pydantic schema validation: {exc}",
                    provider=candidate.provider,
                    model=candidate.model,
                    detail={"raw_response": response.content, "error": str(exc)},
                ) from exc

    async def _record_trace(
        self,
        session: AsyncSession,
        investigation_id: uuid.UUID,
        agent_run_id: uuid.UUID | None,
        task_id: str | None,
        task_class: TaskClass,
        candidate: CandidateModel,
        prompt_name: str,
        prompt_version: str,
        response: LLMResponse | None,
        schema_valid: bool,
        fallback_from: str | None,
    ) -> None:
        """Persist execution telemetry to llm_calls (ModelExecution)."""
        tokens_in = response.usage.prompt_tokens if response else 0
        tokens_out = response.usage.completion_tokens if response else 0
        latency_ms = response.latency_ms if response else 0
        finish_reason = (
            response.finish_reason.value
            if (response and hasattr(response.finish_reason, "value"))
            else str(response.finish_reason)
            if response
            else FinishReason.ERROR.value
        )
        trace = ModelExecution(
            investigation_id=investigation_id,
            agent_run_id=agent_run_id,
            task_id=task_id,
            task_class=task_class.value,
            provider=candidate.provider,
            model=candidate.model,
            prompt_name=prompt_name,
            prompt_version=prompt_version,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            cost_estimate_usd=0.0,
            finish_reason=finish_reason,
            retries=0,
            schema_valid=schema_valid,
            fallback_from=fallback_from,
            temperature=candidate.temperature,
            seed=candidate.seed,
            nondeterminism_risk="low",
            grounding_violations=0,
        )
        session.add(trace)
        await session.flush()


def build_default_router(settings: Any) -> ModelRouter:
    """Construct a default ModelRouter from application settings."""
    from acip.core.llm.providers.nvidia import NvidiaNIMProvider
    from acip.core.llm.providers.replay import DEFAULT_TRIAGE_RESPONSE, ReplayProvider

    policy = RoutingPolicy.create_default(
        nemotron_model=settings.model_nemotron,
        deepseek_model=settings.model_deepseek,
    )
    providers: dict[str, LLMProvider] = {}
    nvidia_key = settings.nvidia_api_key.get_secret_value()

    if getattr(settings, "environment", "") == "test":
        providers["nvidia"] = ReplayProvider(
            name="nvidia",
            default_response=DEFAULT_TRIAGE_RESPONSE,
            canned_responses={"triage": DEFAULT_TRIAGE_RESPONSE},
        )
    elif nvidia_key:
        providers["nvidia"] = NvidiaNIMProvider(
            api_key=nvidia_key,
            base_url=settings.nvidia_base_url,
            default_timeout=settings.llm_request_timeout_seconds,
        )
    return ModelRouter(
        providers=providers,
        policy=policy,
        max_investigation_tokens=settings.llm_max_investigation_tokens,
        request_timeout_seconds=settings.llm_request_timeout_seconds,
    )


__all__ = ["ModelRouter", "build_default_router"]
