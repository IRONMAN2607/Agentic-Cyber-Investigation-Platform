"""Routing policies and candidate model fallback chains for task classes."""

from __future__ import annotations

from dataclasses import dataclass, field

from acip.types import TaskClass


@dataclass(frozen=True)
class CandidateModel:
    """A specific model candidate configured under a provider."""

    provider: str
    model: str
    temperature: float = 0.0
    max_tokens: int = 2048
    seed: int | None = None


@dataclass(frozen=True)
class TaskRoutingRule:
    """Routing and fallback candidates for a single TaskClass."""

    task_class: TaskClass
    candidates: list[CandidateModel] = field(default_factory=list)
    max_output_tokens: int = 2048
    schema_retries: int = 2


class RoutingPolicy:
    """Configurable routing table mapping TaskClasses to candidate priority chains."""

    def __init__(self, rules: dict[TaskClass, TaskRoutingRule] | None = None) -> None:
        self.rules: dict[TaskClass, TaskRoutingRule] = dict(rules or {})

    def get_rule(self, task_class: TaskClass) -> TaskRoutingRule:
        """Retrieve the routing rule and candidate list for a given task class."""
        if task_class in self.rules:
            return self.rules[task_class]
        # Fallback to an empty or default rule
        return TaskRoutingRule(task_class=task_class, candidates=[])

    @classmethod
    def create_default(
        cls,
        *,
        primary_model: str = "meta/llama-3.2-11b-vision-instruct",
        secondary_model: str = "openai/gpt-oss-20b",
        provider_name: str = "nvidia",
        nemotron_model: str | None = None,
        deepseek_model: str | None = None,
    ) -> RoutingPolicy:
        """Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates."""
        primary = nemotron_model or primary_model
        secondary = deepseek_model or secondary_model

        primary_candidate = CandidateModel(
            provider=provider_name,
            model=primary,
            temperature=0.0,
            max_tokens=4096,
        )
        secondary_candidate = CandidateModel(
            provider=provider_name,
            model=secondary,
            temperature=0.0,
            max_tokens=4096,
        )

        rules: dict[TaskClass, TaskRoutingRule] = {
            # Deep reasoning tasks
            TaskClass.HYPOTHESIS: TaskRoutingRule(
                task_class=TaskClass.HYPOTHESIS,
                candidates=[primary_candidate, secondary_candidate],
                max_output_tokens=4096,
                schema_retries=2,
            ),
            TaskClass.VALIDATION: TaskRoutingRule(
                task_class=TaskClass.VALIDATION,
                candidates=[primary_candidate, secondary_candidate],
                max_output_tokens=4096,
                schema_retries=2,
            ),
            TaskClass.CORRELATION: TaskRoutingRule(
                task_class=TaskClass.CORRELATION,
                candidates=[primary_candidate, secondary_candidate],
                max_output_tokens=4096,
                schema_retries=2,
            ),
            # Instruction-following, extraction, and planning
            TaskClass.PLANNING: TaskRoutingRule(
                task_class=TaskClass.PLANNING,
                candidates=[primary_candidate, secondary_candidate],
                max_output_tokens=4096,
                schema_retries=2,
            ),
            TaskClass.EXTRACTION: TaskRoutingRule(
                task_class=TaskClass.EXTRACTION,
                candidates=[primary_candidate, secondary_candidate],
                max_output_tokens=4096,
                schema_retries=2,
            ),
            TaskClass.CLASSIFICATION: TaskRoutingRule(
                task_class=TaskClass.CLASSIFICATION,
                candidates=[primary_candidate, secondary_candidate],
                max_output_tokens=4096,
                schema_retries=2,
            ),
            TaskClass.NARRATIVE: TaskRoutingRule(
                task_class=TaskClass.NARRATIVE,
                candidates=[primary_candidate, secondary_candidate],
                max_output_tokens=4096,
                schema_retries=2,
            ),
            TaskClass.CHAT: TaskRoutingRule(
                task_class=TaskClass.CHAT,
                candidates=[primary_candidate, secondary_candidate],
                max_output_tokens=4096,
                schema_retries=2,
            ),
        }
        return cls(rules)


__all__ = ["CandidateModel", "RoutingPolicy", "TaskRoutingRule"]
