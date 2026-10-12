"""Top-level benchmark harness runner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from acip.config import Settings
from acip.db.session import Database
from experiments.datasets.scenarios import SCENARIOS
from experiments.metrics.calculator import ScenarioMetrics
from experiments.runners.baselines import execute_condition


@dataclass
class BenchmarkSuiteResult:
    """Consolidated metrics across all scenarios and conditions."""

    results: list[ScenarioMetrics]

    def summary_table(self) -> list[dict[str, Any]]:
        """Compute aggregate precision, recall, F1, and grounding metrics per condition."""
        by_condition: dict[str, list[ScenarioMetrics]] = {}
        for r in self.results:
            by_condition.setdefault(r.condition, []).append(r)

        summary: list[dict[str, Any]] = []
        for cond, metrics_list in by_condition.items():
            n = len(metrics_list)
            avg_prec = sum(m.precision for m in metrics_list) / n
            avg_rec = sum(m.recall for m in metrics_list) / n
            avg_f1 = sum(m.f1_score for m in metrics_list) / n
            avg_fpr = sum(m.false_positive_rate_benign for m in metrics_list) / n
            avg_prov = sum(m.provenance_completeness for m in metrics_list) / n
            total_fab = sum(m.fabrication_count for m in metrics_list)

            summary.append(
                {
                    "condition": cond,
                    "scenarios_evaluated": n,
                    "precision": round(avg_prec, 4),
                    "recall": round(avg_rec, 4),
                    "f1_score": round(avg_f1, 4),
                    "fpr_benign": round(avg_fpr, 4),
                    "provenance_completeness": round(avg_prov, 4),
                    "total_fabrications": total_fab,
                }
            )
        return summary


class BenchmarkRunner:
    """Executes the benchmark matrix across conditions and scenarios."""

    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings

    async def run_scenario(self, scenario_id: str, condition: str) -> ScenarioMetrics:
        scenario = SCENARIOS.get(scenario_id)
        if scenario is None:
            raise ValueError(f"Scenario '{scenario_id}' not found in benchmark suite")
        return await execute_condition(self.database, scenario, condition, self.settings)

    async def run_all(
        self,
        conditions: list[str] | None = None,
        scenario_ids: list[str] | None = None,
    ) -> BenchmarkSuiteResult:
        target_conditions = conditions or [
            "condition_a_rules",
            "condition_b_single_llm",
            "condition_c_no_graph",
            "condition_d_proposed",
        ]
        target_scenarios = scenario_ids or list(SCENARIOS.keys())

        results: list[ScenarioMetrics] = []
        for cond in target_conditions:
            for s_id in target_scenarios:
                metrics = await self.run_scenario(s_id, cond)
                results.append(metrics)

        return BenchmarkSuiteResult(results=results)
