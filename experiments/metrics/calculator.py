"""Metric calculation harness for evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from experiments.metrics.matcher import MatchingResult


@dataclass(frozen=True)
class ScenarioMetrics:
    """Evaluation metrics for a single condition on a scenario."""

    scenario_id: str
    condition: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate_benign: float
    unsupported_assertion_rate: float
    grounding_violation_rate: float
    provenance_completeness: float
    fabrication_count: int
    near_miss_count: int
    total_claims: int
    duration_ms: int
    total_tokens: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "condition": self.condition,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1_score, 4),
            "fpr_benign": round(self.false_positive_rate_benign, 4),
            "unsupported_assertion_rate": round(self.unsupported_assertion_rate, 4),
            "grounding_violation_rate": round(self.grounding_violation_rate, 4),
            "provenance_completeness": round(self.provenance_completeness, 4),
            "fabrication_count": self.fabrication_count,
            "near_miss_count": self.near_miss_count,
            "total_claims": self.total_claims,
            "duration_ms": self.duration_ms,
            "total_tokens": self.total_tokens,
        }


class MetricCalculator:
    """Calculates evaluation metrics over matching result and audit records."""

    @classmethod
    def compute(
        cls,
        scenario_id: str,
        condition: str,
        matching: MatchingResult,
        is_benign: bool,
        total_claims: int,
        unsupported_claims: int,
        grounding_violations: int,
        fabricated_entities: set[str],
        provenance_complete_count: int,
        total_statements: int,
        duration_ms: int = 0,
        total_tokens: int = 0,
    ) -> ScenarioMetrics:
        tp = len(matching.matched_pairs)
        fp = len(matching.unmatched_predictions)
        fn = len(matching.unmatched_ground_truth)

        # Precision, Recall, F1
        if tp + fp > 0:
            precision = tp / (tp + fp)
        elif is_benign and fp == 0:
            precision = 1.0  # Perfect precision on clean baseline
        else:
            precision = 0.0

        if tp + fn > 0:
            recall = tp / (tp + fn)
        elif is_benign and fn == 0:
            recall = 1.0  # Perfect recall on clean baseline
        else:
            recall = 0.0

        if precision + recall > 0:
            f1 = (2.0 * precision * recall) / (precision + recall)
        else:
            f1 = 0.0

        fpr_benign = float(fp > 0) if is_benign else 0.0

        # Grounding metrics
        unsupported_rate = (unsupported_claims / total_claims) if total_claims > 0 else 0.0
        grounding_violation_rate = (
            (grounding_violations / total_claims) if total_claims > 0 else 0.0
        )
        prov_completeness = (
            (provenance_complete_count / total_statements) if total_statements > 0 else 1.0
        )

        return ScenarioMetrics(
            scenario_id=scenario_id,
            condition=condition,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate_benign=fpr_benign,
            unsupported_assertion_rate=unsupported_rate,
            grounding_violation_rate=grounding_violation_rate,
            provenance_completeness=prov_completeness,
            fabrication_count=len(fabricated_entities),
            near_miss_count=len(matching.near_misses),
            total_claims=total_claims,
            duration_ms=duration_ms,
            total_tokens=total_tokens,
        )
