from __future__ import annotations

from typing import Any

from experiments.datasets.ground_truth import GroundTruthFinding
from experiments.metrics.calculator import MetricCalculator
from experiments.metrics.matcher import MaximumBipartiteMatcher

from acip.types import Severity


def test_bipartite_matcher_exact_matching() -> None:
    # 2 Ground truth findings
    gt_list = [
        GroundTruthFinding(
            id="gt_1",
            title="SSH Brute Force",
            behavior_class="credential_access",
            technique_id="T1110.001",
            primary_entities=frozenset({"203.0.113.55", "deploy"}),
            severity=Severity.HIGH,
        ),
        GroundTruthFinding(
            id="gt_2",
            title="Sudo Privilege Escalation",
            behavior_class="privilege_escalation",
            technique_id="T1548.003",
            primary_entities=frozenset({"deploy", "root"}),
            severity=Severity.HIGH,
        ),
    ]

    # 2 Predicted findings matching exactly
    predicted = [
        {
            "id": "pred_1",
            "title": "Auth: SSH password guessing attack detected",
            "description": "Source IP 203.0.113.55 targeted account deploy",
            "behavior_class": "credential_access",
            "entities": ["203.0.113.55", "deploy"],
        },
        {
            "id": "pred_2",
            "title": "Host: Sudo root command execution",
            "description": "User deploy escalated privileges to root",
            "behavior_class": "privilege_escalation",
            "entities": ["deploy", "root"],
        },
    ]

    matching = MaximumBipartiteMatcher.match(predicted, gt_list)
    assert len(matching.matched_pairs) == 2
    assert len(matching.unmatched_predictions) == 0
    assert len(matching.unmatched_ground_truth) == 0

    metrics = MetricCalculator.compute(
        scenario_id="test_scenario",
        condition="condition_d_proposed",
        matching=matching,
        is_benign=False,
        total_claims=2,
        unsupported_claims=0,
        grounding_violations=0,
        fabricated_entities=set(),
        provenance_complete_count=2,
        total_statements=2,
    )

    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.fabrication_count == 0
    assert metrics.provenance_completeness == 1.0


def test_bipartite_matcher_prevents_multi_claiming() -> None:
    """One vague finding cannot match multiple ground truth labels."""
    gt_list = [
        GroundTruthFinding(
            id="gt_1",
            title="SSH Brute Force",
            behavior_class="credential_access",
            primary_entities=frozenset({"203.0.113.55"}),
        ),
        GroundTruthFinding(
            id="gt_2",
            title="SSH Second Brute Force",
            behavior_class="credential_access",
            primary_entities=frozenset({"203.0.113.55"}),
        ),
    ]

    # Only 1 prediction
    predicted = [
        {
            "id": "pred_single",
            "title": "Credential guessing on SSH",
            "description": "Observed 203.0.113.55",
            "behavior_class": "credential_access",
            "entities": ["203.0.113.55"],
        }
    ]

    matching = MaximumBipartiteMatcher.match(predicted, gt_list)
    # Strictly matched to 1 GT only!
    assert len(matching.matched_pairs) == 1
    assert len(matching.unmatched_ground_truth) == 1  # 1 false negative

    metrics = MetricCalculator.compute(
        scenario_id="test_multiclaim",
        condition="baseline_b",
        matching=matching,
        is_benign=False,
        total_claims=1,
        unsupported_claims=0,
        grounding_violations=0,
        fabricated_entities=set(),
        provenance_complete_count=1,
        total_statements=1,
    )

    assert metrics.precision == 1.0
    assert metrics.recall == 0.5  # 1 out of 2 detected
    assert round(metrics.f1_score, 4) == round(2 * 1.0 * 0.5 / 1.5, 4)


def test_clean_benign_metrics() -> None:
    """Clean benign input should yield 0 false positives."""
    gt_list: list[GroundTruthFinding] = []
    predicted: list[dict[str, Any]] = []

    matching = MaximumBipartiteMatcher.match(predicted, gt_list)
    assert len(matching.matched_pairs) == 0
    assert len(matching.unmatched_predictions) == 0

    metrics = MetricCalculator.compute(
        scenario_id="clean_baseline",
        condition="condition_d_proposed",
        matching=matching,
        is_benign=True,
        total_claims=0,
        unsupported_claims=0,
        grounding_violations=0,
        fabricated_entities=set(),
        provenance_complete_count=0,
        total_statements=0,
    )

    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.false_positive_rate_benign == 0.0
