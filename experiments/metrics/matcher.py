"""One-to-one maximum bipartite matching between predicted and ground-truth findings.

Enforces strict one-to-one matching per docs/experiments.md s2 to prevent one vague
finding from inflating recall by claiming multiple ground-truth labels.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from experiments.datasets.ground_truth import GroundTruthFinding


@dataclass(frozen=True)
class MatchingResult:
    """Outcome of bipartite matching."""

    matched_pairs: tuple[tuple[str, str], ...]  # (pred_id, gt_id)
    unmatched_predictions: tuple[str, ...]  # False positives
    unmatched_ground_truth: tuple[str, ...]  # False negatives
    near_misses: tuple[tuple[str, str, str], ...]  # (pred_id, gt_id, reason)


class MaximumBipartiteMatcher:
    """Computes exact maximum cardinality bipartite matching."""

    @classmethod
    def match(
        cls,
        predicted: list[dict[str, Any]],
        ground_truth: list[GroundTruthFinding],
    ) -> MatchingResult:
        if not ground_truth:
            return MatchingResult(
                matched_pairs=(),
                unmatched_predictions=tuple(str(p["id"]) for p in predicted),
                unmatched_ground_truth=(),
                near_misses=(),
            )

        if not predicted:
            return MatchingResult(
                matched_pairs=(),
                unmatched_predictions=(),
                unmatched_ground_truth=tuple(gt.id for gt in ground_truth),
                near_misses=(),
            )

        # Build adjacency graph
        adj: dict[str, list[str]] = {str(p["id"]): [] for p in predicted}
        near_misses: list[tuple[str, str, str]] = []

        for p in predicted:
            p_id = str(p["id"])
            p_entities = {str(e).lower() for e in p.get("entities", [])}
            p_text = f"{p.get('title', '')} {p.get('description', '')}".lower()
            p_behavior = p.get("behavior_class", "").lower()
            p_tech = str(p.get("technique_id") or "").lower()

            for gt in ground_truth:
                gt_entities = {e.lower() for e in gt.primary_entities}
                gt_behavior = gt.behavior_class.lower()

                # Entity overlap check
                entity_overlap = bool(p_entities & gt_entities)

                # Behavior match check
                behavior_match = False
                if p_behavior and p_behavior == gt_behavior:
                    behavior_match = True
                elif gt_behavior == "credential_access" and any(
                    k in p_text for k in ("brute force", "password", "credential", "auth")
                ):
                    behavior_match = True
                elif gt_behavior == "privilege_escalation" and any(
                    k in p_text for k in ("sudo", "root", "privilege", "elevation")
                ):
                    behavior_match = True
                elif gt_behavior == "web_attack" and any(
                    k in p_text for k in ("sql", "sqli", "injection", "traversal", "web")
                ):
                    behavior_match = True
                elif gt_behavior == "attack_chain" and any(
                    k in p_text for k in ("chain", "lateral", "progression", "multi-hop")
                ):
                    behavior_match = True

                # Technique exact match
                if gt.technique_id and p_tech and p_tech == gt.technique_id.lower():
                    behavior_match = True

                if behavior_match and entity_overlap:
                    adj[p_id].append(gt.id)
                elif behavior_match and not entity_overlap:
                    near_misses.append((p_id, gt.id, "behavior_matched_but_entity_mismatched"))
                elif entity_overlap and not behavior_match:
                    near_misses.append((p_id, gt.id, "entity_matched_but_behavior_mismatched"))

        # Exact Maximum Bipartite Matching via augmenting paths (DFS)
        pair_gt_to_pred: dict[str, str] = {}

        def dfs(u: str, visited: set[str]) -> bool:
            for v in adj[u]:
                if v not in visited:
                    visited.add(v)
                    if v not in pair_gt_to_pred or dfs(pair_gt_to_pred[v], visited):
                        pair_gt_to_pred[v] = u
                        return True
            return False

        for p_id in adj:
            visited_set: set[str] = set()
            dfs(p_id, visited_set)

        matched_pairs: list[tuple[str, str]] = [
            (pred_id, gt_id) for gt_id, pred_id in pair_gt_to_pred.items()
        ]
        matched_preds = {pred_id for pred_id, _ in matched_pairs}
        matched_gts = {gt_id for _, gt_id in matched_pairs}

        unmatched_preds = [str(p["id"]) for p in predicted if str(p["id"]) not in matched_preds]
        unmatched_gts = [gt.id for gt in ground_truth if gt.id not in matched_gts]

        return MatchingResult(
            matched_pairs=tuple(matched_pairs),
            unmatched_predictions=tuple(unmatched_preds),
            unmatched_ground_truth=tuple(unmatched_gts),
            near_misses=tuple(near_misses),
        )
