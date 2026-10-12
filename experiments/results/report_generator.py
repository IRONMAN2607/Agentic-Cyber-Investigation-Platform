"""Formats benchmark suite evaluation results into IEEE paper-ready markdown and JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from experiments.runners.benchmark_runner import BenchmarkSuiteResult


class EvaluationReportGenerator:
    """Generates Markdown and JSON summary tables from benchmark results."""

    @classmethod
    def generate_markdown_table(cls, suite: BenchmarkSuiteResult) -> str:
        summary = suite.summary_table()
        lines: list[str] = [
            "# ACIP Empirical Evaluation Results",
            "",
            "Comparative evaluation across experimental conditions and ablations.",
            "",
            "| Condition / Baseline | Precision | Recall | F1 Score | Benign FPR | "
            "Provenance Completeness | Fabrications |",
            "|---|---|---|---|---|---|---|",
        ]
        for row in summary:
            cond_label = (
                "**Condition D (Proposed)**"
                if row["condition"] == "condition_d_proposed"
                else (
                    "Baseline A (Rules Only)"
                    if row["condition"] == "condition_a_rules"
                    else (
                        "Baseline B (Single LLM)"
                        if row["condition"] == "condition_b_single_llm"
                        else (
                            "Baseline C (No Graph)"
                            if row["condition"] == "condition_c_no_graph"
                            else row["condition"]
                        )
                    )
                )
            )
            lines.append(
                f"| {cond_label} | {row['precision']:.3f} | {row['recall']:.3f} | "
                f"**{row['f1_score']:.3f}** | {row['fpr_benign']:.3f} | "
                f"{row['provenance_completeness']:.3f} | {row['total_fabrications']} |"
            )

        lines.extend(
            [
                "",
                "### Metric Definitions",
                (
                    "- **Precision / Recall / F1**: Computed via strict one-to-one maximum "
                    "bipartite matching between predicted and ground-truth findings."
                ),
                "- **Benign FPR**: False-positive rate on verified clean operational baselines.",
                (
                    "- **Provenance Completeness**: Proportion of claims with valid non-null "
                    "deterministic tool run and evidence records."
                ),
                "- **Fabrications**: Output entities absent from all immutable evidence rows.",
            ]
        )
        return "\n".join(lines)

    @classmethod
    def save_results(cls, suite: BenchmarkSuiteResult, output_dir: Path) -> tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        md_path = output_dir / "EVALUATION_REPORT.md"
        json_path = output_dir / "benchmark_results.json"

        md_content = cls.generate_markdown_table(suite)
        md_path.write_text(md_content, encoding="utf-8")

        data: dict[str, Any] = {
            "summary": suite.summary_table(),
            "runs": [r.to_dict() for r in suite.results],
        }
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        return md_path, json_path
