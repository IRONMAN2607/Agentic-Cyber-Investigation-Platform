"""Integration tests for benchmark execution runner and report generator."""

from __future__ import annotations

from pathlib import Path

import pytest
from experiments.results.report_generator import EvaluationReportGenerator
from experiments.runners.benchmark_runner import BenchmarkRunner
from pydantic import SecretStr

from acip.config import Settings
from acip.db.session import Database


@pytest.mark.asyncio
async def test_benchmark_runner_executes_conditions(database: Database, tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        artifact_dir=tmp_path / "artifacts",
        secret_key=SecretStr("bench-secret-key-that-is-at-least-32-bytes-long"),
        enable_adaptive_planning=True,
    )
    runner = BenchmarkRunner(database=database, settings=settings)

    # 1. Run single scenario under Condition D (Proposed)
    m_d = await runner.run_scenario("ssh_brute_force_sudo", "condition_d_proposed")
    assert m_d.scenario_id == "ssh_brute_force_sudo"
    assert m_d.condition == "condition_d_proposed"
    assert m_d.precision > 0.0
    assert m_d.recall > 0.0
    assert m_d.f1_score > 0.0
    assert m_d.fabrication_count == 0

    # 2. Run clean benign scenario under Condition D (assert FPR = 0)
    m_benign = await runner.run_scenario("clean_benign_baseline", "condition_d_proposed")
    assert m_benign.false_positive_rate_benign == 0.0

    # 3. Run comparative suite across Condition A and Condition D
    suite = await runner.run_all(
        conditions=["condition_a_rules", "condition_d_proposed"],
        scenario_ids=["ssh_brute_force_sudo", "web_sqli_attack"],
    )
    summary = suite.summary_table()
    assert len(summary) == 2

    # 4. Generate report artifacts
    output_dir = tmp_path / "results"
    md_file, json_file = EvaluationReportGenerator.save_results(suite, output_dir)
    assert md_file.exists()
    assert json_file.exists()

    md_content = md_file.read_text(encoding="utf-8")
    assert "ACIP Empirical Evaluation Results" in md_content
    assert "Condition D (Proposed)" in md_content
