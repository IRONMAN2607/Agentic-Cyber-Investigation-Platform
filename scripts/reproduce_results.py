"""One-command experiment reproduction runner for ACIP.

Executes the full evaluation matrix across experimental conditions (A through D)
and ablations, validates formal grounding invariants, verifies zero fabrications,
and saves certified evaluation artifacts with SHA256 checksums.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from experiments.results.report_generator import EvaluationReportGenerator
from experiments.runners.benchmark_runner import BenchmarkRunner
from pydantic import SecretStr

from acip.bootstrap import bootstrap
from acip.config import Settings
from acip.db.session import Database


def compute_sha256(path: Path) -> str:
    """Compute SHA256 digest of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


async def run_reproduction(output_dir: Path) -> int:
    """Execute complete reproduction pipeline."""
    print("=" * 70)
    print("ACIP RESEARCH REPRODUCIBILITY SUITE")
    print("=" * 70)
    print(f"Output directory: {output_dir.resolve()}\n")

    output_dir.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        environment="test",
        artifact_dir=output_dir / "artifacts",
        database_url=f"sqlite+aiosqlite:///{output_dir.resolve().as_posix()}/reproduce.db",
        secret_key=SecretStr("repro-secret-key-at-least-32-bytes-long-for-test"),
        enable_adaptive_planning=True,
    )
    settings.ensure_directories()

    database = Database(settings.database_url, echo=False)
    try:
        print("[1/4] Bootstrapping schema and initializing database...")
        await bootstrap(database, settings)

        print("[2/4] Executing benchmark matrix across conditions A through D...")
        runner = BenchmarkRunner(database=database, settings=settings)
        suite = await runner.run_all(
            conditions=[
                "condition_a_rules",
                "condition_b_single_llm",
                "condition_c_no_graph",
                "condition_d_proposed",
            ]
        )

        print("[3/4] Generating evaluation report and raw metrics JSON...")
        md_path, json_path = EvaluationReportGenerator.save_results(suite, output_dir)
        print(f"      Report generated: {md_path}")
        print(f"      Metrics JSON:     {json_path}")

        print("\n[4/4] Verifying grounding claims and computing checksums...")
        summary = suite.summary_table()
        checksum_lines: list[str] = []

        for p in (md_path, json_path):
            digest = compute_sha256(p)
            checksum_lines.append(f"{digest}  {p.name}")
            print(f"      SHA256({p.name}): {digest}")

        checksum_path = output_dir / "CHECKSUMS.sha256"
        checksum_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        print(f"      Wrote checksums to: {checksum_path}")

        # Assert scientific invariants
        print("\n" + "=" * 70)
        print("VERIFICATION OF SCIENTIFIC INVARIANTS")
        print("=" * 70)

        all_fabrications = sum(row["total_fabrications"] for row in summary)
        all_fpr_benign = [row["fpr_benign"] for row in summary]
        all_prov_comp = [row["provenance_completeness"] for row in summary]

        print(f"- Total Fabrications Across All Conditions: {all_fabrications}")
        assert all_fabrications == 0, f"Expected 0 fabrications, got {all_fabrications}"
        print("  -> PASS: Zero hallucinations/fabrications confirmed.")

        print(f"- Benign Baseline False-Positive Rates:     {all_fpr_benign}")
        assert all(fpr == 0.0 for fpr in all_fpr_benign), "Benign FPR exceeded 0.0"
        print("  -> PASS: Zero false positives on routine operational traffic.")

        print(f"- Provenance Completeness:                  {all_prov_comp}")
        assert all(p == 1.0 for p in all_prov_comp), "Provenance completeness under 1.0"
        print("  -> PASS: 100% of claims backed by verified deterministic tool evidence.")

        print("\n" + EvaluationReportGenerator.generate_markdown_table(suite))
        print("\nREPRODUCIBILITY RUN COMPLETED SUCCESSFULLY.")
        return 0

    except Exception as exc:
        print(f"\nREPRODUCIBILITY RUN FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        await database.dispose()


def main() -> int:
    out_dir = Path("experiments/results")
    if len(sys.argv) > 1:
        out_dir = Path(sys.argv[1])
    return asyncio.run(run_reproduction(out_dir))


if __name__ == "__main__":
    raise SystemExit(main())
