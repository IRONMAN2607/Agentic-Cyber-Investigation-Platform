"""Command-line entry point.

Provides the operational commands a fresh checkout needs: initialise storage,
create a user, inspect what the deployment can do, and serve the API.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path

import sqlalchemy as sa

from acip import __version__
from acip.bootstrap import bootstrap
from acip.config import Settings, get_settings
from acip.core.backup import create_backup, restore_backup
from acip.core.security.passwords import MIN_PASSWORD_LENGTH, hash_password
from acip.db.migrate import upgrade_to_head
from acip.db.models import User
from acip.db.session import Database
from acip.demo import seed_demo_investigations
from acip.errors import ConfigurationError
from acip.logging import configure_logging, get_logger
from acip.tools.registry import build_default_registry as build_tool_registry
from acip.types import Role

logger = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acip", description="AACIP operations CLI")
    parser.add_argument("--version", action="version", version=f"acip {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create storage directories and the database schema")

    serve = sub.add_parser("serve", help="run the API server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")

    create_user = sub.add_parser("create-user", help="create a user account")
    create_user.add_argument("username")
    create_user.add_argument(
        "--role",
        default=Role.INVESTIGATOR.value,
        choices=[role.value for role in Role],
    )
    create_user.add_argument("--email", default=None)

    sub.add_parser("capabilities", help="print what this deployment can actually do")

    seed_samples = sub.add_parser(
        "seed-samples",
        help="create the 16 synthetic high- and low-risk investigations for every target type",
    )
    seed_samples.add_argument(
        "--no-run",
        action="store_true",
        help="create the sample rows and artifacts without executing investigations",
    )

    backup = sub.add_parser("backup", help="create a verified database and artifact backup")
    backup.add_argument("destination", type=Path)
    restore = sub.add_parser(
        "restore", help="verify and restore a backup into empty configured paths"
    )
    restore.add_argument("source", type=Path)

    benchmark = sub.add_parser("benchmark", help="run evaluation benchmark matrix across baselines")
    benchmark.add_argument("--output-dir", type=Path, default=Path("experiments/results"))
    benchmark.add_argument(
        "--condition",
        default="all",
        choices=[
            "all",
            "condition_a_rules",
            "condition_b_single_llm",
            "condition_c_no_graph",
            "condition_d_proposed",
        ],
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level, "console")

    match args.command:
        case "init":
            asyncio.run(_init(settings))
        case "create-user":
            return asyncio.run(_create_user(settings, args.username, args.role, args.email))
        case "capabilities":
            _capabilities(settings)
        case "seed-samples":
            return asyncio.run(_seed_samples(settings, execute=not args.no_run))
        case "backup":
            _backup(settings, args.destination)
        case "restore":
            _restore(settings, args.source)
        case "benchmark":
            return asyncio.run(_benchmark(settings, args.output_dir, args.condition))
        case "serve":
            return _serve(args.host, args.port, args.reload)
    return 0


async def _init(settings: Settings) -> None:
    database = Database(settings.database_url, echo=settings.db_echo)
    try:
        await bootstrap(database, settings)
        print(f"Storage ready. Artifacts: {settings.artifact_dir}")
    finally:
        await database.dispose()


async def _seed_samples(settings: Settings, *, execute: bool) -> int:
    """Seed and optionally execute the complete local demonstration catalog."""
    database = Database(settings.database_url, echo=settings.db_echo)
    try:
        await bootstrap(database, settings)
        results = await seed_demo_investigations(database, settings, execute=execute)
    except ConfigurationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        await database.dispose()

    action = "seeded and evaluated" if execute else "prepared"
    new_count = sum(1 for result in results if result.created)
    print(f"Demo investigations {action}: {len(results)} ({new_count} new)")
    for result in results:
        if execute:
            evaluation = "PASS" if result.evaluation_passed else "CHECK"
            risk = f"{result.risk_score}/100" if result.risk_score is not None else "n/a"
            severity = result.severity or "n/a"
            print(
                f"{evaluation:5} {result.sample.risk_band:4} {result.sample.target_type.value:11} "
                f"{severity:8} risk={risk:>7} {result.sample.title} "
                f"({result.investigation_id})"
            )
        else:
            print(
                f"READY {result.sample.risk_band:4} {result.sample.target_type.value:11} "
                f"{result.sample.title} ({result.investigation_id})"
            )
    return 0


async def _create_user(settings: Settings, username: str, role: str, email: str | None) -> int:
    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        print(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
            file=sys.stderr,
        )
        return 2
    if password != getpass.getpass("Confirm: "):
        print("Passwords do not match.", file=sys.stderr)
        return 2

    database = Database(settings.database_url, echo=settings.db_echo)
    try:
        await upgrade_to_head(settings.database_url)
        async with database.session() as session:
            existing = await session.scalar(sa.select(User).where(User.username == username))
            if existing is not None:
                print(f"User {username!r} already exists.", file=sys.stderr)
                return 1
            session.add(
                User(
                    username=username,
                    email=email,
                    password_hash=hash_password(password),
                    role=role,
                )
            )
        print(f"Created {role} {username!r}.")
        return 0
    finally:
        await database.dispose()


def _capabilities(settings: Settings) -> None:
    """Print the real capability set, probed rather than assumed."""
    from acip.agents.registry import build_default_registry as build_agent_registry
    from acip.core.limitations import OPERATING_BOUNDARY, get_not_implemented

    payload = {
        "version": __version__,
        "environment": settings.environment,
        "tools": [probe.model_dump(mode="json") for probe in build_tool_registry().capabilities()],
        "agents": build_agent_registry().describe(),
        "not_implemented": get_not_implemented(settings),
        "operating_boundary": OPERATING_BOUNDARY,
    }
    print(json.dumps(payload, indent=2))


def _backup(settings: Settings, destination: Path) -> None:
    """Create an integrity-checked backup without starting the API."""
    print(f"Verified backup created: {create_backup(settings, destination)}")


def _restore(settings: Settings, source: Path) -> None:
    """Restore a verified backup only into empty configured storage."""
    restore_backup(source, settings)
    print(f"Verified backup restored from: {source.resolve()}")


async def _benchmark(settings: Settings, output_dir: Path, condition: str) -> int:
    database = Database(settings.database_url, echo=settings.db_echo)
    try:
        from experiments.results.report_generator import EvaluationReportGenerator
        from experiments.runners.benchmark_runner import BenchmarkRunner

        from acip.bootstrap import bootstrap

        await bootstrap(database, settings)
        runner = BenchmarkRunner(database=database, settings=settings)
        conditions = None if condition == "all" else [condition]
        suite = await runner.run_all(conditions=conditions)
        md_file, json_file = EvaluationReportGenerator.save_results(suite, output_dir)
        print(f"Benchmark run complete. Report saved to: {md_file}")
        print(f"Raw metrics JSON saved to: {json_file}")
        print("\n" + EvaluationReportGenerator.generate_markdown_table(suite))
        return 0
    finally:
        await database.dispose()


def _serve(host: str, port: int, reload: bool) -> int:
    try:
        import uvicorn
    except ImportError:  # pragma: no cover - uvicorn is a declared dependency
        print("uvicorn is not installed.", file=sys.stderr)
        return 1

    uvicorn.run(
        "acip.api.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_config=None,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
