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

import sqlalchemy as sa

from acip import __version__
from acip.bootstrap import bootstrap
from acip.config import Settings, get_settings
from acip.core.security.passwords import MIN_PASSWORD_LENGTH, hash_password
from acip.db.models import User
from acip.db.session import Database
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


async def _create_user(
    settings: Settings, username: str, role: str, email: str | None
) -> int:
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
        await database.create_all()
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
    from acip.core.limitations import NOT_IMPLEMENTED

    payload = {
        "version": __version__,
        "environment": settings.environment,
        "tools": [probe.model_dump(mode="json") for probe in build_tool_registry().capabilities()],
        "agents": build_agent_registry().describe(),
        "not_implemented": list(NOT_IMPLEMENTED),
    }
    print(json.dumps(payload, indent=2))


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
