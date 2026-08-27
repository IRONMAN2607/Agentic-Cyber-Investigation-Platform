"""FastAPI application factory.

``create_app`` takes optional settings and database instances so tests can build
an app against an isolated database without patching module state. Domain errors
are translated to HTTP here, and only here — the domain layer raises
:class:`~acip.errors.ACIPError` subclasses and knows nothing about HTTP.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from acip import __version__
from acip.agents.registry import build_default_registry as build_agent_registry
from acip.api.deps import Services
from acip.api.routers import auth, investigations, system
from acip.bootstrap import bootstrap
from acip.config import Settings, get_settings
from acip.core.orchestration.orchestrator import Orchestrator
from acip.core.orchestration.planner import StaticPlanner
from acip.core.orchestration.runner import InvestigationRunner
from acip.db.session import Database
from acip.errors import ACIPError
from acip.logging import configure_logging, get_logger
from acip.tools.registry import build_default_registry as build_tool_registry

logger = get_logger(__name__)

DESCRIPTION = """
Evidence-first cyber investigation platform.

Every claim returned by this API carries an assertion class (`fact`,
`inference`, `hypothesis`, `unknown`), the evidence it cites, and the tool run
that produced that evidence. `GET /capabilities` reports what this deployment
can actually do; anything listed under `not_implemented` was not performed.
""".strip()


def build_services(settings: Settings, database: Database) -> Services:
    """Compose the object graph. Pure wiring, no I/O."""
    tools = build_tool_registry()
    agents = build_agent_registry()
    planner = StaticPlanner(agents)
    orchestrator = Orchestrator(
        database=database,
        settings=settings,
        agents=agents,
        tools=tools,
        planner=planner,
    )
    runner = InvestigationRunner(orchestrator=orchestrator, database=database)
    return Services(
        settings=settings,
        database=database,
        tools=tools,
        agents=agents,
        planner=planner,
        runner=runner,
    )


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    run_bootstrap: bool = True,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)
    owns_database = database is None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = database or Database(settings.database_url, echo=settings.db_echo)
        if run_bootstrap:
            await bootstrap(db, settings)
        app.state.services = build_services(settings, db)
        await app.state.services.runner.recover_interrupted()
        logger.info(
            "application ready",
            extra={
                "environment": settings.environment,
                "tools": app.state.services.tools.names(),
                "agents": app.state.services.agents.names(),
            },
        )
        try:
            yield
        finally:
            await app.state.services.runner.shutdown()
            if owns_database:
                await db.dispose()

    app = FastAPI(
        title="Agentic Cyber Investigation Platform",
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    prefix = settings.api_prefix
    app.include_router(system.router, prefix=prefix)
    app.include_router(auth.router, prefix=prefix)
    app.include_router(investigations.router, prefix=prefix)

    web_dir = Path("web")
    if web_dir.exists() and (web_dir / "index.html").exists():
        app.mount("/", StaticFiles(directory="web", html=True), name="web")

    _install_error_handlers(app, settings)
    return app


def _install_error_handlers(app: FastAPI, settings: Settings) -> None:
    @app.exception_handler(ACIPError)
    async def _acip_error(_request: Request, exc: ACIPError) -> JSONResponse:
        if exc.status_code >= 500:
            # "message" and "asctime" are reserved on LogRecord: passing either in
            # extra raises KeyError inside makeRecord, and an exception raised in
            # an exception handler is not caught by the Exception handler below.
            # That lost the documented envelope for every 5xx ACIPError, which
            # includes GroundingError - the one error the platform most needs to
            # report. tests/security/test_static_invariants.py now blocks the class.
            logger.error(
                "request failed", extra={"error_code": exc.code, "error_message": exc.message}
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"code": exc.code, "message": exc.message, "detail": exc.detail},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "code": "validation_error",
                "message": "request validation failed",
                "detail": {"errors": _serialisable_errors(exc)},
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled exception")
        # An internal error message can carry file paths, SQL or fragments of
        # artifact content, so it is only echoed when debug is explicitly on.
        message = f"{type(exc).__name__}: {exc}" if settings.debug else "internal server error"
        return JSONResponse(
            status_code=500,
            content={"code": "internal_error", "message": message, "detail": {}},
        )


def _serialisable_errors(exc: RequestValidationError) -> list[dict[str, object]]:
    """Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of errors."""
    cleaned: list[dict[str, object]] = []
    for error in exc.errors():
        entry: dict[str, object] = {}
        for key, value in error.items():
            if key == "input":
                continue
            if key == "ctx" and isinstance(value, dict):
                entry[key] = {k: str(v) for k, v in value.items()}
            else:
                entry[key] = value
        entry["loc"] = [str(part) for part in error.get("loc", ())]
        cleaned.append(entry)
    return cleaned
