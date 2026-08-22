"""Health and capability endpoints.

``/capabilities`` is a first-class endpoint, not a convenience: the platform's
honesty guarantee requires a machine-readable statement of what this deployment
can and cannot do, so a client never renders a capability that does not exist.
"""

from __future__ import annotations

from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from acip import __version__
from acip.api.deps import Services, get_services, get_session
from acip.api.schemas import (
    AgentCapabilityInfo,
    CapabilitiesResponse,
    HealthResponse,
    ToolCapability,
)
from acip.core.limitations import NOT_IMPLEMENTED
from acip.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
async def health(session: Annotated[AsyncSession, Depends(get_session)]) -> HealthResponse:
    """Liveness plus a real database round trip."""
    database = "ok"
    try:
        await session.execute(sa.text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        logger.error("database health check failed", extra={"error": str(exc)})
        database = "unavailable"
    return HealthResponse(
        status="ok" if database == "ok" else "degraded",
        database=database,
        version=__version__,
    )


@router.get("/capabilities", response_model=CapabilitiesResponse)
async def capabilities(
    services: Annotated[Services, Depends(get_services)],
) -> CapabilitiesResponse:
    """What is actually installed and runnable right now."""
    return CapabilitiesResponse(
        environment=services.settings.environment,
        tools=[
            ToolCapability(
                name=probe.name,
                version=probe.version,
                tier=probe.tier.value,
                available=probe.available,
                reason=probe.reason,
            )
            for probe in services.tools.capabilities()
        ],
        agents=[AgentCapabilityInfo(**info) for info in services.agents.describe()],
        planner=services.planner.name,
        not_implemented=list(NOT_IMPLEMENTED),
    )
