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
from acip.api.deps import Admin, Services, get_services, get_session
from acip.api.schemas import (
    AdminCapabilitiesResponse,
    AgentCapabilityInfo,
    CapabilitiesResponse,
    HealthResponse,
    ToolCapability,
)
from acip.core.limitations import OPERATING_BOUNDARY, get_not_implemented
from acip.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
async def health(session: Annotated[AsyncSession, Depends(get_session)]) -> HealthResponse:
    """Liveness plus a real database round trip."""
    database = "ok"
    try:
        await session.execute(sa.text("SELECT 1"))
    except Exception as exc:
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
    """Coarse capability report for clients without disclosing internal diagnostics."""
    return CapabilitiesResponse(
        environment=services.settings.environment,
        tools=services.tools.names(),
        agents=services.agents.names(),
        planner=services.planner.name,
        not_implemented=get_not_implemented(services.settings),
        operating_boundary=OPERATING_BOUNDARY,
    )


@router.get("/admin/capabilities", response_model=AdminCapabilitiesResponse)
async def admin_capabilities(
    _admin: Admin,
    services: Annotated[Services, Depends(get_services)],
) -> AdminCapabilitiesResponse:
    """Detailed diagnostic capability report with live probe outputs for administrators."""
    return AdminCapabilitiesResponse(
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
        not_implemented=get_not_implemented(services.settings),
        operating_boundary=OPERATING_BOUNDARY,
    )
