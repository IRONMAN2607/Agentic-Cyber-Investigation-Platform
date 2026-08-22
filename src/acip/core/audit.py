"""Audit trail writes.

Security-relevant actions are recorded in an append-only table (spec s13). This
module is the only place that writes it, so the set of audited actions is
enumerable by reading one file.

The rows are immutable at the mapper level (see :mod:`acip.db.models`), which is
why this module offers no update or delete.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from acip.db.models import AuditLog
from acip.logging import get_logger

logger = get_logger(__name__)

# Audited actions. Kept as constants so a typo cannot silently create a new
# action name that nothing queries for.
LOGIN_SUCCEEDED = "login.succeeded"
LOGIN_FAILED = "login.failed"
INVESTIGATION_CREATED = "investigation.created"
INVESTIGATION_STARTED = "investigation.started"
INVESTIGATION_FINISHED = "investigation.finished"
ARTIFACT_UPLOADED = "artifact.uploaded"
ARTIFACT_REJECTED = "artifact.rejected"
REPORT_READ = "report.read"

SUCCESS = "success"
FAILURE = "failure"


async def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    outcome: str = SUCCESS,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one audit row.

    ``actor`` is a username or ``"system"``; never a raw password or token.
    """
    row = AuditLog(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        detail=detail or {},
    )
    session.add(row)
    await session.flush()
    logger.info(
        "audit",
        extra={
            "audit_action": action,
            "actor": actor,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
        },
    )
    return row
