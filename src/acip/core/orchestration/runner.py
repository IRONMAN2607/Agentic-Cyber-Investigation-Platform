"""Background execution of investigations.

M1 runs investigations as asyncio tasks in the API process. That is a deliberate
scope decision, not an oversight: the work is I/O- and CPU-light (text parsing),
and a broker would add operational surface with nothing to show for it yet. The
seam is this class — Phase 4 replaces the body of :meth:`submit` with a queue
publish when container-isolated tools make out-of-process execution mandatory.

Two properties are preserved regardless of backend:

* **Bounded concurrency.** A semaphore caps simultaneous investigations, so a
  burst of submissions degrades latency instead of exhausting the machine.
* **No silent loss.** Every task is tracked, awaited at shutdown, and a crash in
  the orchestrator itself is written back to the investigation row.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import uuid

import sqlalchemy as sa

from acip.core import audit
from acip.core.orchestration.orchestrator import Orchestrator
from acip.db.models import Investigation
from acip.db.session import Database
from acip.logging import get_logger
from acip.types import InvestigationStatus

logger = get_logger(__name__)


class InvestigationRunner:
    """Schedules investigations with bounded concurrency."""

    def __init__(
        self,
        *,
        orchestrator: Orchestrator,
        database: Database,
        max_concurrent: int = 2,
    ) -> None:
        self._orchestrator = orchestrator
        self._db = database
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks: set[asyncio.Task[None]] = set()

    def submit(self, investigation_id: uuid.UUID) -> asyncio.Task[None]:
        """Schedule an investigation and return its task handle."""
        task = asyncio.create_task(
            self._guarded(investigation_id), name=f"investigation-{investigation_id}"
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    @property
    def in_flight(self) -> int:
        return len(self._tasks)

    async def cancel(self, investigation_id: uuid.UUID) -> bool:
        """Cancel an in-flight investigation task."""
        for task in list(self._tasks):
            if task.get_name() == f"investigation-{investigation_id}":
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
                await self._mark_failed(
                    investigation_id,
                    "investigation cancelled by user",
                    status=InvestigationStatus.HALTED,
                )
                return True
        return False

    async def wait_all(self, timeout: float | None = None) -> None:  # noqa: ASYNC109
        """Await every scheduled investigation. Used by tests and shutdown."""
        if not self._tasks:
            return
        pending = set(self._tasks)
        done, still_pending = await asyncio.wait(pending, timeout=timeout)
        del done
        if still_pending:
            logger.warning(
                "investigations still running at shutdown",
                extra={"count": len(still_pending)},
            )

    async def shutdown(self, timeout: float = 30.0) -> None:  # noqa: ASYNC109
        """Cancel outstanding work after giving it a chance to finish."""
        await self.wait_all(timeout=timeout)
        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    async def recover_interrupted(self) -> int:
        """Mark orphan running investigations as interrupted on startup."""
        async with self._db.session() as session:
            rows = (
                await session.scalars(
                    sa.select(Investigation).where(
                        Investigation.status == InvestigationStatus.RUNNING.value
                    )
                )
            ).all()
            recovered = 0
            now = dt.datetime.now(dt.UTC)
            for inv in rows:
                inv.status = InvestigationStatus.FAILED.value
                inv.completed_at = now
                inv.error = "interrupted: server restarted while execution was in progress"
                recovered += 1
                await audit.record(
                    session,
                    actor="system",
                    action=audit.INVESTIGATION_FINISHED,
                    resource_type="investigation",
                    resource_id=str(inv.id),
                    outcome=audit.FAILURE,
                    detail={"reason": "server restarted during execution"},
                )
            if recovered:
                logger.warning(
                    "recovered interrupted investigations",
                    extra={"count": recovered},
                )
            return recovered

    async def _guarded(self, investigation_id: uuid.UUID) -> None:
        async with self._semaphore:
            try:
                await self._orchestrator.execute(investigation_id)
            except asyncio.CancelledError:
                await self._mark_failed(
                    investigation_id,
                    "execution was cancelled",
                    status=InvestigationStatus.HALTED,
                )
                raise
            except Exception as exc:
                logger.exception(
                    "orchestrator crashed",
                    extra={"investigation_id": str(investigation_id)},
                )
                await self._mark_failed(investigation_id, f"{type(exc).__name__}: {exc}")

    async def _mark_failed(
        self,
        investigation_id: uuid.UUID,
        reason: str,
        status: InvestigationStatus = InvestigationStatus.FAILED,
    ) -> None:
        """Record an orchestrator-level crash on the investigation row."""
        try:
            async with self._db.session() as session:
                investigation = await session.get(Investigation, investigation_id)
                if investigation is None:
                    return
                investigation.status = status.value
                investigation.completed_at = dt.datetime.now(dt.UTC)
                investigation.error = reason
        except Exception:
            logger.exception(
                "could not record investigation failure",
                extra={"investigation_id": str(investigation_id)},
            )
