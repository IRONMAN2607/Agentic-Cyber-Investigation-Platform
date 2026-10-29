"""Seed and execute the synthetic investigations used in local demonstrations."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import sqlalchemy as sa

from acip.config import Settings
from acip.db.models import Artifact, Investigation, User
from acip.db.session import Database
from acip.demo_data import DEMO_INVESTIGATIONS, DemoInvestigation
from acip.errors import ConfigurationError
from acip.types import InvestigationStatus, Severity


@dataclass(frozen=True, slots=True)
class DemoSeedResult:
    """Persisted state and deterministic risk evaluation for one demo row."""

    sample: DemoInvestigation
    investigation_id: uuid.UUID
    created: bool
    status: str
    severity: str | None
    risk_score: int | None

    @property
    def evaluation_passed(self) -> bool:
        """Whether the computed roll-up matches the sample's declared risk band."""
        if self.sample.risk_band == "high":
            return (
                self.risk_score is not None
                and self.risk_score >= 20
                and self.severity in {Severity.HIGH.value, Severity.CRITICAL.value}
            )
        return (self.risk_score or 0) <= 10 and self.severity in {
            Severity.INFO.value,
            Severity.LOW.value,
        }


async def seed_demo_investigations(
    database: Database,
    settings: Settings,
    *,
    execute: bool = True,
) -> list[DemoSeedResult]:
    """Create all demo investigations and optionally run the real pipeline.

    The operation is idempotent by title. Existing rows are reported and are not
    duplicated; rows still in ``created`` state are executed when ``execute`` is
    true. Demo data is deliberately blocked in production.
    """
    if settings.is_prod:
        raise ConfigurationError("demo investigation seeding is disabled in production")

    settings.ensure_directories()
    titles = [sample.title for sample in DEMO_INVESTIGATIONS]
    created_ids: list[uuid.UUID] = []
    result_metadata: dict[uuid.UUID, tuple[DemoInvestigation, bool]] = {}

    async with database.session() as session:
        existing_rows = list(
            (
                await session.scalars(
                    sa.select(Investigation).where(Investigation.title.in_(titles))
                )
            ).all()
        )
        existing_by_title = {row.title: row for row in existing_rows}
        admin = await session.scalar(
            sa.select(User).where(User.username == settings.bootstrap_admin_username)
        )

        for sample in DEMO_INVESTIGATIONS:
            existing = existing_by_title.get(sample.title)
            if existing is not None:
                result_metadata[existing.id] = (sample, False)
                if execute and existing.status == InvestigationStatus.CREATED.value:
                    created_ids.append(existing.id)
                continue

            investigation = Investigation(
                title=sample.title,
                target_type=sample.target_type.value,
                target_value=sample.target_value,
                status=InvestigationStatus.CREATED.value,
                created_by=admin.id if admin is not None else None,
            )
            session.add(investigation)
            await session.flush()

            for demo_artifact in sample.artifacts:
                from acip.core.security.files import store_bytes

                stored = await store_bytes(
                    demo_artifact.content,
                    dest_dir=settings.artifact_dir,
                    max_bytes=settings.max_artifact_bytes,
                    original_filename=demo_artifact.filename,
                    declared_kind=demo_artifact.kind,
                )
                session.add(
                    Artifact(
                        investigation_id=investigation.id,
                        kind=demo_artifact.kind.value,
                        original_filename=stored.safe_filename,
                        sha256=stored.sha256,
                        size_bytes=stored.size_bytes,
                        storage_path=str(stored.path),
                        uploaded_by=admin.id if admin is not None else None,
                    )
                )

            await session.flush()
            result_metadata[investigation.id] = (sample, True)
            created_ids.append(investigation.id)

    if execute and created_ids:
        from acip.api.app import build_services

        execution_settings = settings.model_copy(update={"enable_llm_triage": False})
        services = build_services(execution_settings, database)
        try:
            for investigation_id in created_ids:
                await services.runner.submit(investigation_id)
        finally:
            await services.runner.shutdown()

    async with database.session() as session:
        rows = list(
            (
                await session.scalars(
                    sa.select(Investigation).where(
                        Investigation.id.in_(list(result_metadata)),
                    )
                )
            ).all()
        )

    rows_by_id = {row.id: row for row in rows}
    return [
        DemoSeedResult(
            sample=sample,
            investigation_id=investigation_id,
            created=created,
            status=rows_by_id[investigation_id].status,
            severity=rows_by_id[investigation_id].severity,
            risk_score=rows_by_id[investigation_id].risk_score,
        )
        for investigation_id, (sample, created) in result_metadata.items()
    ]


__all__ = ["DemoSeedResult", "seed_demo_investigations"]
