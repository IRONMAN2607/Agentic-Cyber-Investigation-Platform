"""Investigation lifecycle endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from acip.api.deps import (
    CurrentUser,
    Investigator,
    LoadedInvestigation,
    Services,
    get_services,
    get_session,
)
from acip.api.schemas import (
    AgentRunResponse,
    ArtifactResponse,
    EvidenceResponse,
    FindingResponse,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationResponse,
    PagedEvidence,
    ReportResponse,
    StartResponse,
    ToolRunResponse,
)
from acip.core import audit
from acip.core.security.files import store_stream
from acip.db.models import AgentRun, Artifact, Evidence, Finding, Investigation, Report, ToolRun
from acip.errors import ConflictError, NotFoundError
from acip.logging import get_logger
from acip.types import ArtifactKind, InvestigationStatus

logger = get_logger(__name__)
router = APIRouter(prefix="/investigations", tags=["investigations"])

_UPLOAD_CHUNK = 64 * 1024


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCreate,
    user: Investigator,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationResponse:
    investigation = Investigation(
        title=payload.title,
        target_type=payload.target_type.value,
        target_value=payload.target_value,
        status=InvestigationStatus.CREATED.value,
        created_by=user.id,
    )
    session.add(investigation)
    await session.flush()

    await audit.record(
        session,
        actor=user.username,
        action=audit.INVESTIGATION_CREATED,
        resource_type="investigation",
        resource_id=str(investigation.id),
        detail={"target_type": payload.target_type.value},
    )
    return InvestigationResponse.model_validate(investigation)


@router.get("", response_model=list[InvestigationResponse])
async def list_investigations(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[InvestigationResponse]:
    rows = await session.scalars(
        sa.select(Investigation)
        .order_by(Investigation.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [InvestigationResponse.model_validate(row) for row in rows.all()]


@router.get("/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation_detail(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationDetail:
    """Everything a workspace view needs, in one round trip.

    Evidence is excluded and paged separately: an investigation can produce
    thousands of observations, and silently truncating them here would misreport
    how much was collected.
    """
    investigation_id = investigation.id

    artifacts = (
        await session.scalars(
            sa.select(Artifact)
            .where(Artifact.investigation_id == investigation_id)
            .order_by(Artifact.uploaded_at)
        )
    ).all()
    findings = (
        await session.scalars(
            sa.select(Finding)
            .where(Finding.investigation_id == investigation_id)
            .order_by(Finding.created_at)
        )
    ).all()
    agent_runs = (
        await session.scalars(
            sa.select(AgentRun)
            .where(AgentRun.investigation_id == investigation_id)
            .order_by(AgentRun.started_at)
        )
    ).all()
    tool_runs = (
        await session.scalars(
            sa.select(ToolRun)
            .where(ToolRun.investigation_id == investigation_id)
            .order_by(ToolRun.started_at)
        )
    ).all()
    report = await session.scalar(
        sa.select(Report)
        .where(Report.investigation_id == investigation_id)
        .order_by(Report.generated_at.desc())
        .limit(1)
    )
    evidence_count = await session.scalar(
        sa.select(sa.func.count())
        .select_from(Evidence)
        .where(Evidence.investigation_id == investigation_id)
    )

    return InvestigationDetail(
        investigation=InvestigationResponse.model_validate(investigation),
        artifacts=[ArtifactResponse.model_validate(row) for row in artifacts],
        findings=[FindingResponse.model_validate(row) for row in findings],
        agent_runs=[AgentRunResponse.model_validate(row) for row in agent_runs],
        tool_runs=[ToolRunResponse.model_validate(row) for row in tool_runs],
        report=ReportResponse.model_validate(report) if report is not None else None,
        counts={
            "artifacts": len(artifacts),
            "findings": len(findings),
            "agent_runs": len(agent_runs),
            "tool_runs": len(tool_runs),
            "evidence": int(evidence_count or 0),
        },
    )


@router.post(
    "/{investigation_id}/artifacts",
    response_model=ArtifactResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_artifact(
    investigation: LoadedInvestigation,
    user: Investigator,
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
    file: Annotated[UploadFile, File(description="Artifact to analyse")],
    kind: Annotated[ArtifactKind, Form()] = ArtifactKind.UNKNOWN,
) -> ArtifactResponse:
    """Accept an artifact into content-addressed quarantine storage.

    The declared ``kind`` is recorded but not trusted; tool adapters validate
    content themselves.
    """
    if investigation.status_enum is not InvestigationStatus.CREATED:
        raise ConflictError(
            "artifacts can only be added before the investigation starts",
            detail={"status": investigation.status},
        )

    settings = services.settings
    try:
        stored = await store_stream(
            _chunks(file),
            dest_dir=settings.artifact_dir,
            max_bytes=settings.max_artifact_bytes,
            original_filename=file.filename or "",
        )
    except Exception as exc:
        # Rejections are audited too: a stream of oversized or malformed uploads
        # is itself a signal worth retaining.
        await audit.record(
            session,
            actor=user.username,
            action=audit.ARTIFACT_REJECTED,
            resource_type="investigation",
            resource_id=str(investigation.id),
            outcome=audit.FAILURE,
            detail={"reason": f"{type(exc).__name__}: {exc}"},
        )
        raise

    artifact = Artifact(
        investigation_id=investigation.id,
        kind=kind.value,
        original_filename=stored.safe_filename,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        storage_path=str(stored.path),
        uploaded_by=user.id,
    )
    session.add(artifact)
    await session.flush()

    await audit.record(
        session,
        actor=user.username,
        action=audit.ARTIFACT_UPLOADED,
        resource_type="artifact",
        resource_id=str(artifact.id),
        detail={
            "investigation_id": str(investigation.id),
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "declared_kind": kind.value,
        },
    )
    return ArtifactResponse.model_validate(artifact)


@router.post("/{investigation_id}/start", response_model=StartResponse)
async def start_investigation(
    investigation: LoadedInvestigation,
    user: Investigator,
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> StartResponse:
    """Queue the investigation for execution.

    Returns immediately; progress is observed through the detail endpoint.
    """
    if investigation.status_enum is not InvestigationStatus.CREATED:
        raise ConflictError(
            f"investigation is already {investigation.status}",
            detail={"status": investigation.status},
        )

    investigation.status = InvestigationStatus.RUNNING.value
    # Committed before scheduling: the background task uses its own connection
    # and must not race this transaction for the row.
    await session.commit()

    services.runner.submit(investigation.id)
    logger.info(
        "investigation queued",
        extra={"investigation_id": str(investigation.id), "actor": user.username},
    )
    return StartResponse(
        investigation_id=investigation.id,
        status=InvestigationStatus.RUNNING,
        accepted=True,
        message="Investigation queued. Poll the detail endpoint for progress.",
    )


@router.get("/{investigation_id}/evidence", response_model=PagedEvidence)
async def list_evidence(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    kind: Annotated[str | None, Query()] = None,
) -> PagedEvidence:
    conditions = [Evidence.investigation_id == investigation.id]
    if kind:
        conditions.append(Evidence.kind == kind)

    total = await session.scalar(
        sa.select(sa.func.count()).select_from(Evidence).where(*conditions)
    )
    rows = await session.scalars(
        sa.select(Evidence)
        .where(*conditions)
        .order_by(Evidence.observed_at.is_(None), Evidence.observed_at, Evidence.collected_at)
        .limit(limit)
        .offset(offset)
    )
    return PagedEvidence(
        items=[EvidenceResponse.model_validate(row) for row in rows.all()],
        total=int(total or 0),
        limit=limit,
        offset=offset,
    )


@router.get("/{investigation_id}/report", response_model=ReportResponse)
async def get_report(
    investigation: LoadedInvestigation,
    user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ReportResponse:
    report = await session.scalar(
        sa.select(Report)
        .where(Report.investigation_id == investigation.id)
        .order_by(Report.generated_at.desc())
        .limit(1)
    )
    if report is None:
        raise NotFoundError(
            "no report has been generated for this investigation",
            detail={"status": investigation.status},
        )
    await audit.record(
        session,
        actor=user.username,
        action=audit.REPORT_READ,
        resource_type="report",
        resource_id=str(report.id),
        detail={"investigation_id": str(investigation.id)},
    )
    return ReportResponse.model_validate(report)


async def _chunks(file: UploadFile) -> AsyncIterator[bytes]:
    """Stream an upload without buffering it whole."""
    while chunk := await file.read(_UPLOAD_CHUNK):
        yield chunk
