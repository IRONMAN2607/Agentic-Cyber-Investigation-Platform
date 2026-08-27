"""Investigation lifecycle endpoints."""

from __future__ import annotations

import datetime as dt
import uuid
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
    InvestigationProgress,
    InvestigationResponse,
    InvestigationUpdate,
    PagedEvidence,
    ReportResponse,
    StartResponse,
    TaskCreate,
    TaskRunResponse,
    ToolRunResponse,
)
from acip.core import audit
from acip.core.security.files import store_stream
from acip.db.models import (
    AgentRun,
    Artifact,
    Evidence,
    Finding,
    Investigation,
    Report,
    TaskRun,
    ToolRun,
)
from acip.errors import ConflictError, NotFoundError
from acip.logging import get_logger
from acip.types import ArtifactKind, InvestigationStatus, TargetType, TaskStatus

logger = get_logger(__name__)
router = APIRouter(prefix="/investigations", tags=["investigations"])

_UPLOAD_CHUNK = 64 * 1024


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCreate,
    user: Investigator,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationResponse:
    """Create a new investigation in CREATED state."""
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
    status_filter: Annotated[InvestigationStatus | None, Query(alias="status")] = None,
    target_type: Annotated[TargetType | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[InvestigationResponse]:
    """List investigations with optional status and target_type filtering."""
    stmt = sa.select(Investigation).order_by(Investigation.created_at.desc())
    if status_filter:
        stmt = stmt.where(Investigation.status == status_filter.value)
    if target_type:
        stmt = stmt.where(Investigation.target_type == target_type.value)

    rows = await session.scalars(stmt.limit(limit).offset(offset))
    return [InvestigationResponse.model_validate(row) for row in rows.all()]


@router.get("/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation_detail(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationDetail:
    """Everything a workspace view needs, in one round trip."""
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


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    investigation: LoadedInvestigation,
    payload: InvestigationUpdate,
    user: Investigator,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationResponse:
    """Update investigation metadata (title, target_value, retention_state)."""
    if payload.title is not None:
        investigation.title = payload.title
    if payload.target_value is not None:
        investigation.target_value = payload.target_value
    if payload.retention_state is not None:
        investigation.retention_state = payload.retention_state.value

    await session.flush()
    await audit.record(
        session,
        actor=user.username,
        action="investigation.updated",
        resource_type="investigation",
        resource_id=str(investigation.id),
        detail=payload.model_dump(exclude_unset=True),
    )
    return InvestigationResponse.model_validate(investigation)


@router.get("/{investigation_id}/progress", response_model=InvestigationProgress)
async def get_investigation_progress(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationProgress:
    """Compute real-time progress metrics for the investigation."""
    tasks = list(
        (
            await session.scalars(
                sa.select(TaskRun).where(TaskRun.investigation_id == investigation.id)
            )
        ).all()
    )
    total_tasks = len(tasks)
    completed_tasks = sum(1 for t in tasks if t.status == TaskStatus.SUCCEEDED.value)
    failed_tasks = sum(
        1 for t in tasks if t.status in {TaskStatus.FAILED.value, TaskStatus.CANCELLED.value}
    )
    running_task = next((t.task_type for t in tasks if t.status == TaskStatus.RUNNING.value), None)

    percent = (
        (completed_tasks / total_tasks * 100.0)
        if total_tasks > 0
        else (100.0 if investigation.status_enum.terminal else 0.0)
    )

    return InvestigationProgress(
        investigation_id=investigation.id,
        status=investigation.status_enum,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        failed_tasks=failed_tasks,
        running_task=running_task,
        percent_complete=round(percent, 2),
    )


@router.get("/{investigation_id}/tasks", response_model=list[TaskRunResponse])
async def list_tasks(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[TaskRunResponse]:
    """List all scheduled and executed tasks in the investigation plan."""
    tasks = await session.scalars(
        sa.select(TaskRun)
        .where(TaskRun.investigation_id == investigation.id)
        .order_by(TaskRun.started_at)
    )
    return [TaskRunResponse.model_validate(t) for t in tasks.all()]


@router.post(
    "/{investigation_id}/tasks", response_model=TaskRunResponse, status_code=status.HTTP_201_CREATED
)
async def create_task(
    investigation: LoadedInvestigation,
    payload: TaskCreate,
    user: Investigator,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> TaskRunResponse:
    """Manually append a task to the investigation."""
    task_id = f"task-manual-{uuid.uuid4().hex[:8]}"
    task = TaskRun(
        investigation_id=investigation.id,
        task_id=task_id,
        task_type=payload.task_type,
        status=TaskStatus.PENDING.value,
        rationale=payload.rationale,
        inputs=payload.inputs,
    )
    session.add(task)
    await session.flush()

    await audit.record(
        session,
        actor=user.username,
        action="task.created",
        resource_type="task",
        resource_id=task_id,
        detail={"investigation_id": str(investigation.id), "task_type": payload.task_type},
    )
    return TaskRunResponse.model_validate(task)


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
    """Accept an artifact into content-addressed quarantine storage."""
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
    """Queue the investigation for execution."""
    if investigation.status_enum is not InvestigationStatus.CREATED:
        raise ConflictError(
            f"investigation is already {investigation.status}",
            detail={"status": investigation.status},
        )

    investigation.status = InvestigationStatus.RUNNING.value
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


@router.post("/{investigation_id}/cancel", response_model=InvestigationResponse)
async def cancel_investigation(
    investigation: LoadedInvestigation,
    user: Investigator,
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationResponse:
    """Cancel / Halt an in-progress or queued investigation."""
    if investigation.status_enum.terminal:
        raise ConflictError(
            f"cannot cancel investigation with terminal status: {investigation.status}",
            detail={"status": investigation.status},
        )

    cancelled = await services.runner.cancel(investigation.id)
    if not cancelled:
        investigation.status = InvestigationStatus.HALTED.value
        investigation.completed_at = dt.datetime.now(dt.UTC)
        investigation.error = "investigation cancelled by user"
        await session.flush()

    await audit.record(
        session,
        actor=user.username,
        action="investigation.cancelled",
        resource_type="investigation",
        resource_id=str(investigation.id),
    )
    return InvestigationResponse.model_validate(investigation)


@router.post("/{investigation_id}/retry", response_model=StartResponse)
async def retry_investigation(
    investigation: LoadedInvestigation,
    user: Investigator,
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> StartResponse:
    """Retry an investigation that failed, halted, or was interrupted."""
    if investigation.status_enum not in {
        InvestigationStatus.FAILED,
        InvestigationStatus.HALTED,
        InvestigationStatus.PARTIAL,
    }:
        raise ConflictError(
            "only failed, partial, or halted investigations can be retried; "
            f"current status is {investigation.status}",
            detail={"status": investigation.status},
        )

    investigation.status = InvestigationStatus.RUNNING.value
    investigation.error = None
    await session.commit()

    services.runner.submit(investigation.id)
    await audit.record(
        session,
        actor=user.username,
        action="investigation.retried",
        resource_type="investigation",
        resource_id=str(investigation.id),
    )
    return StartResponse(
        investigation_id=investigation.id,
        status=InvestigationStatus.RUNNING,
        accepted=True,
        message="Investigation re-queued for execution.",
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


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_investigation(
    investigation: LoadedInvestigation,
    user: Investigator,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete an investigation and cascade its operational records."""
    inv_id_str = str(investigation.id)
    await session.delete(investigation)
    await session.flush()

    await audit.record(
        session,
        actor=user.username,
        action="investigation.deleted",
        resource_type="investigation",
        resource_id=inv_id_str,
    )


async def _chunks(file: UploadFile) -> AsyncIterator[bytes]:
    """Stream an upload without buffering it whole."""
    while chunk := await file.read(_UPLOAD_CHUNK):
        yield chunk
