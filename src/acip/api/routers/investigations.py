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
    ProvenanceChainResponse,
    ReportResponse,
    StartResponse,
    TaskCreate,
    TaskRunResponse,
    ToolRunResponse,
)
from acip.core import audit
from acip.core.evidence.store import MAX_EVIDENCE_PAGE, EvidenceStore
from acip.core.security.files import store_stream
from acip.core.security.ratelimit import investigation_limiter, rate_limit
from acip.db.models import (
    AgentRun,
    Artifact,
    Evidence,
    Finding,
    Investigation,
    ModelExecution,
    Report,
    TaskRun,
    ToolRun,
)
from acip.db.session import authorized_purge
from acip.errors import ConflictError, NotFoundError
from acip.logging import get_logger
from acip.types import (
    ArtifactKind,
    InvestigationStatus,
    RetentionState,
    TargetType,
    TaskStatus,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/investigations", tags=["investigations"])

_UPLOAD_CHUNK = 64 * 1024


@router.post(
    "",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit(investigation_limiter))],
)
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
    dependencies=[Depends(rate_limit(investigation_limiter))],
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


@router.post(
    "/{investigation_id}/start",
    response_model=StartResponse,
    dependencies=[Depends(rate_limit(investigation_limiter))],
)
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
    limit: Annotated[int, Query(ge=1, le=MAX_EVIDENCE_PAGE)] = 100,
    cursor: Annotated[
        str | None, Query(description="Opaque cursor from a previous page's next_cursor.")
    ] = None,
    kind: Annotated[str | None, Query()] = None,
) -> PagedEvidence:
    """One page of evidence in timeline order.

    Ordering and cursor handling live in :class:`~acip.core.evidence.store.EvidenceStore`
    rather than here. Two places ordering the same rows is how the sort key and the
    pagination key drift apart, which is the defect this replaced.
    """
    store = EvidenceStore(session, investigation.id)
    kinds = [kind] if kind else None
    page = await store.list_evidence(limit=limit, cursor=cursor, kinds=kinds)
    return PagedEvidence(
        items=[EvidenceResponse.model_validate(row) for row in page.rows],
        total=await store.count_evidence(kinds=kinds),
        limit=limit,
        next_cursor=page.next_cursor,
    )


@router.get(
    "/{investigation_id}/evidence/{evidence_id}/provenance",
    response_model=ProvenanceChainResponse,
)
async def get_evidence_provenance(
    investigation: LoadedInvestigation,
    evidence_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ProvenanceChainResponse:
    """Resolve one observation to the tool, arguments, agent and artifact behind it."""
    row = await session.scalar(
        sa.select(Evidence).where(
            Evidence.id == evidence_id,
            Evidence.investigation_id == investigation.id,
        )
    )
    if row is None:
        # Scoped to the investigation, so this also refuses to confirm that an id
        # belonging to another investigation exists at all (G0's read-side twin).
        raise NotFoundError(
            f"evidence {evidence_id} not found in this investigation",
            detail={"investigation_id": str(investigation.id)},
        )

    tool_run = await session.get(ToolRun, row.tool_run_id) if row.tool_run_id else None
    artifact = await session.get(Artifact, row.artifact_id) if row.artifact_id else None
    agent_run = await session.get(AgentRun, row.agent_run_id) if row.agent_run_id else None

    gaps: list[str] = []
    if tool_run is None:
        gaps.append("no tool run recorded: this observation has no deterministic origin (G1)")
    if artifact is None:
        gaps.append("no source artifact recorded: the observation cannot be traced to input bytes")
    elif artifact.retention_state != RetentionState.REPRODUCIBLE.value:
        gaps.append(
            "source bytes are no longer retained "
            f"(retention_state={artifact.retention_state}); the chain ends at derived records"
        )
    if agent_run is None:
        gaps.append("no agent run recorded: the requesting agent cannot be named")

    return ProvenanceChainResponse(
        evidence=EvidenceResponse.model_validate(row),
        tool_run=ToolRunResponse.model_validate(tool_run) if tool_run else None,
        artifact=ArtifactResponse.model_validate(artifact) if artifact else None,
        agent_run=AgentRunResponse.model_validate(agent_run) if agent_run else None,
        complete=not gaps,
        gaps=gaps,
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


async def _append_only_counts(session: AsyncSession, investigation_id: uuid.UUID) -> dict[str, int]:
    """Count the records a purge would destroy, before any of them are gone."""
    counts: dict[str, int] = {}
    for label, model in (
        ("evidence", Evidence),
        ("findings", Finding),
        ("tool_runs", ToolRun),
        ("model_executions", ModelExecution),
    ):
        total = await session.scalar(
            sa.select(sa.func.count())
            .select_from(model)
            .where(model.investigation_id == investigation_id)
        )
        counts[label] = int(total or 0)
    return counts


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_investigation(
    investigation: LoadedInvestigation,
    user: Investigator,
    session: Annotated[AsyncSession, Depends(get_session)],
    purge: Annotated[
        bool, Query(description="Required to destroy an investigation holding append-only records.")
    ] = False,
) -> None:
    """Delete an investigation; destroying append-only records requires an explicit purge.

    Evidence and model-execution rows are append-only, and their foreign keys are
    ``RESTRICT`` precisely so that deleting a parent cannot quietly take them
    with it. Destroying them is therefore a deliberate act, not a side effect:
    ``?purge=true`` is required, and the counts are captured *before* anything is
    removed so the audit row can name what was destroyed, as database.md s5
    requires. The audit row survives the purge because ``audit_log`` holds no
    foreign key to the investigation.

    An investigation holding no append-only records deletes without the flag —
    there is nothing to protect, and the 409 exists to prevent silent loss.
    """
    inv_id = investigation.id
    inv_id_str = str(inv_id)
    counts = await _append_only_counts(session, inv_id)
    destroyed = {label: count for label, count in counts.items() if count}

    if destroyed and not purge:
        raise ConflictError(
            "investigation holds append-only records; destroying them must be an explicit purge",
            detail={"records": destroyed, "retry_with": "?purge=true"},
        )

    await audit.record(
        session,
        actor=user.username,
        action="investigation.purged" if destroyed else "investigation.deleted",
        resource_type="investigation",
        resource_id=inv_id_str,
        detail={"destroyed": destroyed} if destroyed else {},
    )

    with authorized_purge():
        # RESTRICT means nothing reaches evidence by cascade any more, so the
        # append-only rows are removed explicitly and first; deleting the
        # investigation then cascades the operational records that may be
        # discarded freely.
        await session.execute(sa.delete(Evidence).where(Evidence.investigation_id == inv_id))
        await session.execute(
            sa.delete(ModelExecution).where(ModelExecution.investigation_id == inv_id)
        )
        await session.delete(investigation)
        await session.flush()

    logger.info(
        "investigation purged" if destroyed else "investigation deleted",
        extra={"investigation_id": inv_id_str, "actor": user.username, "destroyed": destroyed},
    )


async def _chunks(file: UploadFile) -> AsyncIterator[bytes]:
    """Stream an upload without buffering it whole."""
    while chunk := await file.read(_UPLOAD_CHUNK):
        yield chunk
