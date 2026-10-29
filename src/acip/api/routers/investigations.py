"""Investigation lifecycle endpoints."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any, cast

import sqlalchemy as sa
from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.engine import CursorResult
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
    EntityEdgeResponse,
    EntityResponse,
    EvidenceResponse,
    FindingResponse,
    GraphResponse,
    HypothesisDetailResponse,
    HypothesisGapResponse,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationProgress,
    InvestigationResponse,
    InvestigationSummaryResponse,
    InvestigationUpdate,
    LaymanSummary,
    ModelExecutionResponse,
    PagedEvidence,
    ProvenanceChainResponse,
    ReportResponse,
    StartResponse,
    TaskCreate,
    TaskRunResponse,
    TextArtifactIngest,
    TimelineEventResponse,
    TimelineResponse,
    ToolRunResponse,
    URLArtifactIngest,
)
from acip.core import audit
from acip.core.evidence.store import MAX_EVIDENCE_PAGE, EvidenceStore
from acip.core.graph.traversal import GraphTraversal
from acip.core.llm.contracts import ChatMessage, MessageRole
from acip.core.security.files import store_bytes, store_stream
from acip.core.security.ratelimit import investigation_limiter, rate_limit
from acip.core.security.ssrf import SafeHTTPFetcher
from acip.db.models import (
    AgentRun,
    Artifact,
    Entity,
    Evidence,
    Finding,
    Hypothesis,
    HypothesisEvidence,
    HypothesisGap,
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
    TaskClass,
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
    llm_calls = (
        await session.scalars(
            sa.select(ModelExecution)
            .where(ModelExecution.investigation_id == investigation_id)
            .order_by(ModelExecution.created_at)
        )
    ).all()
    evidence_count = await session.scalar(
        sa.select(sa.func.count())
        .select_from(Evidence)
        .where(Evidence.investigation_id == investigation_id)
    )
    hypotheses_detail = await _fetch_hypotheses_detail(session, investigation_id)

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
            "llm_calls": len(llm_calls),
            "hypotheses": len(hypotheses_detail),
        },
        llm_calls=[ModelExecutionResponse.model_validate(row) for row in llm_calls],
        hypotheses=hypotheses_detail,
    )


async def _fetch_hypotheses_detail(
    session: AsyncSession, investigation_id: uuid.UUID
) -> list[HypothesisDetailResponse]:
    hyp_stmt = (
        sa.select(Hypothesis)
        .where(Hypothesis.investigation_id == investigation_id)
        .order_by(Hypothesis.created_at)
    )
    hypotheses = list((await session.scalars(hyp_stmt)).all())
    if not hypotheses:
        return []

    hyp_ids = [h.id for h in hypotheses]
    he_stmt = sa.select(HypothesisEvidence).where(HypothesisEvidence.hypothesis_id.in_(hyp_ids))
    he_rows = list((await session.scalars(he_stmt)).all())

    gap_stmt = sa.select(HypothesisGap).where(HypothesisGap.hypothesis_id.in_(hyp_ids))
    gap_rows = list((await session.scalars(gap_stmt)).all())

    result: list[HypothesisDetailResponse] = []
    for h in hypotheses:
        supp_ids = [
            str(he.evidence_id)
            for he in he_rows
            if he.hypothesis_id == h.id and he.role == "supports"
        ]
        contra_ids = [
            str(he.evidence_id)
            for he in he_rows
            if he.hypothesis_id == h.id and he.role == "contradicts"
        ]
        gaps = [
            HypothesisGapResponse.model_validate(g) for g in gap_rows if g.hypothesis_id == h.id
        ]
        result.append(
            HypothesisDetailResponse(
                id=h.id,
                display_id=h.display_id,
                investigation_id=h.investigation_id,
                statement=h.statement,
                status=h.status_enum,
                confidence=h.confidence,
                refutation_condition=h.refutation_condition,
                agent_run_id=h.agent_run_id,
                supporting_evidence_ids=supp_ids,
                contradicting_evidence_ids=contra_ids,
                gaps=gaps,
                created_at=h.created_at,
            )
        )
    return result


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
    """Accept an artifact into content-addressed quarantine storage with magic byte inspection."""
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
            declared_kind=kind,
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
        kind=stored.detected_kind.value if kind is ArtifactKind.UNKNOWN else kind.value,
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
            "detected_kind": stored.detected_kind.value,
        },
    )
    return ArtifactResponse.model_validate(artifact)


@router.post(
    "/{investigation_id}/artifacts/url",
    response_model=ArtifactResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit(investigation_limiter))],
)
async def ingest_url_artifact(
    investigation: LoadedInvestigation,
    payload: URLArtifactIngest,
    user: Investigator,
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ArtifactResponse:
    """Ingest content from a remote URL via SSRF-protected safe HTTP fetch."""
    if investigation.status_enum is not InvestigationStatus.CREATED:
        raise ConflictError(
            "artifacts can only be added before the investigation starts",
            detail={"status": investigation.status},
        )

    settings = services.settings
    fetcher = SafeHTTPFetcher(
        max_bytes=settings.max_artifact_bytes,
        max_redirects=3,
        timeout_seconds=10.0,
    )
    try:
        fetch_res = await fetcher.fetch_url(payload.url)
        stored = await store_bytes(
            fetch_res.content,
            dest_dir=settings.artifact_dir,
            max_bytes=settings.max_artifact_bytes,
            original_filename=f"url_response_{fetch_res.sha256[:8]}.bin",
            declared_kind=payload.declared_kind,
        )
    except Exception as exc:
        await audit.record(
            session,
            actor=user.username,
            action=audit.ARTIFACT_REJECTED,
            resource_type="investigation",
            resource_id=str(investigation.id),
            outcome=audit.FAILURE,
            detail={"url": payload.url, "reason": f"{type(exc).__name__}: {exc}"},
        )
        raise

    artifact = Artifact(
        investigation_id=investigation.id,
        kind=payload.declared_kind.value,
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
            "source_url": payload.url,
            "declared_kind": payload.declared_kind.value,
        },
    )
    return ArtifactResponse.model_validate(artifact)


@router.post(
    "/{investigation_id}/artifacts/text",
    response_model=ArtifactResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit(investigation_limiter))],
)
async def ingest_text_artifact(
    investigation: LoadedInvestigation,
    payload: TextArtifactIngest,
    user: Investigator,
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ArtifactResponse:
    """Ingest raw text/log/indicator directly into quarantine storage."""
    if investigation.status_enum is not InvestigationStatus.CREATED:
        raise ConflictError(
            "artifacts can only be added before the investigation starts",
            detail={"status": investigation.status},
        )

    settings = services.settings
    content_bytes = payload.content.encode("utf-8")
    try:
        stored = await store_bytes(
            content_bytes,
            dest_dir=settings.artifact_dir,
            max_bytes=settings.max_artifact_bytes,
            original_filename=payload.filename or "pasted_artifact.txt",
            declared_kind=payload.declared_kind,
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
        kind=payload.declared_kind.value,
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
            "declared_kind": payload.declared_kind.value,
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
    # Do not turn the loaded object's status into a claim: two requests can
    # both have loaded CREATED before either one commits.  The status predicate
    # makes the database elect exactly one starter, including on SQLite where
    # there is no row-level ``SELECT FOR UPDATE`` to rely on.
    claim = cast(
        CursorResult[Any],
        await session.execute(
            sa.update(Investigation)
            .where(
                Investigation.id == investigation.id,
                Investigation.status == InvestigationStatus.CREATED.value,
            )
            .values(status=InvestigationStatus.RUNNING.value)
        ),
    )
    if claim.rowcount != 1:
        await session.refresh(investigation)
        raise ConflictError(
            f"investigation is already {investigation.status}",
            detail={"status": investigation.status},
        )
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

    claim = cast(
        CursorResult[Any],
        await session.execute(
            sa.update(Investigation)
            .where(
                Investigation.id == investigation.id,
                Investigation.status.in_(
                    [
                        InvestigationStatus.FAILED.value,
                        InvestigationStatus.HALTED.value,
                        InvestigationStatus.PARTIAL.value,
                    ]
                ),
            )
            .values(status=InvestigationStatus.RUNNING.value, error=None)
        ),
    )
    if claim.rowcount != 1:
        await session.refresh(investigation)
        raise ConflictError(
            "only failed, partial, or halted investigations can be retried; "
            f"current status is {investigation.status}",
            detail={"status": investigation.status},
        )
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


@router.post("/{investigation_id}/summarize", response_model=InvestigationSummaryResponse)
async def summarize_investigation(
    investigation: LoadedInvestigation,
    user: CurrentUser,
    services: Annotated[Services, Depends(get_services)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> InvestigationSummaryResponse:
    """Generate an executive plain-English layman summary using NVIDIA Nemotron 3 Ultra 550B."""
    # 1. Fetch findings
    findings = list(
        (
            await session.scalars(
                sa.select(Finding)
                .where(Finding.investigation_id == investigation.id)
                .order_by(Finding.severity.desc())
            )
        ).all()
    )

    # 2. Fetch latest report (if available)
    report = await session.scalar(
        sa.select(Report)
        .where(Report.investigation_id == investigation.id)
        .order_by(Report.generated_at.desc())
        .limit(1)
    )

    # 3. Fetch hypotheses (if available)
    hypotheses = list(
        (
            await session.scalars(
                sa.select(Hypothesis).where(Hypothesis.investigation_id == investigation.id)
            )
        ).all()
    )

    findings_summary = (
        "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.description} "
            f"(Confidence: {int(f.confidence * 100)}%)"
            for f in findings
        )
        if findings
        else "No grounded security findings recorded."
    )

    hypotheses_summary = (
        "\n".join(f"- {h.statement} (Status: {h.status})" for h in hypotheses)
        if hypotheses
        else "No competing hypotheses formulated."
    )

    risk_display = investigation.risk_score if investigation.risk_score is not None else 0
    report_excerpt = report.content[:2000] if report else "No report generated yet."

    prompt = (
        f"Investigation Title: {investigation.title}\n"
        f"Target Type: {investigation.target_type}\n"
        f"Target Value: {investigation.target_value}\n"
        f"Status: {investigation.status}\n"
        f"Severity: {investigation.severity or 'info'}\n"
        f"Blended Risk Score: {risk_display} / 100\n\n"
        f"Grounded Findings:\n{findings_summary}\n\n"
        f"Hypotheses Evaluated:\n{hypotheses_summary}\n\n"
        f"Report Context:\n{report_excerpt}\n\n"
        "Generate a clear, objective executive summary in layman terms using "
        "NVIDIA Nemotron 3 Ultra 550B. Explain what happened chronologically, "
        "what was found without dense jargon, the definitive conclusion on "
        "whether systems are compromised, and recommended practical next steps."
    )

    summary_model_name = getattr(
        services.settings, "model_nemotron_summary", "nvidia/nemotron-3-ultra-550b"
    )

    router = services.router
    if router is None:
        from acip.core.llm.router import build_default_router

        router = build_default_router(services.settings)
        services.router = router

    parsed_summary, response = await router.complete(
        TaskClass.NARRATIVE,
        messages=[
            ChatMessage(
                role=MessageRole.SYSTEM,
                content=(
                    f"You are {summary_model_name}, an expert cybersecurity AI advisor. "
                    "Your mission is to summarize technical incidents and investigations into "
                    "plain English for non-technical leadership and executives. Be clear and calm."
                ),
            ),
            ChatMessage(role=MessageRole.USER, content=prompt),
        ],
        schema=LaymanSummary,
        investigation_id=investigation.id,
        prompt_name="layman_summary",
        prompt_version="v1",
        session=session,
    )

    if parsed_summary is None:
        what_happened_fallback = (
            response.content.strip()
            if response and response.content.strip()
            else "Investigation concluded with collected telemetry."
        )
        parsed_summary = LaymanSummary(
            headline=f"Executive Summary for {investigation.title}",
            what_happened=what_happened_fallback,
            key_findings=[f.title for f in findings] or ["Evaluation completed."],
            conclusion=(
                f"Overall status is {investigation.status} with risk score "
                f"{investigation.risk_score or 0}/100."
            ),
            recommended_actions=["Review system access logs and maintain regular monitoring."],
        )

    findings_md = "\n".join(f"- {kf}" for kf in parsed_summary.key_findings)
    actions_md = "\n".join(f"- {ra}" for ra in parsed_summary.recommended_actions)
    markdown_content = (
        f"# Executive Incident Summary\n\n"
        f"**Model Attribution:** `{summary_model_name}`  \n"
        f"**Target:** `{investigation.target_value}` ({investigation.target_type})  \n"
        f"**Risk Assessment:** {investigation.risk_score or 0} / 100 "
        f"({investigation.severity or 'info'})\n\n"
        f"## {parsed_summary.headline}\n\n"
        f"### What Happened\n{parsed_summary.what_happened}\n\n"
        f"### Key Findings\n{findings_md}\n\n"
        f"### Conclusion\n{parsed_summary.conclusion}\n\n"
        f"### Recommended Actions\n{actions_md}\n"
    )

    await audit.record(
        session,
        actor=user.username,
        action="investigation.summarized",
        resource_type="investigation",
        resource_id=str(investigation.id),
        detail={"model": summary_model_name},
    )

    tokens = response.usage.total_tokens if response and response.usage else 0

    return InvestigationSummaryResponse(
        investigation_id=investigation.id,
        model=summary_model_name,
        summary=parsed_summary,
        markdown=markdown_content,
        tokens_used=tokens,
    )


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


# --- Evidence Graph & Timeline Endpoints ------------------------------------


@router.get("/{investigation_id}/graph", response_model=GraphResponse)
async def get_investigation_graph(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
    entity: Annotated[
        uuid.UUID | None,
        Query(description="Optional entity node ID to root bounded traversal"),
    ] = None,
    depth: Annotated[int, Query(ge=1, le=6, description="Traversal hop limit (default 2)")] = 2,
    limit: Annotated[int, Query(ge=1, le=1000, description="Max edge/entity result cap")] = 250,
) -> GraphResponse:
    """Fetch the evidence graph for this investigation.

    If entity is provided, returns depth-bounded neighborhood traversal around that entity.
    Otherwise returns the bounded investigation evidence graph.
    """
    traversal = GraphTraversal(session, investigation.id)
    if entity is not None:
        subgraph = await traversal.neighbours(entity, max_depth=depth, limit=limit)
    else:
        subgraph = await traversal.get_full_graph(limit=limit)

    return GraphResponse(
        investigation_id=subgraph.investigation_id,
        entities=[EntityResponse.model_validate(e) for e in subgraph.entities],
        edges=[EntityEdgeResponse.model_validate(e) for e in subgraph.edges],
        truncated=subgraph.truncated,
    )


@router.get("/{investigation_id}/entities", response_model=list[EntityResponse])
async def list_investigation_entities(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
    type: Annotated[str | None, Query(description="Filter by EntityType")] = None,
    q: Annotated[
        str | None, Query(description="Substring search over normalized or raw value")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[EntityResponse]:
    """List canonical resolved entities in this investigation."""
    stmt = sa.select(Entity).where(Entity.investigation_id == investigation.id)
    if type:
        stmt = stmt.where(Entity.type == type)
    if q:
        query_pat = f"%{q.strip().lower()}%"
        stmt = stmt.where(
            sa.or_(
                Entity.value_normalized.ilike(query_pat),
                Entity.value_raw_first_seen.ilike(query_pat),
            )
        )
    stmt = stmt.order_by(Entity.observation_count.desc(), Entity.created_at.asc()).limit(limit)
    rows = (await session.scalars(stmt)).all()
    return [EntityResponse.model_validate(r) for r in rows]


@router.get("/{investigation_id}/timeline", response_model=TimelineResponse)
async def get_investigation_timeline(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> TimelineResponse:
    """Chronologically ordered event timeline over stored evidence."""
    traversal = GraphTraversal(session, investigation.id)
    events = await traversal.timeline(limit=limit)
    return TimelineResponse(
        investigation_id=investigation.id,
        events=[
            TimelineEventResponse(
                evidence_id=ev.evidence_id,
                observed_at=ev.observed_at,
                source_tool=ev.source_tool,
                kind=ev.kind,
                time_confidence=ev.time_confidence,
                summary=ev.summary,
                entities=ev.entities,
            )
            for ev in events
        ],
        total=len(events),
    )


@router.get(
    "/{investigation_id}/findings/{finding_id}/subgraph",
    response_model=GraphResponse,
)
async def get_finding_subgraph(
    investigation: LoadedInvestigation,
    finding_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 250,
) -> GraphResponse:
    """Extract the evidence subgraph supporting a specific finding."""
    finding = await session.scalar(
        sa.select(Finding).where(
            Finding.id == finding_id,
            Finding.investigation_id == investigation.id,
        )
    )
    if finding is None:
        raise NotFoundError(
            f"finding {finding_id} not found in this investigation",
            detail={"investigation_id": str(investigation.id)},
        )

    traversal = GraphTraversal(session, investigation.id)
    subgraph = await traversal.subgraph_for_finding(finding_id, limit=limit)
    return GraphResponse(
        investigation_id=subgraph.investigation_id,
        entities=[EntityResponse.model_validate(e) for e in subgraph.entities],
        edges=[EntityEdgeResponse.model_validate(e) for e in subgraph.edges],
        truncated=subgraph.truncated,
    )


@router.get(
    "/{investigation_id}/hypotheses",
    response_model=list[HypothesisDetailResponse],
)
async def list_investigation_hypotheses(
    investigation: LoadedInvestigation,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[HypothesisDetailResponse]:
    """List competing hypotheses, refutation conditions, and gaps."""
    return await _fetch_hypotheses_detail(session, investigation.id)


@router.get("/{investigation_id}/events")
async def stream_investigation_events(
    investigation: LoadedInvestigation,
    services: Annotated[Services, Depends(get_services)],
) -> StreamingResponse:
    """Server-Sent Events (SSE) stream for real-time investigation progress."""
    inv_id = investigation.id

    async def event_generator() -> AsyncIterator[str]:
        # Send initial connection handshake
        init_payload = {"type": "connected", "investigation_id": str(inv_id)}
        yield f"data: {json.dumps(init_payload)}\n\n"
        last_status = None
        last_task = None
        consecutive_terminal_checks = 0

        while True:
            await asyncio.sleep(1.0)
            async with services.database.session() as s:
                inv = await s.scalar(sa.select(Investigation).where(Investigation.id == inv_id))
                if inv is None:
                    yield f"data: {json.dumps({'type': 'error', 'message': 'not found'})}\n\n"
                    break

                tasks = list(
                    (
                        await s.scalars(
                            sa.select(TaskRun).where(TaskRun.investigation_id == inv_id)
                        )
                    ).all()
                )
                running_task = next(
                    (t.task_type for t in tasks if t.status == TaskStatus.RUNNING.value),
                    None,
                )

                if inv.status != last_status or running_task != last_task:
                    last_status = inv.status
                    last_task = running_task
                    completed = sum(1 for t in tasks if t.status == TaskStatus.SUCCEEDED.value)
                    total = len(tasks)
                    percent = (
                        (completed / total * 100.0)
                        if total > 0
                        else (100.0 if inv.status_enum.terminal else 0.0)
                    )
                    payload = {
                        "type": "progress",
                        "status": inv.status,
                        "running_task": running_task,
                        "completed_tasks": completed,
                        "total_tasks": total,
                        "percent_complete": round(percent, 2),
                    }
                    yield f"data: {json.dumps(payload)}\n\n"

                if inv.status_enum.terminal:
                    consecutive_terminal_checks += 1
                    if consecutive_terminal_checks >= 2:
                        done_payload = {"type": "done", "status": inv.status}
                        yield f"data: {json.dumps(done_payload)}\n\n"
                        break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _chunks(file: UploadFile) -> AsyncIterator[bytes]:
    """Stream an upload without buffering it whole."""
    while chunk := await file.read(_UPLOAD_CHUNK):
        yield chunk
