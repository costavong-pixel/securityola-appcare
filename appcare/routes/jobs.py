"""Durable, state-validated job endpoints with no external execution."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, get_session
from ..models import Job, User
from ..repositories.tenant_scope import get_owned, list_owned
from ..services.audit import MetadataError
from ..services.control_plane import StateTransitionError, create_job, transition_job
from .common import invalid_input, not_found, owned_application
from .resources import _record
from .schemas import JobCreate, JobPatch, JobResponse

router = APIRouter(prefix="/v1", tags=["jobs"])


@router.get("/jobs", response_model=list[JobResponse])
def list_jobs(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[JobResponse]:
    return [
        JobResponse.model_validate(item)
        for item in list_owned(session, Job, user.tenant_id, limit=min(limit, 100))
    ]


@router.post("/jobs", response_model=JobResponse, status_code=201)
def create_control_plane_job(
    body: JobCreate,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> JobResponse:
    application = owned_application(session, user, body.application_id)
    try:
        job = create_job(
            session,
            tenant_id=user.tenant_id,
            application=application,
            kind=body.kind,
            cost_amount=body.cost_amount,
            cost_currency=body.cost_currency,
        )
    except ValueError as exc:
        raise invalid_input() from exc
    _record(
        session,
        user,
        action="job.create",
        subject_type="job",
        subject_id=job.id,
        metadata={"kind": body.kind},
    )
    return JobResponse.model_validate(job)


@router.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(
    job_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> JobResponse:
    job = get_owned(session, Job, user.tenant_id, job_id)
    if job is None:
        raise not_found()
    return JobResponse.model_validate(job)


@router.patch("/jobs/{job_id}", response_model=JobResponse)
def patch_job(
    job_id: str,
    body: JobPatch,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> JobResponse:
    job = get_owned(session, Job, user.tenant_id, job_id)
    if job is None:
        raise not_found()
    try:
        transition_job(
            session,
            job,
            status=body.status,
            retry_count=body.retry_count,
            failure_code=body.failure_code,
            failure_message=body.failure_message,
        )
    except (StateTransitionError, MetadataError) as exc:
        raise invalid_input() from exc
    _record(
        session,
        user,
        action="job.update",
        subject_type="job",
        subject_id=job.id,
        metadata={"status": body.status},
    )
    return JobResponse.model_validate(job)
