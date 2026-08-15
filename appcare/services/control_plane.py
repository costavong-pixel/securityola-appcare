"""Durable job operations and descriptive-only control-plane records."""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy.orm import Session

from ..models import Application, Job, utcnow
from .audit import sanitize_text

JOB_TRANSITIONS: dict[str, set[str]] = {
    "queued": {"running", "cancelled"},
    "running": {"succeeded", "failed", "cancelled"},
    "succeeded": set(),
    "failed": set(),
    "cancelled": set(),
}


class StateTransitionError(ValueError):
    """A requested lifecycle transition is not allowed."""


def create_job(
    session: Session,
    *,
    tenant_id: str,
    application: Application,
    kind: str,
    cost_amount: Decimal | None,
    cost_currency: str | None,
) -> Job:
    if application.tenant_id != tenant_id:
        raise ValueError("application is outside the tenant")
    if cost_amount is not None and cost_amount < 0:
        raise ValueError("cost amount cannot be negative")
    if cost_currency is not None and (len(cost_currency) != 3 or not cost_currency.isalpha()):
        raise ValueError("cost currency must be a three-letter code")
    job = Job(
        tenant_id=tenant_id,
        application_id=application.id,
        kind=kind,
        status="queued",
        retry_count=0,
        cost_amount=cost_amount,
        cost_currency=cost_currency.upper() if cost_currency else None,
        queued_at=utcnow(),
    )
    session.add(job)
    session.flush()
    return job


def transition_job(
    session: Session,
    job: Job,
    *,
    status: str,
    retry_count: int | None = None,
    failure_code: str | None = None,
    failure_message: str | None = None,
) -> Job:
    if status not in JOB_TRANSITIONS.get(job.status, set()):
        raise StateTransitionError("job status transition is not allowed")
    if retry_count is not None and retry_count < job.retry_count:
        raise StateTransitionError("job retry count cannot decrease")
    job.status = status
    if retry_count is not None:
        job.retry_count = retry_count
    if status == "running":
        job.started_at = utcnow()
    if status in {"succeeded", "failed", "cancelled"}:
        job.finished_at = utcnow()
    if failure_code is not None:
        job.failure_code = sanitize_text(failure_code, max_length=100)
    if failure_message is not None:
        job.failure_message = sanitize_text(failure_message)
    session.flush()
    return job
