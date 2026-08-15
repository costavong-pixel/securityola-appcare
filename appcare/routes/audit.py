"""Read-only, tenant-scoped audit history."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, get_session
from ..models import AuditEvent, User
from .schemas import AuditEventResponse

router = APIRouter(prefix="/v1", tags=["audit"])


@router.get("/audit-events", response_model=list[AuditEventResponse])
def list_audit_events(
    limit: int = Query(default=100, ge=1, le=100),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[AuditEventResponse]:
    statement = (
        select(AuditEvent)
        .where(AuditEvent.tenant_id == user.tenant_id)
        .order_by(desc(AuditEvent.occurred_at), desc(AuditEvent.id))
        .limit(limit)
    )
    return [AuditEventResponse.model_validate(item) for item in session.scalars(statement).all()]
