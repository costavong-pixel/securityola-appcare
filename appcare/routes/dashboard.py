"""Authenticated, read-only dashboard state."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, get_session
from ..dashboard.contracts import DashboardSnapshot
from ..dashboard.service import build_dashboard_snapshot
from ..models import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/state", response_model=DashboardSnapshot)
def get_dashboard_state(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> DashboardSnapshot:
    try:
        return build_dashboard_snapshot(session, user)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "unavailable", "reason": "dashboard_state_unavailable"},
        ) from exc
