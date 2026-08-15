"""Unauthenticated process and isolated-database health checks."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..auth.dependencies import get_database
from ..db import Database

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready(request: Request, database: Database = Depends(get_database)) -> dict[str, str]:
    if not database.ready():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "not_ready"},
        )
    return {"status": "ready", "environment": request.app.state.settings.environment}
