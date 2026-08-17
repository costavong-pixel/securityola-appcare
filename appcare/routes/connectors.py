"""Tenant-scoped health checks and local inventory for read-only connectors."""

from __future__ import annotations

from typing import Literal, cast

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, get_session
from ..connectors import ConnectorRegistry
from ..models import Connector, User
from ..repositories.tenant_scope import get_owned
from ..services.connectors import check_connector, inventory_connector
from .common import invalid_input, not_found
from .resources import _record
from .schemas import (
    AssetResponse,
    ConnectorCheckResponse,
    InventoryRequest,
    InventoryResponse,
)

router = APIRouter(prefix="/v1", tags=["connectors"])


def _registry(request: Request) -> ConnectorRegistry:
    registry = getattr(request.app.state, "connector_registry", None)
    if not isinstance(registry, ConnectorRegistry):
        raise RuntimeError("AppCare connector registry is not initialized")
    return registry


@router.post(
    "/connectors/{connector_id}/check",
    response_model=ConnectorCheckResponse,
)
def check_connector_endpoint(
    connector_id: str,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ConnectorCheckResponse:
    connector = get_owned(session, Connector, user.tenant_id, connector_id)
    if connector is None:
        raise not_found()
    try:
        summary = check_connector(
            session,
            tenant_id=user.tenant_id,
            connector=connector,
            registry=_registry(request),
        )
    except ValueError as exc:
        raise invalid_input() from exc
    _record(
        session,
        user,
        action="connector.check",
        subject_type="connector",
        subject_id=connector.id,
        metadata={
            "overall_status": summary.overall_status,
            "reason_codes": list(summary.reason_codes),
        },
    )
    return ConnectorCheckResponse(
        connector_id=connector.id,
        overall_status=summary.overall_status,
        health_status=summary.health_status,
        permission_status=summary.permission_status,
        ownership_status=summary.ownership_status,
        reason_codes=list(summary.reason_codes),
        checked_at=summary.checked_at,
    )


@router.post(
    "/connectors/{connector_id}/inventory",
    response_model=InventoryResponse,
    status_code=status.HTTP_200_OK,
)
def inventory_connector_endpoint(
    connector_id: str,
    body: InventoryRequest,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> InventoryResponse:
    connector = get_owned(session, Connector, user.tenant_id, connector_id)
    if connector is None:
        raise not_found()
    try:
        summary = inventory_connector(
            session,
            tenant_id=user.tenant_id,
            connector=connector,
            registry=_registry(request),
            snapshot_key=body.snapshot_key,
            actor_user_id=user.id,
        )
    except ValueError as exc:
        raise invalid_input() from exc
    return InventoryResponse(
        connector_id=connector.id,
        snapshot_key=summary.run.snapshot_key,
        status=cast(Literal["running", "succeeded", "failed"], summary.run.status),
        asset_count=summary.run.asset_count,
        failure_code=summary.run.failure_code,
        started_at=summary.run.started_at,
        finished_at=summary.run.finished_at,
        assets=[AssetResponse.model_validate(asset) for asset in summary.assets],
    )
