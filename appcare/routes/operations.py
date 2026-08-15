"""Descriptive connector, backup, approval, and deployment records."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, get_session
from ..models import Approval, Backup, Connector, Deployment, User, utcnow
from ..repositories.tenant_scope import get_owned, list_owned
from ..services.audit import MetadataError, sanitize_text
from ..services.connectors import ConnectorRegistration, connector_credential, register_connector
from .common import invalid_input, not_found, owned_application, safe_reference
from .resources import _record
from .schemas import (
    ApprovalCreate,
    ApprovalResponse,
    BackupCreate,
    BackupResponse,
    ConnectorCreate,
    ConnectorResponse,
    DeploymentCreate,
    DeploymentResponse,
)

router = APIRouter(prefix="/v1", tags=["operations"])


def _limit(value: int) -> int:
    return min(value, 100)


def _connector_response(session: Session, connector: Connector) -> ConnectorResponse:
    credential = connector_credential(
        session, tenant_id=connector.tenant_id, connector_id=connector.id
    )
    return ConnectorResponse(
        id=connector.id,
        tenant_id=connector.tenant_id,
        application_id=connector.application_id,
        provider=connector.provider,
        kind=connector.kind,
        status=connector.status,
        display_name=connector.display_name,
        resource_reference=connector.resource_reference,
        owner_reference=connector.owner_reference,
        scopes=list(connector.scope_json),
        credential_reference=credential.reference if credential else None,
        credential_authority=credential.authority if credential else None,
        credential_status=credential.status if credential else None,
        credential_expires_at=credential.expires_at if credential else None,
        health_status=connector.health_status,
        permission_status=connector.permission_status,
        ownership_status=connector.ownership_status,
        last_checked_at=connector.last_checked_at,
        created_at=connector.created_at,
        updated_at=connector.updated_at,
    )


@router.get("/connectors", response_model=list[ConnectorResponse])
def list_connectors(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[ConnectorResponse]:
    return [
        _connector_response(session, item)
        for item in list_owned(session, Connector, user.tenant_id, limit=_limit(limit))
    ]


@router.post("/connectors", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED)
def create_connector(
    body: ConnectorCreate,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ConnectorResponse:
    application = owned_application(session, user, body.application_id)
    try:
        connector = register_connector(
            session,
            tenant_id=user.tenant_id,
            application=application,
            registration=ConnectorRegistration(
                application_id=body.application_id,
                provider=body.provider,
                kind=body.kind,
                display_name=body.display_name,
                resource_reference=body.resource_reference,
                owner_reference=body.owner_reference,
                scopes=tuple(body.scopes),
                credential_reference=body.credential_reference,
                credential_authority=body.credential_authority,
                credential_expires_at=body.credential_expires_at,
                credential_status=body.credential_status,
                credential_fingerprint=body.credential_fingerprint,
            ),
        )
    except ValueError as exc:
        raise invalid_input() from exc
    _record(
        session,
        user,
        action="connector.create",
        subject_type="connector",
        subject_id=connector.id,
        metadata={"provider": body.provider, "kind": body.kind},
    )
    return _connector_response(session, connector)


@router.get("/connectors/{connector_id}", response_model=ConnectorResponse)
def get_connector(
    connector_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ConnectorResponse:
    connector = get_owned(session, Connector, user.tenant_id, connector_id)
    if connector is None:
        raise not_found()
    return _connector_response(session, connector)


@router.get("/backups", response_model=list[BackupResponse])
def list_backups(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[BackupResponse]:
    return [
        BackupResponse.model_validate(item)
        for item in list_owned(session, Backup, user.tenant_id, limit=_limit(limit))
    ]


@router.post("/backups", response_model=BackupResponse, status_code=status.HTTP_201_CREATED)
def create_backup(
    body: BackupCreate,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> BackupResponse:
    owned_application(session, user, body.application_id)
    if body.artifact_reference is not None and not safe_reference(body.artifact_reference):
        raise invalid_input()
    backup = Backup(
        tenant_id=user.tenant_id,
        application_id=body.application_id,
        status="requested",
        provider=body.provider,
        artifact_reference=body.artifact_reference,
    )
    session.add(backup)
    session.flush()
    _record(
        session,
        user,
        action="backup.create",
        subject_type="backup",
        subject_id=backup.id,
        metadata={"provider": body.provider},
    )
    return BackupResponse.model_validate(backup)


@router.get("/backups/{backup_id}", response_model=BackupResponse)
def get_backup(
    backup_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> BackupResponse:
    backup = get_owned(session, Backup, user.tenant_id, backup_id)
    if backup is None:
        raise not_found()
    return BackupResponse.model_validate(backup)


@router.get("/approvals", response_model=list[ApprovalResponse])
def list_approvals(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[ApprovalResponse]:
    return [
        ApprovalResponse.model_validate(item)
        for item in list_owned(session, Approval, user.tenant_id, limit=_limit(limit))
    ]


@router.post("/approvals", response_model=ApprovalResponse, status_code=status.HTTP_201_CREATED)
def create_approval(
    body: ApprovalCreate,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ApprovalResponse:
    owned_application(session, user, body.application_id)
    approval = Approval(
        tenant_id=user.tenant_id,
        application_id=body.application_id,
        kind=body.kind,
        status="requested",
        requested_by=user.id,
        requested_at=utcnow(),
    )
    session.add(approval)
    session.flush()
    _record(
        session,
        user,
        action="approval.create",
        subject_type="approval",
        subject_id=approval.id,
        metadata={"kind": body.kind},
    )
    return ApprovalResponse.model_validate(approval)


@router.get("/approvals/{approval_id}", response_model=ApprovalResponse)
def get_approval(
    approval_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ApprovalResponse:
    approval = get_owned(session, Approval, user.tenant_id, approval_id)
    if approval is None:
        raise not_found()
    return ApprovalResponse.model_validate(approval)


@router.get("/deployments", response_model=list[DeploymentResponse])
def list_deployments(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[DeploymentResponse]:
    return [
        DeploymentResponse.model_validate(item)
        for item in list_owned(session, Deployment, user.tenant_id, limit=_limit(limit))
    ]


@router.post("/deployments", response_model=DeploymentResponse, status_code=status.HTTP_201_CREATED)
def create_deployment(
    body: DeploymentCreate,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> DeploymentResponse:
    owned_application(session, user, body.application_id)
    try:
        revision = sanitize_text(body.revision, max_length=200)
    except MetadataError as exc:
        raise invalid_input() from exc
    deployment = Deployment(
        tenant_id=user.tenant_id,
        application_id=body.application_id,
        environment=body.environment,
        status="requested",
        requested_by=user.id,
        revision=revision or body.revision,
    )
    session.add(deployment)
    session.flush()
    _record(
        session,
        user,
        action="deployment.create",
        subject_type="deployment",
        subject_id=deployment.id,
        metadata={"environment": body.environment},
    )
    return DeploymentResponse.model_validate(deployment)


@router.get("/deployments/{deployment_id}", response_model=DeploymentResponse)
def get_deployment(
    deployment_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> DeploymentResponse:
    deployment = get_owned(session, Deployment, user.tenant_id, deployment_id)
    if deployment is None:
        raise not_found()
    return DeploymentResponse.model_validate(deployment)
