"""Tenant-scoped resources and descriptive-only operation records."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, get_session
from ..models import (
    Application,
    Asset,
    Finding,
    User,
)
from ..repositories.tenant_scope import get_owned, list_owned
from ..services.audit import MetadataError, append_event, sanitize_text
from .common import invalid_input, not_found, owned_application, safe_reference
from .schemas import (
    ApplicationCreate,
    ApplicationPatch,
    ApplicationResponse,
    AssetCreate,
    AssetPatch,
    AssetResponse,
    FindingCreate,
    FindingPatch,
    FindingResponse,
)

router = APIRouter(prefix="/v1", tags=["resources"])


def _record(
    session: Session,
    user: User,
    *,
    action: str,
    subject_type: str,
    subject_id: str | None,
    metadata: dict[str, object],
) -> None:
    try:
        append_event(
            session,
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action=action,
            subject_type=subject_type,
            subject_id=subject_id,
            outcome="success",
            metadata=metadata,
        )
    except MetadataError as exc:
        raise invalid_input() from exc


def _limit(value: int) -> int:
    return min(value, 100)


@router.get("/applications", response_model=list[ApplicationResponse])
def list_applications(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[ApplicationResponse]:
    return [
        ApplicationResponse.model_validate(item)
        for item in list_owned(session, Application, user.tenant_id, limit=_limit(limit))
    ]


@router.post(
    "/applications", response_model=ApplicationResponse, status_code=status.HTTP_201_CREATED
)
def create_application(
    body: ApplicationCreate,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ApplicationResponse:
    if not safe_reference(body.repository_url):
        raise invalid_input()
    application = Application(
        tenant_id=user.tenant_id,
        name=body.name,
        repository_url=body.repository_url,
        environment=body.environment,
        status="active",
    )
    session.add(application)
    session.flush()
    _record(
        session,
        user,
        action="application.create",
        subject_type="application",
        subject_id=application.id,
        metadata={"environment": body.environment},
    )
    return ApplicationResponse.model_validate(application)


@router.get("/applications/{application_id}", response_model=ApplicationResponse)
def get_application(
    application_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ApplicationResponse:
    return ApplicationResponse.model_validate(owned_application(session, user, application_id))


@router.patch("/applications/{application_id}", response_model=ApplicationResponse)
def patch_application(
    application_id: str,
    body: ApplicationPatch,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> ApplicationResponse:
    application = owned_application(session, user, application_id)
    changes = body.model_dump(exclude_unset=True)
    if "repository_url" in changes and (
        changes["repository_url"] is None or not safe_reference(str(changes["repository_url"]))
    ):
        raise invalid_input()
    for key, value in changes.items():
        if value is not None:
            setattr(application, key, value)
    session.flush()
    _record(
        session,
        user,
        action="application.update",
        subject_type="application",
        subject_id=application.id,
        metadata={"fields": sorted(changes)},
    )
    return ApplicationResponse.model_validate(application)


@router.delete("/applications/{application_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_application(
    application_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> Response:
    application = owned_application(session, user, application_id)
    session.delete(application)
    session.flush()
    _record(
        session,
        user,
        action="application.delete",
        subject_type="application",
        subject_id=application_id,
        metadata={},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/assets", response_model=list[AssetResponse])
def list_assets(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[AssetResponse]:
    return [
        AssetResponse.model_validate(item)
        for item in list_owned(session, Asset, user.tenant_id, limit=_limit(limit))
    ]


@router.post("/assets", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    body: AssetCreate,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> AssetResponse:
    owned_application(session, user, body.application_id)
    if not safe_reference(body.locator):
        raise invalid_input()
    asset = Asset(
        tenant_id=user.tenant_id,
        application_id=body.application_id,
        kind=body.kind,
        locator=body.locator,
        status="active",
    )
    session.add(asset)
    session.flush()
    _record(
        session,
        user,
        action="asset.create",
        subject_type="asset",
        subject_id=asset.id,
        metadata={"kind": body.kind},
    )
    return AssetResponse.model_validate(asset)


@router.get("/assets/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> AssetResponse:
    asset = get_owned(session, Asset, user.tenant_id, asset_id)
    if asset is None:
        raise not_found()
    return AssetResponse.model_validate(asset)


@router.patch("/assets/{asset_id}", response_model=AssetResponse)
def patch_asset(
    asset_id: str,
    body: AssetPatch,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> AssetResponse:
    asset = get_owned(session, Asset, user.tenant_id, asset_id)
    if asset is None:
        raise not_found()
    changes = body.model_dump(exclude_unset=True)
    if "locator" in changes and (
        changes["locator"] is None or not safe_reference(str(changes["locator"]))
    ):
        raise invalid_input()
    for key, value in changes.items():
        if value is not None:
            setattr(asset, key, value)
    session.flush()
    _record(
        session,
        user,
        action="asset.update",
        subject_type="asset",
        subject_id=asset.id,
        metadata={"fields": sorted(changes)},
    )
    return AssetResponse.model_validate(asset)


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> Response:
    asset = get_owned(session, Asset, user.tenant_id, asset_id)
    if asset is None:
        raise not_found()
    session.delete(asset)
    session.flush()
    _record(
        session, user, action="asset.delete", subject_type="asset", subject_id=asset_id, metadata={}
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/findings", response_model=list[FindingResponse])
def list_findings(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[FindingResponse]:
    return [
        FindingResponse.model_validate(item)
        for item in list_owned(session, Finding, user.tenant_id, limit=_limit(limit))
    ]


@router.post("/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
def create_finding(
    body: FindingCreate,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> FindingResponse:
    application = owned_application(session, user, body.application_id)
    if body.asset_id is not None:
        asset = get_owned(session, Asset, user.tenant_id, body.asset_id)
        if asset is None or asset.application_id != application.id:
            raise not_found()
    try:
        summary = sanitize_text(body.summary, max_length=10_000)
        title = sanitize_text(body.title, max_length=300)
    except MetadataError as exc:
        raise invalid_input() from exc
    finding = Finding(
        tenant_id=user.tenant_id,
        application_id=application.id,
        asset_id=body.asset_id,
        severity=body.severity,
        status="open",
        title=title or body.title,
        summary=summary or body.summary,
        fingerprint=body.fingerprint,
    )
    session.add(finding)
    session.flush()
    _record(
        session,
        user,
        action="finding.create",
        subject_type="finding",
        subject_id=finding.id,
        metadata={"severity": body.severity},
    )
    return FindingResponse.model_validate(finding)


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> FindingResponse:
    finding = get_owned(session, Finding, user.tenant_id, finding_id)
    if finding is None:
        raise not_found()
    return FindingResponse.model_validate(finding)


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
def patch_finding(
    finding_id: str,
    body: FindingPatch,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> FindingResponse:
    finding = get_owned(session, Finding, user.tenant_id, finding_id)
    if finding is None:
        raise not_found()
    changes = body.model_dump(exclude_unset=True)
    try:
        if "title" in changes and changes["title"] is not None:
            changes["title"] = sanitize_text(str(changes["title"]), max_length=300)
        if "summary" in changes and changes["summary"] is not None:
            changes["summary"] = sanitize_text(str(changes["summary"]), max_length=10_000)
    except MetadataError as exc:
        raise invalid_input() from exc
    for key, value in changes.items():
        if value is not None:
            setattr(finding, key, value)
    session.flush()
    _record(
        session,
        user,
        action="finding.update",
        subject_type="finding",
        subject_id=finding.id,
        metadata={"fields": sorted(changes)},
    )
    return FindingResponse.model_validate(finding)


@router.delete("/findings/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_finding(
    finding_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> Response:
    finding = get_owned(session, Finding, user.tenant_id, finding_id)
    if finding is None:
        raise not_found()
    session.delete(finding)
    session.flush()
    _record(
        session,
        user,
        action="finding.delete",
        subject_type="finding",
        subject_id=finding_id,
        metadata={},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
