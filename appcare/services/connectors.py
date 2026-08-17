"""Tenant-scoped, fail-closed read-only connector services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors import (
    ConnectorRegistry,
    NormalizedConnectorResult,
    provider_profile,
    validate_scopes,
)
from ..connectors.base import ConnectorAccessError, RegistryReadOnlyConnector
from ..connectors.contracts import CheckResult
from ..connectors.credentials import CredentialLifecycleError, CredentialRegistry
from ..connectors.providers import ProviderConfigurationError, canonical_capabilities
from ..connectors.security import (
    is_safe_credential_fingerprint,
    is_safe_credential_reference,
)
from ..connectors.types import CredentialMetadata, OwnershipTarget
from ..inventory import InventoryError, collect_inventory
from ..models import (
    Application,
    Asset,
    Connector,
    ConnectorCheck,
    ConnectorCredential,
    InventoryRun,
    utcnow,
)
from ..routes.common import safe_reference
from ..services.audit import MetadataError, append_event, sanitize_text
from ..services.security import contains_credential_like

_ALLOWED_CREDENTIAL_STATUSES = {
    "active",
    "expired",
    "revoked",
    "invalid",
    "insufficient_scope",
}
_CREDENTIAL_AUTHORITY = "appcare-secret-service"


@dataclass(frozen=True, slots=True)
class ConnectorRegistration:
    application_id: str
    provider: str
    kind: str
    display_name: str
    resource_reference: str | None
    owner_reference: str | None
    scopes: tuple[str, ...]
    credential_reference: str | None
    credential_authority: str
    credential_expires_at: datetime | None
    credential_status: str
    credential_fingerprint: str | None


@dataclass(frozen=True, slots=True)
class ConnectorCheckSummary:
    health_status: Literal["passed", "failed", "unknown"]
    permission_status: Literal["passed", "failed", "unknown"]
    ownership_status: Literal["passed", "failed", "unknown"]
    overall_status: Literal["passed", "failed", "unknown"]
    reason_codes: tuple[str, ...]
    checked_at: datetime
    normalized: NormalizedConnectorResult | None


@dataclass(frozen=True, slots=True)
class InventorySummary:
    run: InventoryRun
    assets: tuple[Asset, ...]


def _safe_reason(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.casefold()
    if not normalized or len(normalized) > 100:
        return "connector_check_failed"
    if not all(character.isalnum() or character == "_" for character in normalized):
        return "connector_check_failed"
    return normalized


def _safe_metadata_reference(value: str | None, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError("connector reference is required")
        return None
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 500
        or any(character.isspace() or ord(character) < 32 for character in normalized)
        or not safe_reference(normalized)
    ):
        raise ValueError("connector reference is unsafe")
    if contains_credential_like(normalized):
        raise ValueError("connector reference is unsafe")
    return normalized


def _safe_credential_reference(value: str | None, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError("credential reference is required")
        return None
    normalized = value.strip()
    if not is_safe_credential_reference(normalized):
        raise ValueError("credential reference is unsafe")
    return normalized


def _safe_credential_fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not is_safe_credential_fingerprint(normalized):
        raise ValueError("credential fingerprint is unsafe")
    return normalized.lower()


def _safe_display_text(value: str, *, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError("connector display text is invalid")
    try:
        sanitized = sanitize_text(normalized, max_length=maximum)
    except MetadataError as exc:
        raise ValueError("connector display text is unsafe") from exc
    if sanitized is None:
        raise ValueError("connector display text is invalid")
    return sanitized


def _credential_for(
    session: Session, *, tenant_id: str, connector_id: str
) -> ConnectorCredential | None:
    return session.scalar(
        select(ConnectorCredential).where(
            ConnectorCredential.tenant_id == tenant_id,
            ConnectorCredential.connector_id == connector_id,
        )
    )


def _credential_failure(
    credential: ConnectorCredential | None,
    *,
    provider: str,
    configured_scopes: tuple[str, ...],
    now: datetime,
) -> str | None:
    if credential is None:
        return "credential_reference_missing"
    if credential.status not in _ALLOWED_CREDENTIAL_STATUSES:
        return "credential_status_invalid"
    if credential.status != "active":
        return "credential_" + credential.status
    if credential.expires_at is not None:
        expires_at = credential.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            return "credential_expired"
    try:
        _safe_credential_reference(credential.reference, required=True)
        available_scopes = canonical_capabilities(provider, credential.scopes_json)
        configured_capabilities = canonical_capabilities(provider, configured_scopes)
    except (ProviderConfigurationError, ValueError):
        return "credential_metadata_invalid"
    if not set(configured_capabilities).issubset(set(available_scopes)):
        return "credential_insufficient_scope"
    return None


def register_connector(
    session: Session,
    *,
    tenant_id: str,
    application: Application,
    registration: ConnectorRegistration,
) -> Connector:
    if application.tenant_id != tenant_id:
        raise ValueError("application is outside the tenant")
    if registration.credential_status not in _ALLOWED_CREDENTIAL_STATUSES:
        raise ValueError("credential status is invalid")
    scopes = validate_scopes(registration.provider, registration.scopes)
    kind = _safe_display_text(registration.kind, maximum=100)
    display_name = _safe_display_text(registration.display_name, maximum=200)
    authority = _safe_metadata_reference(registration.credential_authority, required=True)
    if authority != _CREDENTIAL_AUTHORITY:
        raise ValueError("credential authority is unsupported")
    profile = provider_profile(registration.provider)
    if profile is None or kind.casefold() not in profile.inventory_kinds:
        raise ValueError("connector kind is not supported for the provider")
    resource_reference = _safe_metadata_reference(registration.resource_reference)
    owner_reference = _safe_metadata_reference(registration.owner_reference)
    credential_reference = _safe_credential_reference(registration.credential_reference)
    canonical_scopes = canonical_capabilities(registration.provider, scopes)
    fingerprint = _safe_credential_fingerprint(registration.credential_fingerprint)
    if registration.credential_status != "active" and credential_reference is None:
        raise ValueError("credential status requires a reference")
    if credential_reference is None and (
        registration.credential_authority != "appcare-secret-service"
        or registration.credential_expires_at is not None
        or fingerprint is not None
    ):
        raise ValueError("credential metadata requires a reference")

    connector = Connector(
        tenant_id=tenant_id,
        application_id=application.id,
        provider=registration.provider,
        kind=kind,
        status="configured",
        display_name=display_name,
        resource_reference=resource_reference,
        owner_reference=owner_reference,
        scope_json=list(scopes),
        health_status="unknown",
        permission_status="unknown",
        ownership_status="unknown",
    )
    session.add(connector)
    session.flush()
    if credential_reference is not None:
        session.add(
            ConnectorCredential(
                tenant_id=tenant_id,
                connector_id=connector.id,
                reference=credential_reference,
                authority=authority or "appcare-secret-service",
                scopes_json=list(canonical_scopes),
                status=registration.credential_status,
                expires_at=registration.credential_expires_at,
                fingerprint=fingerprint,
            )
        )
        session.flush()
    return connector


def _record_checks(
    session: Session,
    *,
    tenant_id: str,
    connector: Connector,
    summary: ConnectorCheckSummary,
) -> None:
    if summary.normalized is None:
        results = {
            "health": (
                summary.health_status,
                summary.reason_codes[0] if summary.reason_codes else None,
            ),
            "permissions": (
                summary.permission_status,
                summary.reason_codes[0] if summary.reason_codes else None,
            ),
            "ownership": (
                summary.ownership_status,
                summary.reason_codes[0] if summary.reason_codes else None,
            ),
        }
        evidence: dict[str, object] = {"ok": False}
    else:
        normalized = summary.normalized
        results = {
            "health": (normalized.health.status, normalized.health.reason_code),
            "permissions": (normalized.permissions.status, normalized.permissions.reason_code),
            "ownership": (normalized.ownership.status, normalized.ownership.reason_code),
        }
        evidence = {}
    for kind, (status, reason_code) in results.items():
        item_evidence = evidence.copy()
        if summary.normalized is not None:
            result = getattr(summary.normalized, kind)
            item_evidence = dict(result.evidence)
        session.add(
            ConnectorCheck(
                tenant_id=tenant_id,
                connector_id=connector.id,
                check_kind=kind,
                status=status,
                reason_code=_safe_reason(reason_code),
                evidence_json=item_evidence,
                checked_at=summary.checked_at,
            )
        )


def _failed_summary(reason_code: str, *, checked_at: datetime) -> ConnectorCheckSummary:
    reason = _safe_reason(reason_code) or "connector_check_failed"
    return ConnectorCheckSummary(
        health_status="failed",
        permission_status="failed",
        ownership_status="failed",
        overall_status="failed",
        reason_codes=(reason,),
        checked_at=checked_at,
        normalized=None,
    )


def _build_read_only_connector(
    session: Session,
    *,
    tenant_id: str,
    connector: Connector,
    registry: ConnectorRegistry,
    checked_at: datetime,
) -> RegistryReadOnlyConnector:
    credential = _credential_for(session, tenant_id=tenant_id, connector_id=connector.id)
    configured_scopes = tuple(scope for scope in connector.scope_json if isinstance(scope, str))
    failure = _credential_failure(
        credential,
        provider=connector.provider,
        configured_scopes=configured_scopes,
        now=checked_at,
    )
    if failure is not None or credential is None:
        raise ConnectorAccessError(failure or "credential_reference_missing")
    try:
        canonical_scopes = canonical_capabilities(connector.provider, credential.scopes_json)
    except (ProviderConfigurationError, ValueError) as exc:
        raise ConnectorAccessError("credential_metadata_invalid") from exc
    metadata = CredentialMetadata(
        credential_id=credential.reference,
        provider=connector.provider,  # type: ignore[arg-type]
        tenant_id=credential.tenant_id,
        scopes=canonical_scopes,
        expires_at=credential.expires_at,
        revoked_at=utcnow() if credential.status == "revoked" else None,
    )
    lifecycle = CredentialRegistry()
    try:
        metadata = lifecycle.register(metadata)
        metadata = lifecycle.get(
            tenant_id=tenant_id,
            credential_id=metadata.credential_id,
        )
    except CredentialLifecycleError as exc:
        raise ConnectorAccessError("credential_metadata_invalid") from exc
    return RegistryReadOnlyConnector(
        provider=connector.provider,  # type: ignore[arg-type]
        credential=metadata,
        legacy_scopes=configured_scopes,
        authority=credential.authority,
        resource_reference=connector.resource_reference or "",
        owner_reference=connector.owner_reference or "",
        registry=registry,
    )


def _summary_from_read_only(
    read_only: RegistryReadOnlyConnector,
    *,
    resource_reference: str,
    checked_at: datetime,
) -> ConnectorCheckSummary:
    health = read_only.health()
    if not health.usable:
        return _failed_summary(health.reason, checked_at=checked_at)
    ownership = read_only.verify_ownership(OwnershipTarget(expected_resource_id=resource_reference))
    if not ownership.verified:
        normalized = NormalizedConnectorResult(
            CheckResult("passed", None, {"ok": True}),
            CheckResult("passed", None, {"allowed": True}),
            CheckResult("failed", ownership.reason, {"matched": False}),
            (),
        )
    else:
        try:
            read_only.inventory()
        except ConnectorAccessError as exc:
            return _failed_summary(str(exc), checked_at=checked_at)
        normalized = NormalizedConnectorResult(
            CheckResult("passed", None, {"ok": True}),
            CheckResult("passed", None, {"allowed": True}),
            CheckResult("passed", None, {"matched": True}),
            (),
        )
    reasons = tuple(
        reason
        for reason in (
            normalized.health.reason_code,
            normalized.permissions.reason_code,
            normalized.ownership.reason_code,
        )
        if reason is not None
    )
    statuses = (normalized.health, normalized.permissions, normalized.ownership)
    return ConnectorCheckSummary(
        health_status=normalized.health.status,
        permission_status=normalized.permissions.status,
        ownership_status=normalized.ownership.status,
        overall_status="passed" if all(item.status == "passed" for item in statuses) else "failed",
        reason_codes=tuple(_safe_reason(reason) or "connector_check_failed" for reason in reasons),
        checked_at=checked_at,
        normalized=normalized,
    )


def _collect_and_normalize(
    session: Session,
    *,
    tenant_id: str,
    connector: Connector,
    registry: ConnectorRegistry,
) -> ConnectorCheckSummary:
    checked_at = utcnow()
    if connector.resource_reference is None or connector.owner_reference is None:
        summary = _failed_summary("ownership_reference_missing", checked_at=checked_at)
        _record_checks(session, tenant_id=tenant_id, connector=connector, summary=summary)
        connector.health_status = summary.health_status
        connector.permission_status = summary.permission_status
        connector.ownership_status = summary.ownership_status
        connector.last_checked_at = checked_at
        session.flush()
        return summary
    try:
        read_only = _build_read_only_connector(
            session,
            tenant_id=tenant_id,
            connector=connector,
            registry=registry,
            checked_at=checked_at,
        )
        summary = _summary_from_read_only(
            read_only,
            resource_reference=connector.resource_reference,
            checked_at=checked_at,
        )
    except ConnectorAccessError as exc:
        summary = _failed_summary(str(exc), checked_at=checked_at)
    except (ValueError, KeyError):
        summary = _failed_summary("connector_check_invalid", checked_at=checked_at)
    connector.health_status = summary.health_status
    connector.permission_status = summary.permission_status
    connector.ownership_status = summary.ownership_status
    connector.last_checked_at = checked_at
    _record_checks(session, tenant_id=tenant_id, connector=connector, summary=summary)
    session.flush()
    return summary


def check_connector(
    session: Session,
    *,
    tenant_id: str,
    connector: Connector,
    registry: ConnectorRegistry,
) -> ConnectorCheckSummary:
    if connector.tenant_id != tenant_id:
        raise ValueError("connector is outside the tenant")
    return _collect_and_normalize(
        session, tenant_id=tenant_id, connector=connector, registry=registry
    )


def _snapshot_key(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 128 or not safe_reference(normalized):
        raise ValueError("snapshot key is unsafe")
    return normalized


def _attach_inventory_assets(
    session: Session,
    *,
    tenant_id: str,
    connector: Connector,
    observed_assets: tuple[object, ...],
) -> list[Asset]:
    existing_assets = list(
        session.scalars(
            select(Asset).where(
                Asset.tenant_id == tenant_id,
                Asset.application_id == connector.application_id,
            )
        )
    )
    plans: list[tuple[Asset, str]] = []
    seen_references: set[str] = set()
    for observed in observed_assets:
        provider = getattr(observed, "provider", None)
        provider_id = getattr(observed, "provider_id", None)
        if not isinstance(provider, str) or not isinstance(provider_id, str):
            raise InventoryError("inventory_identity_conflict")
        reference = provider_id.casefold()
        if reference in seen_references:
            raise InventoryError("inventory_identity_conflict")
        seen_references.add(reference)
        matches = [
            asset
            for asset in existing_assets
            if asset.provider is not None
            and asset.provider_reference is not None
            and asset.provider.casefold() == provider.casefold()
            and asset.provider_reference.casefold() == reference
        ]
        if len(matches) != 1:
            raise InventoryError("inventory_identity_conflict")
        plans.append((matches[0], reference))

    with session.begin_nested():
        assets: list[Asset] = []
        for asset, _reference in plans:
            asset.connector_id = connector.id
            asset.last_seen_at = utcnow()
            asset.status = "active"
            assets.append(asset)
        for asset in existing_assets:
            existing_reference = (
                asset.provider_reference.casefold() if asset.provider_reference else None
            )
            if asset.connector_id == connector.id and existing_reference not in seen_references:
                asset.status = "retired"
        session.flush()
        return assets


def inventory_connector(
    session: Session,
    *,
    tenant_id: str,
    connector: Connector,
    registry: ConnectorRegistry,
    snapshot_key: str = "current",
    actor_user_id: str | None = None,
) -> InventorySummary:
    if connector.tenant_id != tenant_id:
        raise ValueError("connector is outside the tenant")
    key = _snapshot_key(snapshot_key)
    started = utcnow()
    run = session.scalar(
        select(InventoryRun).where(
            InventoryRun.tenant_id == tenant_id,
            InventoryRun.connector_id == connector.id,
            InventoryRun.snapshot_key == key,
        )
    )
    if run is None:
        run = InventoryRun(
            tenant_id=tenant_id,
            connector_id=connector.id,
            snapshot_key=key,
            status="running",
            asset_count=0,
            started_at=started,
        )
        session.add(run)
        session.flush()
    else:
        run.status = "running"
        run.failure_code = None
        run.started_at = started
    read_only: RegistryReadOnlyConnector | None = None
    assets: list[Asset] = []
    try:
        with session.begin_nested():
            if connector.resource_reference is None or connector.owner_reference is None:
                raise InventoryError("ownership_reference_missing")
            read_only = _build_read_only_connector(
                session,
                tenant_id=tenant_id,
                connector=connector,
                registry=registry,
                checked_at=started,
            )
            result = collect_inventory(
                read_only,
                tenant_id=tenant_id,
                application_id=connector.application_id,
                target=OwnershipTarget(expected_resource_id=connector.resource_reference),
                session=session,
            )
            summary = _summary_from_read_only(
                read_only,
                resource_reference=connector.resource_reference,
                checked_at=started,
            )
            if summary.overall_status != "passed":
                raise InventoryError("connector_inventory_failed")
            assets = _attach_inventory_assets(
                session,
                tenant_id=tenant_id,
                connector=connector,
                observed_assets=result.assets,
            )
    except (ConnectorAccessError, InventoryError, ValueError) as exc:
        summary = _failed_summary(str(exc), checked_at=started)
        result = None

    connector.health_status = summary.health_status
    connector.permission_status = summary.permission_status
    connector.ownership_status = summary.ownership_status
    connector.last_checked_at = summary.checked_at
    _record_checks(session, tenant_id=tenant_id, connector=connector, summary=summary)

    if result is None or summary.overall_status != "passed":
        run.status = "failed"
        run.failure_code = _safe_reason(summary.reason_codes[0] if summary.reason_codes else None)
        run.failure_code = run.failure_code or "connector_inventory_failed"
        run.finished_at = utcnow()
        run.asset_count = 0
        session.flush()
        if actor_user_id is not None:
            append_event(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                action="connector.inventory",
                subject_type="connector",
                subject_id=connector.id,
                outcome="failure",
                metadata={
                    "snapshot_key": key,
                    "status": "failed",
                    "failure_code": run.failure_code,
                },
            )
        return InventorySummary(run, ())

    run.status = "succeeded"
    run.failure_code = None
    run.finished_at = utcnow()
    run.asset_count = len(assets)
    session.flush()
    if actor_user_id is not None:
        append_event(
            session,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            action="connector.inventory",
            subject_type="connector",
            subject_id=connector.id,
            outcome="success",
            metadata={"snapshot_key": key, "status": "succeeded", "asset_count": len(assets)},
        )
    return InventorySummary(run, tuple(assets))


def connector_credential(
    session: Session, *, tenant_id: str, connector_id: str
) -> ConnectorCredential | None:
    return _credential_for(session, tenant_id=tenant_id, connector_id=connector_id)
