"""Deterministic, tenant-scoped inventory normalization and reconciliation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorAccessError, ReadOnlyConnector
from ..connectors.providers import get_provider_spec
from ..connectors.types import (
    InventoryAsset,
    InventoryResult,
    OwnershipTarget,
    ProviderName,
    RemoteRecord,
)
from ..models import Application, Asset
from ..repositories.tenant_scope import valid_public_id
from ..routes.common import safe_reference
from ..services.audit import MetadataError, sanitize_metadata, sanitize_text

_KIND = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,99}$")


class InventoryError(ValueError):
    """Inventory cannot be safely collected or reconciled."""


def _connector_failure_reason(error: ConnectorAccessError) -> str:
    reason = str(error)
    return reason if re.fullmatch(r"[a-z0-9_]{1,100}", reason) else "unsafe_record"


def _canonical_locator(locator: str) -> str:
    candidate = locator.strip()
    if not safe_reference(candidate):
        raise InventoryError("unsafe_record")
    if "://" not in candidate:
        return candidate.casefold()
    parsed = urlsplit(candidate)
    if parsed.scheme.casefold() != "https":
        raise InventoryError("unsafe_record")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise InventoryError("unsafe_record")
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InventoryError("unsafe_record") from exc
    if not host:
        raise InventoryError("unsafe_record")
    netloc = host.casefold()
    if port is not None:
        netloc = f"{netloc}:{port}"
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.casefold(), netloc, path, parsed.query, ""))


def _normalize_record(provider: ProviderName, record: RemoteRecord) -> InventoryAsset:
    try:
        kind = (sanitize_text(record.kind, max_length=100) or "").strip().casefold()
        provider_id = sanitize_text(record.provider_id, max_length=200) or ""
        name = sanitize_text(record.name, max_length=200) or ""
        locator = _canonical_locator(sanitize_text(record.locator, max_length=500) or "")
        metadata = sanitize_metadata(record.metadata)
    except (MetadataError, InventoryError) as exc:
        raise InventoryError("unsafe_record") from exc
    if not _KIND.fullmatch(kind) or not provider_id or not name or not locator:
        raise InventoryError("unsafe_record")
    canonical = {
        "kind": kind,
        "locator": locator,
        "metadata": metadata,
        "name": name,
        "provider": provider,
        "provider_id": provider_id,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return InventoryAsset(
        asset_key=hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        provider=provider,
        kind=kind,
        provider_id=provider_id,
        name=name,
        locator=locator,
        metadata=metadata,
    )


def normalize_records(provider: str, records: Iterable[RemoteRecord]) -> tuple[InventoryAsset, ...]:
    """Normalize, de-duplicate, and deterministically order remote records."""

    normalized_provider = get_provider_spec(provider).provider
    normalized: dict[str, InventoryAsset] = {}
    for record in records:
        asset = _normalize_record(normalized_provider, record)
        current = normalized.get(asset.asset_key)
        if current is None or json.dumps(asset, default=str, sort_keys=True) < json.dumps(
            current, default=str, sort_keys=True
        ):
            normalized[asset.asset_key] = asset
    return tuple(normalized[key] for key in sorted(normalized))


def inventory_digest(assets: Iterable[InventoryAsset]) -> str:
    payload = [
        {
            "asset_key": asset.asset_key,
            "kind": asset.kind,
            "locator": asset.locator,
            "metadata": asset.metadata,
            "name": asset.name,
            "provider": asset.provider,
            "provider_id": asset.provider_id,
        }
        for asset in assets
    ]
    payload.sort(key=lambda item: str(item["asset_key"]))
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def reconcile_assets(
    session: Session,
    *,
    tenant_id: str,
    application_id: str,
    assets: Iterable[InventoryAsset],
) -> list[Asset]:
    """Add observed assets to AppCare without deleting or changing provider state."""

    application = session.scalar(
        select(Application).where(
            Application.id == application_id,
            Application.tenant_id == tenant_id,
        )
    )
    if application is None:
        raise InventoryError("application_not_owned")
    persisted: list[Asset] = []
    for observed in assets:
        canonical_matches = list(
            session.scalars(
                select(Asset).where(
                    Asset.tenant_id == tenant_id,
                    Asset.application_id == application_id,
                    Asset.provider == observed.provider,
                    Asset.provider_reference == observed.provider_id,
                )
            )
        )
        if len(canonical_matches) > 1:
            raise InventoryError("inventory_identity_conflict")
        existing = canonical_matches[0] if canonical_matches else None
        if existing is None:
            legacy_matches = list(
                session.scalars(
                    select(Asset).where(
                        Asset.tenant_id == tenant_id,
                        Asset.application_id == application_id,
                        Asset.provider.is_(None),
                        Asset.provider_reference.is_(None),
                        Asset.kind == observed.kind,
                        Asset.locator == observed.locator,
                    )
                )
            )
            if len(legacy_matches) > 1:
                raise InventoryError("inventory_identity_conflict")
            existing = legacy_matches[0] if legacy_matches else None
        if existing is None:
            existing = Asset(
                tenant_id=tenant_id,
                application_id=application_id,
                provider=observed.provider,
                provider_reference=observed.provider_id,
                kind=observed.kind,
                locator=observed.locator,
                display_name=observed.name,
                display_metadata_json=dict(observed.metadata),
                status="active",
            )
            session.add(existing)
            session.flush()
        else:
            existing.provider = observed.provider
            existing.provider_reference = observed.provider_id
            existing.kind = observed.kind
            existing.locator = observed.locator
            existing.display_name = observed.name
            existing.display_metadata_json = dict(observed.metadata)
            existing.status = "active"
        persisted.append(existing)
    return persisted


def collect_inventory(
    connector: ReadOnlyConnector,
    *,
    tenant_id: str,
    application_id: str,
    target: OwnershipTarget,
    session: Session | None = None,
) -> InventoryResult:
    """Collect safe inventory and optionally reconcile it into local AppCare assets."""

    if not valid_public_id(tenant_id) or not valid_public_id(application_id):
        raise InventoryError("invalid_owner")
    if connector.tenant_id != tenant_id:
        raise InventoryError("credential_not_owned")
    health = connector.health()
    if not health.usable:
        raise InventoryError(health.reason)
    try:
        ownership = connector.verify_ownership(target)
    except ConnectorAccessError as exc:
        raise InventoryError(_connector_failure_reason(exc)) from exc
    if not ownership.verified:
        raise InventoryError(ownership.reason)
    try:
        snapshot = connector.inventory()
        assets = normalize_records(snapshot.provider, snapshot.records)
    except ConnectorAccessError as exc:
        raise InventoryError(_connector_failure_reason(exc)) from exc
    result = InventoryResult(
        digest=inventory_digest(assets),
        assets=assets,
        ownership=ownership,
    )
    if session is not None:
        reconcile_assets(
            session,
            tenant_id=tenant_id,
            application_id=application_id,
            assets=assets,
        )
    return result
