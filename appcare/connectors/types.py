"""Provider-neutral, secret-free types for the BETA-02 read-only boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from .security import is_safe_credential_reference

ProviderName = Literal["github", "vercel", "supabase"]
CredentialStatus = Literal["active", "expired", "revoked", "invalid"]


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class PermissionResult:
    """Safe permission evidence; it never contains credential material."""

    allowed: bool
    missing_capabilities: tuple[str, ...] = ()
    forbidden_capabilities: tuple[str, ...] = ()
    reason: str = "ok"


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    provider: ProviderName
    required_capabilities: tuple[str, ...]
    forbidden_capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CredentialMetadata:
    """Metadata for an opaque reference; no raw credential is accepted here."""

    credential_id: str
    provider: ProviderName
    tenant_id: str
    scopes: tuple[str, ...]
    version: int = 1
    issued_at: datetime = field(default_factory=utcnow)
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def status(self, now: datetime | None = None) -> CredentialStatus:
        current = now or utcnow()
        if self.issued_at.tzinfo is None or (
            self.expires_at is not None and self.expires_at.tzinfo is None
        ):
            return "invalid"
        if self.revoked_at is not None:
            return "revoked"
        if self.expires_at is not None and self.expires_at <= current:
            return "expired"
        if not is_safe_credential_reference(self.credential_id) or self.version < 1:
            return "invalid"
        return "active"


@dataclass(frozen=True, slots=True)
class RemoteRecord:
    kind: str
    provider_id: str
    name: str
    locator: str
    metadata: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ProviderSnapshot:
    provider: ProviderName
    resource_id: str
    domains: tuple[str, ...]
    records: tuple[RemoteRecord, ...]


@dataclass(frozen=True, slots=True)
class OwnershipTarget:
    expected_resource_id: str | None = None
    expected_domain: str | None = None


@dataclass(frozen=True, slots=True)
class ConnectorHealth:
    provider: ProviderName
    usable: bool
    credential_status: CredentialStatus
    missing_capabilities: tuple[str, ...] = ()
    forbidden_capabilities: tuple[str, ...] = ()
    unrecognized_capabilities: tuple[str, ...] = ()
    reason: str = "ok"


@dataclass(frozen=True, slots=True)
class OwnershipResult:
    verified: bool
    reason: str
    matched_resource: bool = False
    matched_domain: bool = False


@dataclass(frozen=True, slots=True)
class InventoryAsset:
    asset_key: str
    provider: ProviderName
    kind: str
    provider_id: str
    name: str
    locator: str
    metadata: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class InventoryResult:
    digest: str
    assets: tuple[InventoryAsset, ...]
    ownership: OwnershipResult
