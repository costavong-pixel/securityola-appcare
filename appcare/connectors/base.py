"""Fixture-backed read-only connector contract."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from urllib.parse import urlsplit

from ..routes.common import safe_reference
from ..services.audit import MetadataError, sanitize_metadata, sanitize_text
from .contracts import CredentialContext, NormalizedConnectorResult
from .providers import ProviderConfigurationError, get_provider_spec, validate_capabilities
from .types import (
    ConnectorHealth,
    CredentialMetadata,
    OwnershipResult,
    OwnershipTarget,
    ProviderName,
    ProviderSnapshot,
    RemoteRecord,
)

if TYPE_CHECKING:
    from .adapters import ConnectorRegistry


class ConnectorAccessError(ValueError):
    """A read-only connector cannot safely provide its snapshot."""


class ReadOnlyConnector(Protocol):
    provider: ProviderName
    tenant_id: str

    def health(self) -> ConnectorHealth: ...

    def inventory(self) -> ProviderSnapshot: ...

    def verify_ownership(self, target: OwnershipTarget) -> OwnershipResult: ...


class RegistryReadOnlyConnector:
    """Adapt the injected fixed-request registry to the canonical read-only API."""

    def __init__(
        self,
        *,
        provider: ProviderName,
        credential: CredentialMetadata,
        legacy_scopes: tuple[str, ...],
        authority: str,
        resource_reference: str,
        owner_reference: str,
        registry: ConnectorRegistry,
    ) -> None:
        self.provider = provider
        self.tenant_id = credential.tenant_id
        self._credential = credential
        self._legacy_scopes = legacy_scopes
        self._authority = authority
        self._resource_reference = resource_reference
        self._owner_reference = owner_reference
        self._registry = registry
        self._normalized: NormalizedConnectorResult | None = None

    def _collect(self) -> NormalizedConnectorResult:
        if self._normalized is not None:
            return self._normalized
        try:
            adapter = self._registry.adapter(self.provider)
            payloads = self._registry.collect(
                self.provider,
                CredentialContext(
                    reference=self._credential.credential_id,
                    scopes=self._legacy_scopes,
                    tenant_id=self._credential.tenant_id,
                    authority=self._authority,
                ),
                self._resource_reference,
                tenant_id=self._credential.tenant_id,
            )
            self._normalized = adapter.normalize(
                payloads,
                resource_reference=self._resource_reference,
                owner_reference=self._owner_reference,
                configured_scopes=self._legacy_scopes,
            )
            return self._normalized
        except Exception as exc:
            from .transport import ProviderTransportError

            if isinstance(exc, ProviderTransportError):
                raise ConnectorAccessError(exc.reason_code) from exc
            if isinstance(exc, (KeyError, ValueError)):
                raise ConnectorAccessError("connector_evidence_invalid") from exc
            raise ConnectorAccessError("provider_transport_failed") from exc

    def health(self) -> ConnectorHealth:
        status = self._credential.status()
        if self._credential.provider != self.provider:
            return ConnectorHealth(self.provider, False, "invalid", reason="provider_mismatch")
        try:
            permission = validate_capabilities(self.provider, self._credential.scopes)
        except ProviderConfigurationError:
            return ConnectorHealth(self.provider, False, "invalid", reason="invalid_capability")
        if status != "active":
            return ConnectorHealth(self.provider, False, status, reason=f"{status}_credential")
        if not permission.allowed:
            return ConnectorHealth(
                self.provider,
                False,
                status,
                missing_capabilities=permission.missing_capabilities,
                forbidden_capabilities=permission.forbidden_capabilities,
                unrecognized_capabilities=(
                    permission.forbidden_capabilities
                    if permission.reason == "unrecognized_capability"
                    else ()
                ),
                reason=permission.reason,
            )
        try:
            normalized = self._collect()
        except ConnectorAccessError as exc:
            return ConnectorHealth(self.provider, False, status, reason=str(exc))
        if normalized.health.status != "passed":
            return ConnectorHealth(
                self.provider,
                False,
                status,
                reason=normalized.health.reason_code or "provider_health_failed",
            )
        if normalized.permissions.status != "passed":
            return ConnectorHealth(
                self.provider,
                False,
                status,
                reason=normalized.permissions.reason_code or "insufficient_scope",
            )
        return ConnectorHealth(self.provider, True, status)

    def inventory(self) -> ProviderSnapshot:
        health = self.health()
        if not health.usable:
            raise ConnectorAccessError(health.reason)
        normalized = self._collect()
        if not normalized.inventory_valid:
            raise ConnectorAccessError(normalized.inventory_reason or "unsafe_record")
        snapshot = ProviderSnapshot(
            provider=self.provider,
            resource_id=self._resource_reference,
            domains=(),
            records=tuple(
                RemoteRecord(
                    kind=observation.kind,
                    provider_id=observation.provider_reference,
                    name=observation.display_name,
                    locator=observation.locator,
                    metadata=observation.metadata,
                )
                for observation in normalized.assets
            ),
        )
        return _safe_snapshot(snapshot, self.provider)

    def verify_ownership(self, target: OwnershipTarget) -> OwnershipResult:
        health = self.health()
        if not health.usable:
            return OwnershipResult(False, health.reason)
        if target.expected_domain is not None:
            return OwnershipResult(False, "invalid_target")
        matched_resource = (
            target.expected_resource_id is None
            or target.expected_resource_id == self._resource_reference
        )
        if not matched_resource:
            return OwnershipResult(False, "resource_mismatch", False, False)
        ownership = self._collect().ownership
        if ownership.status != "passed":
            return OwnershipResult(
                False, ownership.reason_code or "ownership_mismatch", True, False
            )
        return OwnershipResult(True, "matched", True, True)


def normalize_domain(value: str) -> str | None:
    candidate = value.strip().casefold()
    if not candidate:
        return None
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    if parsed.username is not None or parsed.password is not None:
        return None
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None
    host = parsed.hostname
    if host is None:
        return None
    normalized = host.rstrip(".")
    if (
        not normalized
        or ".." in normalized
        or any(not (character.isalnum() or character in ".-") for character in normalized)
    ):
        return None
    return normalized


def _safe_record(record: RemoteRecord) -> RemoteRecord:
    try:
        kind = sanitize_text(record.kind, max_length=100)
        provider_id = sanitize_text(record.provider_id, max_length=200)
        name = sanitize_text(record.name, max_length=200)
        locator = sanitize_text(record.locator, max_length=500)
        metadata = sanitize_metadata(record.metadata)
    except MetadataError as exc:
        raise ConnectorAccessError("unsafe_record") from exc
    if not kind or not provider_id or not name or not locator or not safe_reference(locator):
        raise ConnectorAccessError("unsafe_record")
    return RemoteRecord(
        kind=kind.strip().casefold(),
        provider_id=provider_id,
        name=name,
        locator=locator,
        metadata=metadata,
    )


def _safe_snapshot(snapshot: ProviderSnapshot, provider: ProviderName) -> ProviderSnapshot:
    if snapshot.provider != provider:
        raise ConnectorAccessError("provider_mismatch")
    resource_id = sanitize_text(snapshot.resource_id, max_length=200)
    if not resource_id:
        raise ConnectorAccessError("unsafe_record")
    domains = tuple(
        domain
        for raw_domain in snapshot.domains
        if (domain := normalize_domain(raw_domain)) is not None
    )
    if len(domains) != len(snapshot.domains):
        raise ConnectorAccessError("unsafe_record")
    return ProviderSnapshot(
        provider=provider,
        resource_id=resource_id,
        domains=tuple(sorted(set(domains))),
        records=tuple(_safe_record(record) for record in snapshot.records),
    )


class FixtureReadOnlyConnector:
    """Use injected provider data while keeping the connector surface read-only."""

    def __init__(
        self,
        provider: ProviderName,
        credential: CredentialMetadata,
        snapshot: ProviderSnapshot,
    ) -> None:
        self.provider = provider
        self.tenant_id = credential.tenant_id
        self._spec = get_provider_spec(provider)
        self._credential = credential
        self._snapshot = snapshot

    def health(self) -> ConnectorHealth:
        credential_status = self._credential.status()
        if self._credential.provider != self.provider:
            return ConnectorHealth(
                provider=self.provider,
                usable=False,
                credential_status="invalid",
                reason="provider_mismatch",
            )
        if credential_status != "active":
            return ConnectorHealth(
                provider=self.provider,
                usable=False,
                credential_status=credential_status,
                reason=f"{credential_status}_credential",
            )
        try:
            permission = validate_capabilities(self.provider, self._credential.scopes)
        except ProviderConfigurationError as exc:
            raise ConnectorAccessError("invalid_provider") from exc
        return ConnectorHealth(
            provider=self.provider,
            usable=permission.allowed,
            credential_status=credential_status,
            missing_capabilities=permission.missing_capabilities,
            forbidden_capabilities=permission.forbidden_capabilities,
            unrecognized_capabilities=(
                permission.forbidden_capabilities
                if permission.reason == "unrecognized_capability"
                else ()
            ),
            reason=permission.reason,
        )

    def inventory(self) -> ProviderSnapshot:
        health = self.health()
        if not health.usable:
            raise ConnectorAccessError(health.reason)
        return _safe_snapshot(self._snapshot, self.provider)

    def verify_ownership(self, target: OwnershipTarget) -> OwnershipResult:
        if target.expected_resource_id is None and target.expected_domain is None:
            return OwnershipResult(False, "missing_target")
        snapshot = self.inventory()
        expected_resource = (
            target.expected_resource_id.strip() if target.expected_resource_id else None
        )
        expected_domain = (
            normalize_domain(target.expected_domain) if target.expected_domain else None
        )
        if target.expected_resource_id and not expected_resource:
            return OwnershipResult(False, "invalid_target")
        if target.expected_domain and expected_domain is None:
            return OwnershipResult(False, "invalid_target")
        resource_match = expected_resource is None or snapshot.resource_id == expected_resource
        domain_match = expected_domain is None or any(
            domain == expected_domain or domain.endswith(f".{expected_domain}")
            for domain in snapshot.domains
        )
        if not resource_match:
            return OwnershipResult(False, "resource_mismatch", False, domain_match)
        if not domain_match:
            return OwnershipResult(False, "domain_mismatch", resource_match, False)
        return OwnershipResult(True, "matched", resource_match, domain_match)


class GitHubReadOnlyConnector(FixtureReadOnlyConnector):
    def __init__(self, credential: CredentialMetadata, snapshot: ProviderSnapshot) -> None:
        super().__init__("github", credential, snapshot)


class VercelReadOnlyConnector(FixtureReadOnlyConnector):
    def __init__(self, credential: CredentialMetadata, snapshot: ProviderSnapshot) -> None:
        super().__init__("vercel", credential, snapshot)


class SupabaseReadOnlyConnector(FixtureReadOnlyConnector):
    def __init__(self, credential: CredentialMetadata, snapshot: ProviderSnapshot) -> None:
        super().__init__("supabase", credential, snapshot)


def build_fixture_connector(
    provider: str,
    credential: CredentialMetadata,
    snapshot: ProviderSnapshot,
) -> ReadOnlyConnector:
    normalized = get_provider_spec(provider).provider
    if normalized == "github":
        return GitHubReadOnlyConnector(credential, snapshot)
    if normalized == "vercel":
        return VercelReadOnlyConnector(credential, snapshot)
    return SupabaseReadOnlyConnector(credential, snapshot)
