"""Fixture-backed read-only connector contract."""

from __future__ import annotations

from typing import Protocol
from urllib.parse import urlsplit

from ..routes.common import safe_reference
from ..services.audit import MetadataError, sanitize_metadata, sanitize_text
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


class ConnectorAccessError(ValueError):
    """A read-only connector cannot safely provide its snapshot."""


class ReadOnlyConnector(Protocol):
    provider: ProviderName
    tenant_id: str

    def health(self) -> ConnectorHealth: ...

    def inventory(self) -> ProviderSnapshot: ...

    def verify_ownership(self, target: OwnershipTarget) -> OwnershipResult: ...


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
