"""Unit tests for provider capabilities and metadata-only credentials."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta

import pytest

from appcare.connectors import (
    PROVIDER_SPECS,
    CredentialLifecycleError,
    CredentialMetadata,
    CredentialRegistry,
    ProviderSnapshot,
    RemoteRecord,
    build_fixture_connector,
)
from appcare.connectors.providers import validate_capabilities

_TENANT_ID = "a" * 32


def _credential(provider: str, *, scopes: tuple[str, ...] | None = None) -> CredentialMetadata:
    spec = PROVIDER_SPECS[provider]  # type: ignore[index]
    return CredentialMetadata(
        credential_id=f"vault://fixture/appcare/{provider}-ref-0001",
        provider=provider,  # type: ignore[arg-type]
        tenant_id=_TENANT_ID,
        scopes=scopes or spec.required_capabilities,
    )


def _snapshot(provider: str) -> ProviderSnapshot:
    return ProviderSnapshot(
        provider=provider,  # type: ignore[arg-type]
        resource_id="resource-001",
        domains=("app.example.test",),
        records=(
            RemoteRecord(
                kind="project",
                provider_id="record-001",
                name="Fixture project",
                locator=f"https://{provider}.example.test/project-001",
                metadata={"region": "fixture"},
            ),
        ),
    )


def test_all_supported_providers_require_read_only_capabilities() -> None:
    for provider, spec in PROVIDER_SPECS.items():
        result = validate_capabilities(provider, spec.required_capabilities)
        assert result.allowed
        assert not result.forbidden_capabilities
        assert not any("write" in capability for capability in spec.required_capabilities)


def test_write_shaped_capability_is_rejected() -> None:
    result = validate_capabilities(
        "github", (*PROVIDER_SPECS["github"].required_capabilities, "repository.contents.write")
    )
    assert not result.allowed
    assert result.reason == "forbidden_capability"
    assert result.forbidden_capabilities == ("repository.contents.write",)


@pytest.mark.parametrize("provider", tuple(PROVIDER_SPECS))
def test_complete_fixture_connector_reports_healthy(provider: str) -> None:
    connector = build_fixture_connector(provider, _credential(provider), _snapshot(provider))
    health = connector.health()
    assert health.usable
    assert health.credential_status == "active"
    assert connector.inventory().provider == provider


def test_expired_and_revoked_credentials_fail_closed() -> None:
    expired = CredentialMetadata(
        credential_id="vault://fixture/appcare/github-ref-expired",
        provider="github",
        tenant_id=_TENANT_ID,
        scopes=PROVIDER_SPECS["github"].required_capabilities,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    revoked = CredentialMetadata(
        credential_id="vault://fixture/appcare/github-ref-revoked",
        provider="github",
        tenant_id=_TENANT_ID,
        scopes=PROVIDER_SPECS["github"].required_capabilities,
        revoked_at=datetime.now(UTC),
    )
    for credential, reason in ((expired, "expired_credential"), (revoked, "revoked_credential")):
        connector = build_fixture_connector("github", credential, _snapshot("github"))
        health = connector.health()
        assert not health.usable
        assert health.reason == reason
        assert credential.credential_id not in repr(health)
        with pytest.raises(ValueError, match=reason):
            connector.inventory()


@pytest.mark.parametrize(
    "credential_id",
    (
        "github-token-0001",
        "gho_1234567890abcdefghijklmnop",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123",
        "vault://gho_1234567890abcdefghijklmnop",
        "vault://eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123",
        "vault://fixture/appcare/token-0001",
    ),
)
def test_malformed_or_secret_shaped_reference_is_rejected(credential_id: str) -> None:
    registry = CredentialRegistry()
    with pytest.raises(CredentialLifecycleError):
        registry.register(
            CredentialMetadata(
                credential_id=credential_id,
                provider="github",
                tenant_id=_TENANT_ID,
                scopes=PROVIDER_SPECS["github"].required_capabilities,
            )
        )


def test_fixture_connector_rejects_wrapped_token_reference() -> None:
    credential = CredentialMetadata(
        credential_id="vault://gho_1234567890abcdefghijklmnop",
        provider="github",
        tenant_id=_TENANT_ID,
        scopes=PROVIDER_SPECS["github"].required_capabilities,
    )
    connector = build_fixture_connector("github", credential, _snapshot("github"))
    assert credential.status() == "invalid"
    assert not connector.health().usable
    assert connector.health().reason == "invalid_credential"


def test_credential_registry_rotates_and_revokes_without_raw_secret_state() -> None:
    registry = CredentialRegistry()
    original = _credential("github")
    registry.register(original)
    replacement = CredentialMetadata(
        credential_id="vault://fixture/appcare/github-ref-0002",
        provider="github",
        tenant_id=_TENANT_ID,
        scopes=original.scopes,
        version=2,
    )
    registry.rotate(
        tenant_id=_TENANT_ID,
        old_credential_id=original.credential_id,
        replacement=replacement,
    )
    assert (
        registry.get(tenant_id=_TENANT_ID, credential_id=original.credential_id).status()
        == "revoked"
    )
    assert (
        registry.get(tenant_id=_TENANT_ID, credential_id=replacement.credential_id).status()
        == "active"
    )
    with pytest.raises(CredentialLifecycleError):
        registry.rotate(
            tenant_id=_TENANT_ID,
            old_credential_id=replacement.credential_id,
            replacement=replacement,
        )
    assert (
        "secret"
        not in repr(
            registry.get(tenant_id=_TENANT_ID, credential_id=replacement.credential_id)
        ).casefold()
    )


def test_credential_registry_is_tenant_scoped() -> None:
    registry = CredentialRegistry()
    registry.register(_credential("github"))
    other_tenant = "b" * 32
    other = CredentialMetadata(
        credential_id="vault://fixture/appcare/github-ref-0001",
        provider="github",
        tenant_id=other_tenant,
        scopes=PROVIDER_SPECS["github"].required_capabilities,
    )
    registry.register(other)
    assert registry.get(tenant_id=other_tenant, credential_id=other.credential_id) == other
    with pytest.raises(CredentialLifecycleError):
        registry.get(
            tenant_id=other_tenant, credential_id="vault://fixture/appcare/github-ref-missing"
        )


def test_inventory_redacts_secret_named_metadata_without_returning_raw_value() -> None:
    snapshot = ProviderSnapshot(
        provider="github",
        resource_id="resource-001",
        domains=("app.example.test",),
        records=(
            RemoteRecord(
                kind="repository",
                provider_id="repo-001",
                name="Fixture repo",
                locator="https://github.example.test/repo-001",
                metadata={"api_key": "fixture-value", "branch": "main"},
            ),
        ),
    )
    connector = build_fixture_connector("github", _credential("github"), snapshot)
    record = connector.inventory().records[0]
    assert record.metadata["api_key"] == "[REDACTED]"
    assert "fixture-value" not in repr(record)


def test_public_connector_surface_is_read_only() -> None:
    from appcare.connectors.base import FixtureReadOnlyConnector

    public_methods = {
        name
        for name, member in inspect.getmembers(FixtureReadOnlyConnector, inspect.isfunction)
        if not name.startswith("_")
    }
    assert public_methods == {"health", "inventory", "verify_ownership"}
