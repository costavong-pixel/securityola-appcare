"""Integration-level negative tests for the supported-stack connector boundary."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta

import pytest

from appcare.connectors import (
    PROVIDER_SPECS,
    ConnectorAccessError,
    CredentialMetadata,
    OwnershipTarget,
    ProviderSnapshot,
    RemoteRecord,
    build_fixture_connector,
)

_TENANT_ID = "a" * 32


def _snapshot(provider: str) -> ProviderSnapshot:
    return ProviderSnapshot(
        provider=provider,  # type: ignore[arg-type]
        resource_id="resource-001",
        domains=("app.example.test",),
        records=(
            RemoteRecord(
                kind="project",
                provider_id="project-001",
                name="Fixture project",
                locator=f"https://{provider}.example.test/project-001",
                metadata={"environment": "fixture"},
            ),
        ),
    )


def _credential(provider: str, *, expires_at: datetime | None = None) -> CredentialMetadata:
    return CredentialMetadata(
        credential_id=f"vault://fixture/appcare/{provider}-integration-ref",
        provider=provider,  # type: ignore[arg-type]
        tenant_id=_TENANT_ID,
        scopes=PROVIDER_SPECS[provider].required_capabilities,  # type: ignore[index]
        expires_at=expires_at,
    )


@pytest.mark.parametrize("provider", tuple(PROVIDER_SPECS))
def test_supported_connectors_have_safe_health_and_inventory(provider: str) -> None:
    connector = build_fixture_connector(provider, _credential(provider), _snapshot(provider))
    health = connector.health()
    assert health.usable
    assert connector.inventory().records[0].provider_id == "project-001"
    assert "integration-ref" not in repr(health)


def test_missing_scope_fails_before_inventory() -> None:
    required = PROVIDER_SPECS["vercel"].required_capabilities
    connector = build_fixture_connector(
        "vercel",
        CredentialMetadata(
            credential_id="vault://fixture/appcare/vercel-under-scoped-ref",
            provider="vercel",
            tenant_id=_TENANT_ID,
            scopes=required[:-1],
        ),
        _snapshot("vercel"),
    )
    health = connector.health()
    assert not health.usable
    assert health.reason == "missing_capability"
    assert health.missing_capabilities == ("team.read",)
    with pytest.raises(ConnectorAccessError, match="missing_capability"):
        connector.inventory()


def test_expired_and_revoked_credentials_fail_without_provider_payload() -> None:
    expired = build_fixture_connector(
        "supabase",
        _credential("supabase", expires_at=datetime.now(UTC) - timedelta(seconds=1)),
        _snapshot("supabase"),
    )
    revoked_metadata = _credential("supabase")
    revoked = build_fixture_connector(
        "supabase",
        CredentialMetadata(
            credential_id=revoked_metadata.credential_id,
            provider="supabase",
            tenant_id=_TENANT_ID,
            scopes=revoked_metadata.scopes,
            revoked_at=datetime.now(UTC),
        ),
        _snapshot("supabase"),
    )
    for connector, reason in ((expired, "expired_credential"), (revoked, "revoked_credential")):
        assert connector.health().reason == reason
        with pytest.raises(ConnectorAccessError, match=reason):
            connector.inventory()


def test_ownership_mismatch_fails_closed() -> None:
    connector = build_fixture_connector("github", _credential("github"), _snapshot("github"))
    wrong_resource = connector.verify_ownership(
        OwnershipTarget(
            expected_resource_id="different-resource",
            expected_domain="app.example.test",
        )
    )
    wrong_domain = connector.verify_ownership(
        OwnershipTarget(
            expected_resource_id="resource-001",
            expected_domain="other.example.test",
        )
    )
    missing = connector.verify_ownership(OwnershipTarget())
    assert (wrong_resource.verified, wrong_resource.reason) == (False, "resource_mismatch")
    assert (wrong_domain.verified, wrong_domain.reason) == (False, "domain_mismatch")
    assert (missing.verified, missing.reason) == (False, "missing_target")


def test_connector_classes_have_no_provider_write_surface() -> None:
    from appcare.connectors.base import (
        FixtureReadOnlyConnector,
        GitHubReadOnlyConnector,
        SupabaseReadOnlyConnector,
        VercelReadOnlyConnector,
    )

    for connector_type in (
        FixtureReadOnlyConnector,
        GitHubReadOnlyConnector,
        VercelReadOnlyConnector,
        SupabaseReadOnlyConnector,
    ):
        methods = {
            name
            for name, member in inspect.getmembers(connector_type, inspect.isfunction)
            if not name.startswith("_")
        }
        assert methods == {"health", "inventory", "verify_ownership"}
        assert not any(
            any(marker in method.casefold() for marker in ("deploy", "delete", "write", "execute"))
            for method in methods
        )
