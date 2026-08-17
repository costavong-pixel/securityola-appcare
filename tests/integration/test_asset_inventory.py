"""Tenant-safe, deterministic, idempotent AppCare asset inventory tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from appcare.connectors import (
    CredentialMetadata,
    OwnershipTarget,
    ProviderSnapshot,
    ReadOnlyConnector,
    RemoteRecord,
    build_fixture_connector,
)
from appcare.inventory import InventoryError, collect_inventory
from appcare.models import Asset
from tests.control_plane_helpers import create_application, issue_token, new_test_app, seed_user


def _connector(records: tuple[RemoteRecord, ...], tenant_id: str) -> ReadOnlyConnector:
    credential = CredentialMetadata(
        credential_id="github-inventory-ref",
        provider="github",
        tenant_id=tenant_id,
        scopes=(
            "repository.metadata.read",
            "repository.contents.read",
            "pull_request.metadata.read",
        ),
    )
    snapshot = ProviderSnapshot(
        provider="github",
        resource_id="repo-owner/app",
        domains=("app.example.test",),
        records=records,
    )
    return build_fixture_connector("github", credential, snapshot)


def _records() -> tuple[RemoteRecord, ...]:
    first = RemoteRecord(
        kind="repository",
        provider_id="repo-001",
        name="App repository",
        locator="https://github.com/example/app",
        metadata={"default_branch": "main"},
    )
    second = RemoteRecord(
        kind="deployment",
        provider_id="deploy-001",
        name="Preview deployment",
        locator="https://preview.example.test",
        metadata={"status": "ready"},
    )
    return first, second, first


def test_replaying_inventory_is_sorted_deduplicated_and_idempotent() -> None:
    app = new_test_app()
    user = seed_user(app, "Inventory")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token)
    connector = _connector(_records(), user.tenant_id)
    target = OwnershipTarget(expected_resource_id="repo-owner/app", expected_domain="example.test")

    with app.state.database.session() as session:
        first = collect_inventory(
            connector,
            tenant_id=user.tenant_id,
            application_id=str(application["id"]),
            target=target,
            session=session,
        )
    reordered_connector = _connector(tuple(reversed(_records())), user.tenant_id)
    with app.state.database.session() as session:
        second = collect_inventory(
            reordered_connector,
            tenant_id=user.tenant_id,
            application_id=str(application["id"]),
            target=target,
            session=session,
        )
        assets = list(
            session.scalars(
                select(Asset).where(
                    Asset.tenant_id == user.tenant_id,
                    Asset.application_id == str(application["id"]),
                )
            )
        )

    assert first.digest == second.digest
    assert [asset.asset_key for asset in first.assets] == [
        asset.asset_key for asset in second.assets
    ]
    assert len(first.assets) == 2
    assert len(assets) == 2


def test_ownership_failure_does_not_persist_local_assets() -> None:
    app = new_test_app()
    user = seed_user(app, "Ownership")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token)
    connector = _connector(_records(), user.tenant_id)

    with app.state.database.session() as session:
        try:
            collect_inventory(
                connector,
                tenant_id=user.tenant_id,
                application_id=str(application["id"]),
                target=OwnershipTarget(expected_domain="attacker.example.test"),
                session=session,
            )
        except InventoryError as exc:
            assert str(exc) == "domain_mismatch"
        else:
            raise AssertionError("ownership mismatch must fail")
        assert session.scalar(select(Asset.id).where(Asset.tenant_id == user.tenant_id)) is None


def test_foreign_tenant_cannot_reconcile_an_application() -> None:
    app = new_test_app()
    owner = seed_user(app, "Owner")
    foreign = seed_user(app, "Foreign")
    with TestClient(app) as client:
        owner_token = issue_token(client, owner.email)
        application = create_application(client, owner_token)
    connector = _connector(_records(), owner.tenant_id)

    with app.state.database.session() as session:
        try:
            collect_inventory(
                connector,
                tenant_id=foreign.tenant_id,
                application_id=str(application["id"]),
                target=OwnershipTarget(expected_resource_id="repo-owner/app"),
                session=session,
            )
        except InventoryError as exc:
            assert str(exc) == "credential_not_owned"
        else:
            raise AssertionError("foreign tenant reconciliation must fail")
        assert session.scalar(select(Asset.id).where(Asset.tenant_id == foreign.tenant_id)) is None


def test_legacy_locator_is_upgraded_to_canonical_provider_identity() -> None:
    app = new_test_app()
    user = seed_user(app, "LegacyAsset")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token)

    with app.state.database.session() as session:
        session.add(
            Asset(
                tenant_id=user.tenant_id,
                application_id=str(application["id"]),
                kind="repository",
                locator="https://github.com/example/app",
                status="active",
            )
        )
        session.flush()

    connector = _connector((_records()[0],), user.tenant_id)
    with app.state.database.session() as session:
        result = collect_inventory(
            connector,
            tenant_id=user.tenant_id,
            application_id=str(application["id"]),
            target=OwnershipTarget(expected_resource_id="repo-owner/app"),
            session=session,
        )
        assets = list(
            session.scalars(
                select(Asset).where(
                    Asset.tenant_id == user.tenant_id,
                    Asset.application_id == str(application["id"]),
                )
            )
        )

    assert len(result.assets) == 1
    assert len(assets) == 1
    assert assets[0].provider == "github"
    assert assets[0].provider_reference == "repo-001"
