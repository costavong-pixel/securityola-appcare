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
from appcare.inventory.service import normalize_records
from appcare.models import Asset
from tests.control_plane_helpers import create_application, issue_token, new_test_app, seed_user


def _connector(records: tuple[RemoteRecord, ...], tenant_id: str) -> ReadOnlyConnector:
    credential = CredentialMetadata(
        credential_id="vault://fixture/appcare/github-inventory-ref",
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


def test_asset_key_ignores_mutable_display_fields() -> None:
    original = _records()[0]
    changed = RemoteRecord(
        kind=original.kind,
        provider_id=original.provider_id,
        name="Renamed repository",
        locator=original.locator,
        metadata={"default_branch": "develop"},
    )
    first = normalize_records("github", (original,))[0]
    second = normalize_records("github", (changed,))[0]
    assert first.asset_key == second.asset_key


def test_conflicting_provider_identity_fails_before_persistence() -> None:
    original = _records()[0]
    changed = RemoteRecord(
        kind=original.kind,
        provider_id=original.provider_id,
        name="Conflicting repository",
        locator=original.locator,
        metadata=original.metadata,
    )
    app = new_test_app()
    user = seed_user(app, "Conflict")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token)
    connector = _connector((original, changed, _records()[1]), user.tenant_id)

    with app.state.database.session() as session:
        try:
            collect_inventory(
                connector,
                tenant_id=user.tenant_id,
                application_id=str(application["id"]),
                target=OwnershipTarget(expected_resource_id="repo-owner/app"),
                session=session,
            )
        except InventoryError as exc:
            assert str(exc) == "inventory_identity_conflict"
        else:
            raise AssertionError("conflicting provider identity must fail")
        assert session.scalar(select(Asset.id).where(Asset.tenant_id == user.tenant_id)) is None


def test_duplicate_legacy_identity_is_rejected_without_partial_assets() -> None:
    app = new_test_app()
    user = seed_user(app, "DuplicateLegacy")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token)
    with app.state.database.session() as session:
        for _ in range(2):
            session.add(
                Asset(
                    tenant_id=user.tenant_id,
                    application_id=str(application["id"]),
                    kind="deployment",
                    locator="https://preview.example.test/",
                    status="active",
                )
            )
        session.flush()

    connector = _connector(_records(), user.tenant_id)
    with app.state.database.session() as session:
        try:
            collect_inventory(
                connector,
                tenant_id=user.tenant_id,
                application_id=str(application["id"]),
                target=OwnershipTarget(expected_resource_id="repo-owner/app"),
                session=session,
            )
        except InventoryError as exc:
            assert str(exc) == "inventory_identity_conflict"
        else:
            raise AssertionError("duplicate legacy identity must fail")
        assets = list(
            session.scalars(
                select(Asset).where(
                    Asset.tenant_id == user.tenant_id,
                    Asset.application_id == str(application["id"]),
                )
            )
        )
        assert len(assets) == 2
        assert all(asset.provider is None for asset in assets)


def test_canonical_and_legacy_identity_conflict_fails_closed() -> None:
    app = new_test_app()
    user = seed_user(app, "MixedIdentity")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token)
    with app.state.database.session() as session:
        session.add_all(
            [
                Asset(
                    tenant_id=user.tenant_id,
                    application_id=str(application["id"]),
                    provider="github",
                    provider_reference="repo-001",
                    kind="repository",
                    locator="https://github.com/example/app",
                    status="active",
                ),
                Asset(
                    tenant_id=user.tenant_id,
                    application_id=str(application["id"]),
                    kind="repository",
                    locator="https://github.com/example/app",
                    status="active",
                ),
            ]
        )
        session.flush()

    with app.state.database.session() as session:
        try:
            collect_inventory(
                _connector((_records()[0],), user.tenant_id),
                tenant_id=user.tenant_id,
                application_id=str(application["id"]),
                target=OwnershipTarget(expected_resource_id="repo-owner/app"),
                session=session,
            )
        except InventoryError as exc:
            assert str(exc) == "inventory_identity_conflict"
        else:
            raise AssertionError("canonical and legacy identity conflict must fail")
        assert session.scalar(select(Asset.id).where(Asset.provider.is_(None))) is not None
