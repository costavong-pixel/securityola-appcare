"""Descriptive connector, backup, approval, and deployment contracts."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    new_test_app,
    seed_user,
)


def test_operation_records_are_tenant_scoped_and_descriptive_only() -> None:
    app = new_test_app()
    user = seed_user(app, "Operations")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        payloads = {
            "/v1/connectors": {
                "application_id": application["id"],
                "provider": "github",
                "kind": "repository",
                "display_name": "GitHub description",
            },
            "/v1/backups": {
                "application_id": application["id"],
                "provider": "local-fixture",
                "artifact_reference": "fixture://backup/app-1",
            },
            "/v1/approvals": {
                "application_id": application["id"],
                "kind": "staging-check",
            },
            "/v1/deployments": {
                "application_id": application["id"],
                "environment": "staging",
                "revision": "fixture-revision",
            },
        }
        for path, payload in payloads.items():
            created = client.post(path, headers=headers, json=payload)
            assert created.status_code == 201, created.text
            item = created.json()
            assert item["tenant_id"] == user.tenant_id
            assert "credential" not in str(item).casefold()
            assert "token" not in str(item).casefold()
            fetched = client.get(f"{path}/{item['id']}", headers=headers)
            assert fetched.status_code == 200


def test_operation_references_reject_foreign_application_and_credential_bearing_urls() -> None:
    app = new_test_app()
    owner = seed_user(app, "Owner")
    foreign = seed_user(app, "Foreign")
    with TestClient(app) as client:
        owner_token = issue_token(client, owner.email)
        foreign_token = issue_token(client, foreign.email)
        application = create_application(client, owner_token)
        headers = auth_headers(foreign_token)
        connector = client.post(
            "/v1/connectors",
            headers=headers,
            json={
                "application_id": application["id"],
                "provider": "github",
                "kind": "repository",
                "display_name": "foreign",
            },
        )
        backup = client.post(
            "/v1/backups",
            headers=auth_headers(owner_token),
            json={
                "application_id": application["id"],
                "provider": "fixture",
                "artifact_reference": "https://user:password@example.test/backup",
            },
        )
    assert connector.status_code == 404
    assert backup.status_code == 422
    assert "password" not in backup.text.casefold()
