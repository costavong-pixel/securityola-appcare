"""Proof that BETA-01 exposes descriptive records, not provider writes."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    new_test_app,
    seed_user,
)


def test_openapi_has_no_execute_sync_or_provider_write_operation() -> None:
    app = new_test_app()
    paths = app.openapi()["paths"]
    forbidden = ("execute", "sync", "provider-write", "deploy-now")
    assert not any(any(word in path.casefold() for word in forbidden) for path in paths)
    assert "/v1/deployments" in paths
    assert all(
        operation.get("operationId", "").casefold().find("execute") < 0
        for path_item in paths.values()
        for operation in path_item.values()
        if isinstance(operation, dict)
    )


def test_operation_records_reject_credentials_and_do_not_execute_external_actions() -> None:
    app = new_test_app()
    user = seed_user(app, "Operations")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        connector = client.post(
            "/v1/connectors",
            headers=headers,
            json={
                "application_id": application["id"],
                "provider": "github",
                "kind": "repository",
                "display_name": "descriptive only",
                "credential": "fake-fixture-credential",
            },
        )
        deployment = client.post(
            "/v1/deployments",
            headers=headers,
            json={
                "application_id": application["id"],
                "environment": "production",
                "revision": "fixture-revision",
                "access_token": "fake-fixture-token",
            },
        )
    assert connector.status_code == 422
    assert deployment.status_code == 422
    assert "fake-fixture" not in connector.text + deployment.text


def test_repository_has_no_provider_sdk_or_deployment_socket_in_control_plane_tree() -> None:
    root = Path(__file__).resolve().parents[2]
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in (root / "appcare").rglob("*.py")
    ).casefold()
    assert "docker.sock" not in source
    assert "ssh_private_key" not in source
    assert "boto3" not in source
    assert "from vercel" not in source
    assert "import vercel" not in source
    for forbidden in (
        "provider_write",
        "execute_sql",
        "deploy_now",
        "delete_remote",
        "mutate_remote",
    ):
        assert forbidden not in source
