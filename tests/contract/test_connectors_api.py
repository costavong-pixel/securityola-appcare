"""BETA-02 connector HTTP contracts."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from appcare.api import create_app
from appcare.config import Settings
from appcare.connectors import ConnectorRegistry, FixtureTransport
from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    seed_user,
)


def _fixture_app() -> tuple[FastAPI, FixtureTransport]:
    transport = FixtureTransport(
        {
            ("github", "health"): {"ok": True},
            ("github", "permissions"): {"scopes": ["metadata:read"]},
            (
                "github",
                "ownership",
            ): {
                "resource_reference": "example/appcare",
                "owner_reference": "owner",
                "credential_owner_reference": "owner",
            },
            (
                "github",
                "inventory",
            ): {
                "assets": [
                    {
                        "provider_reference": "example/appcare",
                        "kind": "repository",
                        "display_name": "AppCare source",
                        "locator": "https://github.com/example/appcare",
                        "metadata": {"status": "active"},
                    }
                ]
            },
        }
    )
    app = create_app(
        settings=Settings(database_url="sqlite+pysqlite:///:memory:", environment="test"),
        connector_registry=ConnectorRegistry(transport=transport),
    )
    return app, transport


def _connector_payload(application_id: str) -> dict[str, object]:
    return {
        "application_id": application_id,
        "provider": "github",
        "kind": "repository",
        "display_name": "AppCare source",
        "resource_reference": "example/appcare",
        "owner_reference": "owner",
        "scopes": ["metadata:read"],
        "credential_reference": "vault://fixture/appcare/github-read",
        "credential_authority": "appcare-secret-service",
    }


def test_connector_check_and_inventory_are_safe_and_strict() -> None:
    app, transport = _fixture_app()
    user = seed_user(app, "Connector")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token)
        headers = auth_headers(token)
        created = client.post(
            "/v1/connectors", headers=headers, json=_connector_payload(str(application["id"]))
        )
        assert created.status_code == 201, created.text
        connector = created.json()
        assert connector["credential_reference"] == "[CONFIGURED]"
        assert "token" not in created.text.casefold()

        checked = client.post(f"/v1/connectors/{connector['id']}/check", headers=headers)
        assert checked.status_code == 200, checked.text
        assert checked.json()["overall_status"] == "passed"

        inventory = client.post(
            f"/v1/connectors/{connector['id']}/inventory",
            headers=headers,
            json={"snapshot_key": "current"},
        )
        assert inventory.status_code == 200, inventory.text
        assert inventory.json()["status"] == "succeeded"
        assert inventory.json()["asset_count"] == 1
        assert len(transport.requests) == 8

        invalid = client.post(
            "/v1/connectors",
            headers=headers,
            json={**_connector_payload(str(application["id"])), "token": "fake-live-token"},
        )
        assert invalid.status_code == 422
        assert "fake-live-token" not in invalid.text


def test_connector_without_live_transport_fails_closed() -> None:
    app = create_app(
        settings=Settings(database_url="sqlite+pysqlite:///:memory:", environment="test")
    )
    user = seed_user(app, "Unavailable")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token)
        headers = auth_headers(token)
        created = client.post(
            "/v1/connectors",
            headers=headers,
            json=_connector_payload(str(application["id"])),
        )
        connector_id = created.json()["id"]
        checked = client.post(f"/v1/connectors/{connector_id}/check", headers=headers)
    assert checked.status_code == 200
    assert checked.json()["overall_status"] == "failed"
    assert checked.json()["reason_codes"] == ["provider_transport_unavailable"]


def test_openapi_has_no_connector_mutation_operations() -> None:
    app, _ = _fixture_app()
    paths = {
        path: methods for path, methods in app.openapi()["paths"].items() if "/connectors" in path
    }
    assert not any(
        any(word in path.casefold() for word in ("deploy", "delete", "mutate", "execute"))
        for path in paths
    )
