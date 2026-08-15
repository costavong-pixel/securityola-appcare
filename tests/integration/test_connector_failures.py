"""Fail-closed BETA-02 connector failure tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from appcare.models import AuditEvent
from tests.contract.test_connectors_api import _connector_payload, _fixture_app
from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    seed_user,
)


def test_expired_credential_fails_without_provider_requests() -> None:
    app, transport = _fixture_app()
    user = seed_user(app, "Expired")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        payload = {
            **_connector_payload(str(application["id"])),
            "credential_expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        }
        created = client.post("/v1/connectors", headers=headers, json=payload)
        connector_id = created.json()["id"]
        checked = client.post(f"/v1/connectors/{connector_id}/check", headers=headers)
    assert checked.json()["overall_status"] == "failed"
    assert checked.json()["reason_codes"] == ["credential_expired"]
    assert transport.requests == []


def test_ownership_mismatch_persists_no_new_assets() -> None:
    app, transport = _fixture_app()
    user = seed_user(app, "Mismatch")
    transport.fixtures[("github", "ownership")] = {
        "resource_reference": "other/app",
        "owner_reference": "other-owner",
        "credential_owner_reference": "other-owner",
    }
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        created = client.post(
            "/v1/connectors", headers=headers, json=_connector_payload(str(application["id"]))
        )
        connector_id = created.json()["id"]
        result = client.post(
            f"/v1/connectors/{connector_id}/inventory",
            headers=headers,
            json={"snapshot_key": "mismatch"},
        )
        assert result.json()["status"] == "failed"
        assert result.json()["asset_count"] == 0
        assert client.get("/v1/assets", headers=headers).json() == []


def test_revoked_credential_fails_without_echoing_metadata() -> None:
    app, transport = _fixture_app()
    user = seed_user(app, "Revoked")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        payload = {
            **_connector_payload(str(application["id"])),
            "credential_status": "revoked",
            "credential_reference": "fixture-revoked-reference",
        }
        created = client.post("/v1/connectors", headers=headers, json=payload)
        checked = client.post(f"/v1/connectors/{created.json()['id']}/check", headers=headers)
    assert checked.json()["reason_codes"] == ["credential_revoked"]
    assert transport.requests == []


def test_secret_shaped_inventory_fails_without_asset_or_audit_echo() -> None:
    app, transport = _fixture_app()
    user = seed_user(app, "SecretObservation")
    poison = "Bearer fake-fixture-token-not-live"
    transport.fixtures[("github", "inventory")] = {
        "assets": [
            {
                "provider_reference": "example/appcare",
                "kind": "repository",
                "display_name": poison,
                "locator": "https://github.com/example/appcare",
                "metadata": {},
            }
        ]
    }
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        created = client.post(
            "/v1/connectors",
            headers=headers,
            json=_connector_payload(str(application["id"])),
        )
        result = client.post(
            f"/v1/connectors/{created.json()['id']}/inventory",
            headers=headers,
            json={"snapshot_key": "secret-observation"},
        )
        assert result.json()["status"] == "failed"
        assert result.json()["failure_code"] == "inventory_evidence_malformed"
        assert poison not in result.text
        assert client.get("/v1/assets", headers=headers).json() == []

    with app.state.database.session_factory() as session:
        events = list(session.query(AuditEvent).all())
        assert poison not in str([event.metadata_json for event in events])
