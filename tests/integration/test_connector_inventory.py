"""Idempotent connector inventory reconciliation tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.contract.test_connectors_api import _connector_payload, _fixture_app
from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    seed_user,
)


def test_inventory_is_idempotent_and_retires_missing_assets() -> None:
    app, transport = _fixture_app()
    user = seed_user(app, "Inventory")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        created = client.post(
            "/v1/connectors", headers=headers, json=_connector_payload(str(application["id"]))
        )
        connector_id = created.json()["id"]

        first = client.post(
            f"/v1/connectors/{connector_id}/inventory",
            headers=headers,
            json={"snapshot_key": "same"},
        )
        second = client.post(
            f"/v1/connectors/{connector_id}/inventory",
            headers=headers,
            json={"snapshot_key": "same"},
        )
        assert first.json()["asset_count"] == second.json()["asset_count"] == 1
        assets = client.get("/v1/assets", headers=headers).json()
        assert len(assets) == 1
        assert assets[0]["status"] == "active"

        transport.fixtures[("github", "inventory")] = {"assets": []}
        third = client.post(
            f"/v1/connectors/{connector_id}/inventory",
            headers=headers,
            json={"snapshot_key": "same"},
        )
        assert third.json()["asset_count"] == 0
        assets = client.get("/v1/assets", headers=headers).json()
        assert assets[0]["status"] == "retired"
