"""Cross-tenant BETA-02 connector isolation tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.contract.test_connectors_api import _connector_payload, _fixture_app
from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    seed_user,
)


def test_foreign_tenant_cannot_check_inventory_or_read_connector_assets() -> None:
    app, _ = _fixture_app()
    owner = seed_user(app, "Owner")
    foreign = seed_user(app, "Foreign")
    with TestClient(app) as client:
        owner_token = issue_token(client, owner.email)
        foreign_token = issue_token(client, foreign.email)
        application = create_application(client, owner_token)
        headers = auth_headers(owner_token)
        created = client.post(
            "/v1/connectors",
            headers=headers,
            json=_connector_payload(str(application["id"])),
        )
        connector_id = created.json()["id"]

        foreign_headers = auth_headers(foreign_token)
        assert (
            client.post(f"/v1/connectors/{connector_id}/check", headers=foreign_headers).status_code
            == 404
        )
        assert (
            client.post(
                f"/v1/connectors/{connector_id}/inventory",
                headers=foreign_headers,
                json={"snapshot_key": "foreign"},
            ).status_code
            == 404
        )
        assert client.get("/v1/assets", headers=foreign_headers).json() == []
