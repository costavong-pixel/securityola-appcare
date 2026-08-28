"""Read-only readiness API contract and tenant isolation tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    new_test_app,
    seed_user,
)


def test_readiness_api_requires_authentication() -> None:
    app = new_test_app()
    user = seed_user(app, "Readiness")
    with TestClient(app) as client:
        application = create_application(client, issue_token(client, user.email))
        response = client.get(f"/v1/applications/{application['id']}/readiness")
    assert response.status_code == 401


def test_readiness_api_is_tenant_scoped_and_persisted_only() -> None:
    app = new_test_app()
    first = seed_user(app, "Readiness A")
    second = seed_user(app, "Readiness B")
    with TestClient(app) as client:
        first_token = issue_token(client, first.email)
        second_token = issue_token(client, second.email)
        application = create_application(client, first_token, "Readiness app")

        own = client.get(
            f"/v1/applications/{application['id']}/readiness",
            headers=auth_headers(first_token),
        )
        foreign = client.get(
            f"/v1/applications/{application['id']}/readiness",
            headers=auth_headers(second_token),
        )

    assert own.status_code == 200
    assert own.json()["state_source"] == "persisted"
    assert own.json()["live_customer_production_enabled"] is False
    assert own.json()["levels"] == []
    assert foreign.status_code == 404
