"""Cross-tenant denial tests for every BETA-01 tenant-owned surface."""

from __future__ import annotations

from fastapi.testclient import TestClient

from appcare.models import AuditEvent
from appcare.services.audit import append_event
from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    new_test_app,
    seed_user,
)


def test_each_tenant_sees_only_its_resources_and_operation_records() -> None:
    app = new_test_app()
    tenant_a = seed_user(app, "TenantA")
    tenant_b = seed_user(app, "TenantB")
    with TestClient(app) as client:
        token_a = issue_token(client, tenant_a.email)
        token_b = issue_token(client, tenant_b.email)
        headers_a = auth_headers(token_a)
        headers_b = auth_headers(token_b)
        application_a = create_application(client, token_a, "A app")
        application_b = create_application(client, token_b, "B app")

        asset_a = client.post(
            "/v1/assets",
            headers=headers_a,
            json={
                "application_id": application_a["id"],
                "kind": "site",
                "locator": "https://a.example.test",
            },
        ).json()
        finding_a = client.post(
            "/v1/findings",
            headers=headers_a,
            json={
                "application_id": application_a["id"],
                "asset_id": asset_a["id"],
                "severity": "medium",
                "title": "A finding",
                "summary": "A test finding",
                "fingerprint": "a-finding-fingerprint",
            },
        ).json()
        job_a = client.post(
            "/v1/jobs",
            headers=headers_a,
            json={"application_id": application_a["id"], "kind": "scan"},
        ).json()
        connector_a = client.post(
            "/v1/connectors",
            headers=headers_a,
            json={
                "application_id": application_a["id"],
                "provider": "github",
                "kind": "repository",
                "display_name": "A GitHub description",
            },
        ).json()
        backup_a = client.post(
            "/v1/backups",
            headers=headers_a,
            json={"application_id": application_a["id"], "provider": "local-fixture"},
        ).json()
        approval_a = client.post(
            "/v1/approvals",
            headers=headers_a,
            json={"application_id": application_a["id"], "kind": "staging-check"},
        ).json()
        deployment_a = client.post(
            "/v1/deployments",
            headers=headers_a,
            json={
                "application_id": application_a["id"],
                "environment": "staging",
                "revision": "fixture-revision",
            },
        ).json()

        with app.state.database.session_factory() as session:
            event = append_event(
                session,
                tenant_id=tenant_a.tenant_id,
                actor_user_id=tenant_a.user_id,
                action="tenant-a.fixture",
                subject_type="application",
                subject_id=str(application_a["id"]),
                outcome="success",
                metadata={"safe": "fixture"},
            )
            session.commit()
            event_a_id = event.id

        own_listings = {
            "/v1/applications": application_a["id"],
            "/v1/assets": asset_a["id"],
            "/v1/findings": finding_a["id"],
            "/v1/jobs": job_a["id"],
            "/v1/connectors": connector_a["id"],
            "/v1/backups": backup_a["id"],
            "/v1/approvals": approval_a["id"],
            "/v1/deployments": deployment_a["id"],
        }
        for path, expected_id in own_listings.items():
            assert any(
                item["id"] == expected_id for item in client.get(path, headers=headers_a).json()
            )
            assert all(
                item["id"] != expected_id for item in client.get(path, headers=headers_b).json()
            )

        foreign_routes = {
            "/v1/applications": application_a["id"],
            "/v1/assets": asset_a["id"],
            "/v1/findings": finding_a["id"],
            "/v1/jobs": job_a["id"],
            "/v1/connectors": connector_a["id"],
            "/v1/backups": backup_a["id"],
            "/v1/approvals": approval_a["id"],
            "/v1/deployments": deployment_a["id"],
        }
        for path, record_id in foreign_routes.items():
            assert client.get(f"{path}/{record_id}", headers=headers_b).status_code == 404

        assert client.get("/v1/audit-events", headers=headers_a).json()
        assert all(
            event["id"] != event_a_id
            for event in client.get("/v1/audit-events", headers=headers_b).json()
        )
        assert (
            client.get(f"/v1/applications/{application_b['id']}", headers=headers_a).status_code
            == 404
        )


def test_cross_tenant_asset_and_finding_creation_cannot_use_a_foreign_application() -> None:
    app = new_test_app()
    tenant_a = seed_user(app, "TenantA")
    tenant_b = seed_user(app, "TenantB")
    with TestClient(app) as client:
        token_a = issue_token(client, tenant_a.email)
        token_b = issue_token(client, tenant_b.email)
        application_a = create_application(client, token_a)
        headers_b = auth_headers(token_b)

        asset = client.post(
            "/v1/assets",
            headers=headers_b,
            json={
                "application_id": application_a["id"],
                "kind": "site",
                "locator": "https://foreign.example.test",
            },
        )
        finding = client.post(
            "/v1/findings",
            headers=headers_b,
            json={
                "application_id": application_a["id"],
                "severity": "low",
                "title": "foreign",
                "summary": "foreign",
                "fingerprint": "foreign-fingerprint",
            },
        )
    assert asset.status_code == 404
    assert finding.status_code == 404


def test_audit_route_is_read_only_and_has_no_cross_tenant_detail_or_mutation_surface() -> None:
    app = new_test_app()
    tenant = seed_user(app, "AuditTenant")
    with TestClient(app) as client:
        token = issue_token(client, tenant.email)
        response = client.post(
            "/v1/audit-events",
            headers=auth_headers(token),
            json={"action": "forbidden"},
        )
        assert response.status_code in {404, 405}
        paths = app.openapi()["paths"]
        assert "/v1/audit-events/{event_id}" not in paths
        assert all(
            "/audit-events" not in path or "put" not in methods for path, methods in paths.items()
        )

    with app.state.database.session_factory() as session:
        assert session.query(AuditEvent).count() == 0
