from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from appcare.models import Backup, Deployment, Finding
from appcare.monitoring import (
    MonitoringEngine,
    MonitorTarget,
    Observation,
    SqlAlchemyMonitoringStore,
)
from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    new_test_app,
    seed_user,
)


def test_dashboard_requires_authentication() -> None:
    app = new_test_app()
    with TestClient(app) as client:
        response = client.get("/dashboard/state")
    assert response.status_code == 401


def test_dashboard_is_tenant_scoped() -> None:
    app = new_test_app()
    first = seed_user(app, "First")
    second = seed_user(app, "Second")
    with TestClient(app) as client:
        first_token = issue_token(client, first.email)
        second_token = issue_token(client, second.email)
        create_application(client, first_token, "First tenant application")
        first_response = client.get("/dashboard/state", headers=auth_headers(first_token))
        second_response = client.get("/dashboard/state", headers=auth_headers(second_token))

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_response.json()["application_count"] == 1
    assert second_response.json()["application_count"] == 0
    assert second_response.json()["overall_status"] == "empty"


def test_dashboard_reports_real_empty_backend_state() -> None:
    app = new_test_app()
    user = seed_user(app, "Empty")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        response = client.get("/dashboard/state", headers=auth_headers(token))

    assert response.status_code == 200
    payload = response.json()
    assert payload["state_source"] == "backend"
    assert payload["overall_status"] == "empty"
    assert payload["application_count"] == 0
    assert payload["production"]["enabled"] is False
    assert payload["production"]["reason_code"] == "BETA06_LIVE_PREVIEW_REQUIRED"


def test_dashboard_aggregates_persisted_records_without_exposing_credentials() -> None:
    app = new_test_app()
    user = seed_user(app, "Tenant")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token, "Recorded application")

    database = app.state.database
    with database.session_factory() as session:
        session.add(
            Finding(
                tenant_id=user.tenant_id,
                application_id=str(application["id"]),
                severity="high",
                status="open",
                title="Review connector scope",
                summary="A bounded review is required.",
                fingerprint="finding-dashboard-1",
            )
        )
        session.add(
            Backup(
                tenant_id=user.tenant_id,
                application_id=str(application["id"]),
                status="requested",
                provider="test-backup",
                artifact_reference="opaque-reference",
            )
        )
        session.add(
            Deployment(
                tenant_id=user.tenant_id,
                application_id=str(application["id"]),
                environment="staging",
                status="requested",
                requested_by=user.user_id,
                revision="reviewed-revision",
            )
        )
        session.commit()

    monitoring_target = MonitorTarget(
        tenant_id=user.tenant_id,
        application_id=str(application["id"]),
        environment="development",
        app_reference="dashboard-monitor-app",
    )
    MonitoringEngine(
        SqlAlchemyMonitoringStore(database.session_factory, target=monitoring_target)
    ).observe(
        Observation(
            target=monitoring_target,
            check_kind="uptime",
            status="failed",
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            evidence_ref="dashboard-outage",
            summary="synthetic monitoring failure",
            reason_code="outage",
        )
    )

    with TestClient(app) as client:
        response = client.get("/dashboard/state", headers=auth_headers(token))

    assert response.status_code == 200
    payload = response.json()
    assert payload["state_source"] == "backend"
    assert payload["application_count"] == 1
    assert payload["findings"]["open"] == 1
    assert payload["findings"]["high"] == 1
    assert payload["backup"]["status"] == "pending"
    assert payload["deployments"]["status"] == "pending"
    assert payload["monitoring"]["status"] == "attention"
    assert payload["monitoring"]["last_event_at"] is not None
    assert payload["overall_status"] == "attention"
    assert "credential" not in response.text.casefold()
    assert "password" not in response.text.casefold()


def test_public_shells_and_assets_have_explicit_states() -> None:
    app = new_test_app()
    with TestClient(app) as client:
        home = client.get("/")
        dashboard = client.get("/dashboard")
        styles = client.get("/static/styles.css")
        script = client.get("/static/dashboard.js")

    assert home.status_code == 200
    assert dashboard.status_code == 200
    assert styles.status_code == 200
    assert script.status_code == 200
    assert "aria-live" in dashboard.text
    assert "loading-state" in dashboard.text
    assert "empty-state" in dashboard.text
    assert "error-state" in dashboard.text
    assert 'state_source !== "backend"' in script.text
    assert "mock" not in (home.text + dashboard.text + script.text).casefold()
    assert "linear-gradient" not in styles.text
    assert "oklch(" in styles.text


def test_dashboard_timestamp_is_timezone_aware() -> None:
    app = new_test_app()
    user = seed_user(app, "Clock")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        snapshot = client.get("/dashboard/state", headers=auth_headers(token)).json()

    captured = datetime.fromisoformat(snapshot["captured_at"])
    assert captured.tzinfo is not None
    assert captured.utcoffset() is not None
