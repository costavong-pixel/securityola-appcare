"""Durable job state, retry, cost, and transition tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    new_test_app,
    seed_user,
)


def test_job_state_retry_cost_and_failure_fields_are_persisted() -> None:
    app = new_test_app()
    user = seed_user(app, "Jobs")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        created = client.post(
            "/v1/jobs",
            headers=headers,
            json={
                "application_id": application["id"],
                "kind": "scan",
                "cost_amount": "1.250000",
                "cost_currency": "usd",
            },
        )
        assert created.status_code == 201, created.text
        job_id = created.json()["id"]
        assert created.json()["status"] == "queued"
        assert created.json()["cost_currency"] == "USD"

        running = client.patch(
            f"/v1/jobs/{job_id}",
            headers=headers,
            json={"status": "running", "retry_count": 1},
        )
        assert running.status_code == 200, running.text
        assert running.json()["retry_count"] == 1
        failed = client.patch(
            f"/v1/jobs/{job_id}",
            headers=headers,
            json={
                "status": "failed",
                "retry_count": 2,
                "failure_code": "provider_timeout",
                "failure_message": "fixture failure without credentials",
            },
        )
        assert failed.status_code == 200, failed.text
        assert failed.json()["status"] == "failed"
        assert failed.json()["retry_count"] == 2
        assert failed.json()["failure_code"] == "provider_timeout"
        assert failed.json()["failure_message"] == "fixture failure without credentials"


def test_invalid_job_state_transition_retry_and_cost_values_fail_closed() -> None:
    app = new_test_app()
    user = seed_user(app, "Jobs")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        invalid_cost = client.post(
            "/v1/jobs",
            headers=headers,
            json={
                "application_id": application["id"],
                "kind": "scan",
                "cost_amount": "-0.01",
            },
        )
        assert invalid_cost.status_code == 422
        job = client.post(
            "/v1/jobs",
            headers=headers,
            json={"application_id": application["id"], "kind": "scan"},
        ).json()
        job_id = job["id"]

        skip_transition = client.patch(
            f"/v1/jobs/{job_id}", headers=headers, json={"status": "succeeded"}
        )
        decrease_retry = client.patch(
            f"/v1/jobs/{job_id}",
            headers=headers,
            json={"status": "running", "retry_count": -1},
        )
        assert skip_transition.status_code == 422
        assert decrease_retry.status_code == 422
        assert "not allowed" not in skip_transition.text
        assert client.get(f"/v1/jobs/{job_id}", headers=headers).json()["status"] == "queued"


def test_job_failure_fields_reject_credential_like_values_without_echoing_them() -> None:
    app = new_test_app()
    user = seed_user(app, "Jobs")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token)
        job = client.post(
            "/v1/jobs",
            headers=headers,
            json={"application_id": application["id"], "kind": "scan"},
        ).json()
        response = client.patch(
            f"/v1/jobs/{job['id']}",
            headers=headers,
            json={
                "status": "running",
                "failure_message": "Bearer fake-fixture-token-12345678901234567890",
            },
        )
    assert response.status_code == 422
    assert "fake-fixture-token" not in response.text
