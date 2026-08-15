"""Restart durability checks using one isolated SQLite file."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from tests.control_plane_helpers import (
    auth_headers,
    create_application,
    issue_token,
    new_test_app,
    seed_user,
    sqlite_file_url,
)


def test_resources_jobs_and_audit_survive_a_database_restart(tmp_path: Path) -> None:
    database_url = sqlite_file_url(tmp_path)
    app = new_test_app(database_url)
    user = seed_user(app, "Restart")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        headers = auth_headers(token)
        application = create_application(client, token, "Durable application")
        asset = client.post(
            "/v1/assets",
            headers=headers,
            json={
                "application_id": application["id"],
                "kind": "site",
                "locator": "https://durable.example.test",
            },
        ).json()
        job = client.post(
            "/v1/jobs",
            headers=headers,
            json={"application_id": application["id"], "kind": "scan"},
        ).json()
        before_events = client.get("/v1/audit-events", headers=headers).json()
        assert before_events

    app.state.database.dispose()
    restarted = new_test_app(database_url)
    with TestClient(restarted) as client:
        headers = auth_headers(issue_token(client, user.email))
        assert (
            client.get(f"/v1/applications/{application['id']}", headers=headers).status_code == 200
        )
        assert client.get(f"/v1/assets/{asset['id']}", headers=headers).status_code == 200
        fetched_job = client.get(f"/v1/jobs/{job['id']}", headers=headers)
        assert fetched_job.status_code == 200
        assert fetched_job.json()["id"] == job["id"]
        after_events = client.get("/v1/audit-events", headers=headers).json()
        assert {event["id"] for event in after_events}.issuperset(
            {event["id"] for event in before_events}
        )
        assert all("password" not in str(event).casefold() for event in after_events)
