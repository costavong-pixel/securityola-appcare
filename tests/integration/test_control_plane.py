"""BETA-01 tenant, durability, health, and audit-boundary tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError

from appcare.api import create_app
from appcare.auth.service import hash_password
from appcare.config import Settings
from appcare.models import AuditEvent, Tenant, User
from appcare.services.audit import append_event, verify_event_hash


def _new_app(database_url: str = "sqlite+pysqlite:///:memory:") -> FastAPI:
    return create_app(settings=Settings(database_url=database_url, environment="test"))


def _seed_user(app: FastAPI, name: str) -> tuple[str, str]:
    database = app.state.database
    with database.session_factory() as session:
        tenant = Tenant(name=f"Tenant {name}")
        session.add(tenant)
        session.flush()
        user = User(
            tenant_id=tenant.id,
            email=f"{name.casefold()}@example.test",
            display_name=name,
            password_hash=hash_password("a-local-test-password"),
        )
        session.add(user)
        session.commit()
        return tenant.id, user.id


def _token(client: TestClient, email: str) -> str:
    response = client.post(
        "/auth/token", json={"email": email, "password": "a-local-test-password"}
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def test_two_tenants_cannot_read_or_create_against_each_other() -> None:
    app = _new_app()
    tenant_a, _ = _seed_user(app, "Alice")
    tenant_b, _ = _seed_user(app, "Bob")
    with TestClient(app) as client:
        token_a = _token(client, "alice@example.test")
        token_b = _token(client, "bob@example.test")
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        created = client.post(
            "/v1/applications",
            headers=headers_a,
            json={
                "name": "Alice app",
                "repository_url": "https://github.com/example/alice",
                "environment": "development",
            },
        )
        assert created.status_code == 201, created.text
        application_id = created.json()["id"]
        assert created.json()["tenant_id"] == tenant_a

        assert client.get("/v1/applications", headers=headers_a).json()[0]["id"] == application_id
        assert client.get("/v1/applications", headers=headers_b).json() == []
        assert (
            client.get(f"/v1/applications/{application_id}", headers=headers_b).status_code == 404
        )
        assert (
            client.patch(
                f"/v1/applications/{application_id}",
                headers=headers_b,
                json={"name": "foreign"},
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/v1/assets",
                headers=headers_b,
                json={
                    "application_id": application_id,
                    "kind": "site",
                    "locator": "https://example.test",
                },
            ).status_code
            == 404
        )
        assert client.get("/v1/applications/not-an-id", headers=headers_a).status_code == 404
        assert client.get("/v1/applications").status_code == 401

    assert tenant_b != tenant_a


def test_restart_preserves_job_and_audit_state(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'appcare.db').as_posix()}"
    app = _new_app(database_url)
    _seed_user(app, "Restart")
    with TestClient(app) as client:
        token = _token(client, "restart@example.test")
        headers = {"Authorization": f"Bearer {token}"}
        application = client.post(
            "/v1/applications",
            headers=headers,
            json={
                "name": "Durable app",
                "repository_url": "https://github.com/example/durable",
            },
        ).json()
        job = client.post(
            "/v1/jobs",
            headers=headers,
            json={
                "application_id": application["id"],
                "kind": "scan",
                "cost_amount": "1.25",
                "cost_currency": "usd",
            },
        )
        assert job.status_code == 201, job.text
        job_id = job.json()["id"]

    app.state.database.dispose()
    restarted = _new_app(database_url)
    with TestClient(restarted) as client:
        headers = {"Authorization": f"Bearer {_token(client, 'restart@example.test')}"}
        fetched = client.get(f"/v1/jobs/{job_id}", headers=headers)
        assert fetched.status_code == 200, fetched.text
        assert fetched.json()["status"] == "queued"
        events = client.get("/v1/audit-events", headers=headers)
        assert events.status_code == 200
        assert events.json()
        assert all("password" not in str(event).casefold() for event in events.json())


def test_audit_events_are_hashed_sanitized_and_immutable() -> None:
    app = _new_app()
    tenant_id, user_id = _seed_user(app, "Audit")
    database = app.state.database
    with database.session_factory() as session:
        event = append_event(
            session,
            tenant_id=tenant_id,
            actor_user_id=user_id,
            action="test.event",
            subject_type="fixture",
            subject_id=None,
            outcome="success",
            metadata={"api_key": "fake-fixture-value", "safe": "yes"},
        )
        session.commit()
        event_id = event.id
        assert event.metadata_json["api_key"] == "[REDACTED]"
        assert verify_event_hash(event)

        with pytest.raises(IntegrityError):
            session.execute(
                update(AuditEvent).where(AuditEvent.id == event_id).values(outcome="tampered")
            )
            session.commit()
        session.rollback()

        with pytest.raises(IntegrityError):
            session.execute(delete(AuditEvent).where(AuditEvent.id == event_id))
            session.commit()
        session.rollback()
        persisted = session.get(AuditEvent, event_id)
        assert persisted is not None
        assert persisted.outcome == "success"


def test_health_and_no_production_write_routes() -> None:
    app = _new_app()
    with TestClient(app) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").json()["status"] == "ready"
    paths = set(app.openapi()["paths"])
    assert not any(
        any(word in path for word in ("execute", "sync", "provider-write")) for path in paths
    )
    assert "/v1/deployments" in paths
