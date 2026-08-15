"""Small, deterministic fixtures shared by the BETA-01 contract tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from appcare.api import create_app
from appcare.auth.service import hash_password
from appcare.config import Settings
from appcare.models import Tenant, User

TEST_PASSWORD = "a-local-test-password"  # noqa: S105 - non-live test fixture


@dataclass(frozen=True)
class SeededUser:
    tenant_id: str
    user_id: str
    email: str


def new_test_app(database_url: str = "sqlite+pysqlite:///:memory:") -> FastAPI:
    return create_app(settings=Settings(database_url=database_url, environment="test"))


def seed_user(
    app: FastAPI,
    label: str,
    *,
    email: str | None = None,
    password: str = TEST_PASSWORD,
    status: str = "active",
) -> SeededUser:
    database = app.state.database
    normalized_email = email or f"{label.casefold()}@example.test"
    with database.session_factory() as session:
        tenant = Tenant(name=f"Tenant {label}")
        session.add(tenant)
        session.flush()
        user = User(
            tenant_id=tenant.id,
            email=normalized_email.casefold(),
            display_name=label,
            password_hash=hash_password(password),
            status=status,
        )
        session.add(user)
        session.commit()
        return SeededUser(tenant.id, user.id, normalized_email.casefold())


def set_token_expired(app: FastAPI, user_id: str) -> None:
    database = app.state.database
    with database.session_factory() as session:
        user = session.get(User, user_id)
        assert user is not None
        user.auth_token_expires_at = datetime.now(UTC).replace(year=2000)
        session.commit()


def issue_token(client: TestClient, email: str, password: str = TEST_PASSWORD) -> str:
    response = client.post("/auth/token", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_application(client: TestClient, token: str, name: str = "Test app") -> dict[str, object]:
    response = client.post(
        "/v1/applications",
        headers=auth_headers(token),
        json={
            "name": name,
            "repository_url": "https://github.com/example/app",
            "environment": "development",
        },
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def sqlite_file_url(tmp_path: Path) -> str:
    return f"sqlite+pysqlite:///{(tmp_path / 'appcare-test.db').as_posix()}"
