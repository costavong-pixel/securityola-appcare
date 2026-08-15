"""Truthful liveness/readiness and unavailable-dependency behavior."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.control_plane_helpers import new_test_app


def test_liveness_is_process_only_and_readiness_reports_the_isolated_database() -> None:
    app = new_test_app()
    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/live").json() == {"status": "ok"}
        ready = client.get("/health/ready")
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready", "environment": "test"}


def test_readiness_fails_without_affecting_liveness_or_echoing_dependency_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = new_test_app()
    monkeypatch.setattr(app.state.database, "ready", lambda: False)
    with TestClient(app) as client:
        ready = client.get("/health/ready")
        live = client.get("/health/live")
    assert ready.status_code == 503
    assert ready.json() == {"detail": {"status": "not_ready"}}
    assert live.status_code == 200
    assert "database" not in ready.text.casefold()


def test_readiness_turns_a_dependency_timeout_into_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = new_test_app()

    def timeout() -> None:
        raise TimeoutError("fixture timeout")

    monkeypatch.setattr(app.state.database.engine, "connect", timeout)
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"detail": {"status": "not_ready"}}
    assert "fixture timeout" not in response.text
