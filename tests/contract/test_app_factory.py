"""Application-factory contract tests."""

from fastapi import FastAPI

from appcare.api import create_app
from appcare.config import Settings


def test_factory_registers_control_plane_health_and_auth() -> None:
    app = create_app(settings=Settings(environment="test"))
    assert isinstance(app, FastAPI)
    paths = set(app.openapi()["paths"])
    assert {"/health/live", "/health/ready", "/auth/token"}.issubset(paths)
    assert "/v1/audit-events" in paths
