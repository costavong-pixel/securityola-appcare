"""Application-factory contract tests."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI

from appcare.api import create_app
from appcare.config import Settings


def _postgres(database_name: str, host: str = "localhost") -> str:
    return f"postgresql+psycopg://appcare:fake@{host}/{database_name}"


def test_factory_registers_control_plane_health_and_auth() -> None:
    app = create_app(settings=Settings(environment="test"))
    assert isinstance(app, FastAPI)
    paths = set(app.openapi()["paths"])
    assert {"/health/live", "/health/ready", "/auth/token"}.issubset(paths)
    assert "/v1/audit-events" in paths


@pytest.mark.parametrize(
    "database_name", ["appcare_production", "appcare_wordpress", "appcare_shared"]
)
def test_factory_rejects_non_environment_database_before_engine_creation(
    database_name: str,
) -> None:
    with patch("appcare.api.Database") as database_class:
        with pytest.raises(ValueError, match="environment target"):
            create_app(
                settings=Settings(
                    database_url=_postgres(database_name),
                    environment="development",
                    allowed_hosts=("localhost",),
                )
            )
    database_class.assert_not_called()


def test_factory_rejects_unapproved_database_url_override_before_engine_creation() -> None:
    with patch("appcare.api.Database") as database_class:
        with pytest.raises(ValueError, match="allowed AppCare host list"):
            create_app(
                settings=Settings(
                    database_url=_postgres("appcare_development"),
                    environment="development",
                    allowed_hosts=("localhost",),
                ),
                database_url=_postgres("appcare_development", host="db.internal"),
            )
    database_class.assert_not_called()


def test_factory_preserves_allowed_hosts_for_a_valid_database_url_override() -> None:
    database = Mock()
    app = create_app(
        settings=Settings(
            database_url=_postgres("appcare_development"),
            environment="development",
            allowed_hosts=("localhost", "db.internal"),
        ),
        database_url=_postgres("appcare_development", host="db.internal"),
        database=database,
    )
    assert isinstance(app, FastAPI)
    database.initialize.assert_called_once_with()
