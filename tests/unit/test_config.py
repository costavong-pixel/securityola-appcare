"""Configuration boundary tests."""

from __future__ import annotations

import pytest

from appcare.config import Settings


def test_settings_accept_isolated_sqlite() -> None:
    assert Settings(database_url="sqlite+pysqlite:///:memory:", environment="test").validate()


def test_non_test_sqlite_requires_an_appcare_database_path() -> None:
    with pytest.raises(ValueError, match="AppCare-owned"):
        Settings(
            database_url="sqlite+pysqlite:///./shared.db", environment="development"
        ).validate()


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite+pysqlite:///./wordpress-shared.db",
        "postgresql+psycopg://appcare:fake@production-db.example.test/appcare",
    ],
)
def test_settings_reject_out_of_boundary_database(database_url: str) -> None:
    with pytest.raises(ValueError, match="outside the AppCare boundary"):
        Settings(database_url=database_url, environment="test").validate()


def test_non_test_postgres_requires_an_appcare_database_name() -> None:
    with pytest.raises(ValueError, match="outside the AppCare boundary"):
        Settings(
            database_url="postgresql+psycopg://appcare:fake@db.internal/other-app",
            environment="development",
        ).validate()


def test_settings_reject_unknown_environment() -> None:
    with pytest.raises(ValueError, match="APPCARE_ENVIRONMENT"):
        Settings(environment="production").validate()
