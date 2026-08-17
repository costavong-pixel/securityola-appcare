"""Configuration boundary tests."""

from __future__ import annotations

import pytest

from appcare.config import Settings


def _postgres(database_name: str, host: str = "localhost") -> str:
    return f"postgresql+psycopg://appcare:fake@{host}/{database_name}"


def test_settings_accept_isolated_sqlite() -> None:
    assert Settings(database_url="sqlite+pysqlite:///:memory:", environment="test").validate()


def test_non_test_sqlite_requires_an_appcare_database_path() -> None:
    with pytest.raises(ValueError, match="AppCare-owned"):
        Settings(
            database_url="sqlite+pysqlite:///./shared.db", environment="development"
        ).validate()


def test_test_sqlite_rejects_shared_database_path() -> None:
    with pytest.raises(ValueError, match="AppCare-owned"):
        Settings(database_url="sqlite+pysqlite:///./shared.db", environment="test").validate()


def test_settings_rejects_forbidden_sqlite_path() -> None:
    with pytest.raises(ValueError, match="outside the AppCare boundary"):
        Settings(
            database_url="sqlite+pysqlite:///./wordpress-shared.db", environment="test"
        ).validate()


@pytest.mark.parametrize(
    "database_name", ["appcare_production", "appcare_wordpress", "appcare_shared"]
)
def test_postgres_rejects_non_environment_database_name(database_name: str) -> None:
    with pytest.raises(ValueError, match="environment target"):
        Settings(
            database_url=_postgres(database_name),
            environment="development",
            allowed_hosts=("localhost",),
        ).validate()


def test_postgres_rejects_encoded_non_environment_database_name() -> None:
    with pytest.raises(ValueError, match="environment target"):
        Settings(
            database_url=_postgres("appcare_pro%64uction"),
            environment="development",
            allowed_hosts=("localhost",),
        ).validate()


def test_postgres_requires_explicit_host_allowlist() -> None:
    with pytest.raises(ValueError, match="APPCARE_DATABASE_ALLOWED_HOSTS"):
        Settings(
            database_url=_postgres("appcare_development"), environment="development"
        ).validate()


def test_postgres_rejects_unapproved_host() -> None:
    with pytest.raises(ValueError, match="allowed AppCare host list"):
        Settings(
            database_url=_postgres("appcare_development", host="db.internal"),
            environment="development",
            allowed_hosts=("localhost",),
        ).validate()


def test_postgres_rejects_forbidden_host_even_if_allowlisted() -> None:
    with pytest.raises(ValueError, match="outside the AppCare boundary"):
        Settings(
            database_url=_postgres("appcare_development", host="production-db"),
            environment="development",
            allowed_hosts=("production-db",),
        ).validate()


@pytest.mark.parametrize(
    ("environment", "database_name"),
    [
        ("development", "appcare_development"),
        ("staging", "appcare_staging"),
        ("test", "appcare_test"),
    ],
)
def test_postgres_accepts_exact_environment_target(environment: str, database_name: str) -> None:
    assert Settings(
        database_url=_postgres(database_name),
        environment=environment,
        allowed_hosts=(" LOCALHOST ",),
    ).validate()


@pytest.mark.parametrize(
    ("environment", "database_name"),
    [
        ("development", "appcare_staging"),
        ("staging", "appcare_development"),
        ("test", "appcare_development"),
    ],
)
def test_postgres_rejects_environment_name_mismatch(environment: str, database_name: str) -> None:
    with pytest.raises(ValueError, match="environment target"):
        Settings(
            database_url=_postgres(database_name),
            environment=environment,
            allowed_hosts=("localhost",),
        ).validate()


def test_from_env_reads_non_secret_postgres_host_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APPCARE_DATABASE_URL", _postgres("appcare_development"))
    monkeypatch.setenv("APPCARE_ENVIRONMENT", "development")
    monkeypatch.setenv("APPCARE_DATABASE_ALLOWED_HOSTS", "localhost, db.internal")
    assert Settings.from_env().database_url.endswith("/appcare_development")


def test_settings_reject_unknown_environment() -> None:
    with pytest.raises(ValueError, match="APPCARE_ENVIRONMENT"):
        Settings(environment="production").validate()
