"""Validated, development-only AppCare configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

_ALLOWED_ENVIRONMENTS = {"development", "staging", "test"}
_FORBIDDEN_PATH_MARKERS = ("wordpress", "barnd", "shield", "production", "deploy")


def _integer_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} is outside the supported range")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """AppCare settings with safe local defaults and no implicit secrets."""

    database_url: str = "sqlite+pysqlite:///:memory:"
    environment: str = "development"
    token_ttl_seconds: int = 900
    max_page_size: int = 100
    audit_metadata_max_bytes: int = 16_384

    def validate(self) -> Settings:
        environment = self.environment.casefold()
        if environment not in _ALLOWED_ENVIRONMENTS:
            raise ValueError("APPCARE_ENVIRONMENT must be development, staging, or test")

        parsed = urlsplit(self.database_url)
        if parsed.scheme.startswith("sqlite"):
            database_path = (parsed.path or "").casefold()
            if any(marker in database_path for marker in _FORBIDDEN_PATH_MARKERS):
                raise ValueError("database path is outside the AppCare boundary")
        elif parsed.scheme in {"postgresql", "postgres"} or parsed.scheme.startswith("postgresql+"):
            host = (parsed.hostname or "").casefold()
            if not host or any(marker in host for marker in _FORBIDDEN_PATH_MARKERS):
                raise ValueError("database host is outside the AppCare boundary")
        else:
            raise ValueError("database URL must use an isolated SQLite or PostgreSQL scheme")
        return self

    @classmethod
    def from_env(cls) -> Settings:
        defaults = cls()
        settings = cls(
            database_url=os.getenv("APPCARE_DATABASE_URL", defaults.database_url),
            environment=os.getenv("APPCARE_ENVIRONMENT", defaults.environment),
            token_ttl_seconds=_integer_env(
                "APPCARE_TOKEN_TTL_SECONDS", defaults.token_ttl_seconds, minimum=60, maximum=86_400
            ),
            max_page_size=_integer_env(
                "APPCARE_MAX_PAGE_SIZE", defaults.max_page_size, minimum=1, maximum=500
            ),
            audit_metadata_max_bytes=_integer_env(
                "APPCARE_AUDIT_METADATA_MAX_BYTES",
                defaults.audit_metadata_max_bytes,
                minimum=1_024,
                maximum=65_536,
            ),
        )
        return settings.validate()
