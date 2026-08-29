"""PostgreSQL bounded custom-format logical backup adapter."""

from __future__ import annotations

from .adapters import LogicalDatabaseAdapter
from .contracts import DatabaseDumpFormat, DatabaseKind


class PostgreSQLAdapter(LogicalDatabaseAdapter):
    """The adapter uses the closed ``pg_dump``/``pg_restore`` profiles."""

    engine_family = DatabaseKind.POSTGRESQL
    dump_format = DatabaseDumpFormat.POSTGRES_CUSTOM
    output_filename = "database.dump"


PostgresAdapter = PostgreSQLAdapter

__all__ = ["PostgreSQLAdapter", "PostgresAdapter"]
