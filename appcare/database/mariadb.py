"""MariaDB/MySQL bounded logical backup adapter."""

from __future__ import annotations

from .adapters import LogicalDatabaseAdapter
from .contracts import DatabaseDumpFormat, DatabaseKind


class MariaDBAdapter(LogicalDatabaseAdapter):
    """The adapter uses the closed ``mariadb-dump``/``mysql`` profiles."""

    engine_family = DatabaseKind.MARIADB_MYSQL
    dump_format = DatabaseDumpFormat.SQL
    output_filename = "database.sql"


MySQLAdapter = MariaDBAdapter

__all__ = ["MariaDBAdapter", "MySQLAdapter"]
