"""Closed command templates for the Spec 015 database adapters.

The registry is the only place that creates database-client argv.  It accepts
typed requests and approved paths, never SQL/flags/binary paths supplied by a
caller.  Credentials are attached later by the private broker and are never
part of a ``DatabaseCommand``.
"""

# ruff: noqa: S608

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .contracts import (
    DatabaseArtifactError,
    DatabaseDumpRequest,
    DatabaseKind,
    DatabaseOperationKind,
    DatabaseOperationRejected,
    DatabaseRestoreRequest,
    DatabaseTarget,
    DatabaseVerifyRequest,
    validate_operation_id,
)

_ALLOWED_EXECUTABLES = frozenset(
    {
        "mariadb-admin",
        "mariadb-dump",
        "mysql",
        "mysqladmin",
        "mysqldump",
        "pg_dump",
        "pg_isready",
        "pg_restore",
        "psql",
    }
)
_FORBIDDEN_ARG_CHARS = frozenset("\x00\n\r")
_ALLOWED_TEMPLATE_IDS = frozenset(
    {
        "mysql.probe.logical.v1",
        "mysql.dump.logical.v1",
        "mysql.restore.logical.v1",
        "mysql.verify.restore.v1",
        "mysql.verify.empty.v1",
        "postgres.probe.logical.v1",
        "postgres.dump.logical.v1",
        "postgres.restore.logical.v1",
        "postgres.verify.restore.v1",
        "postgres.verify.empty.v1",
    }
)
_MYSQL_PROFILES = frozenset({"mariadb-logical-v1"})
_POSTGRES_PROFILES = frozenset({"postgresql-custom-v1"})
_REGISTRY_TOKEN = object()


def _sql_string_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _mysql_verify_query(request: DatabaseVerifyRequest) -> str:
    if request.expected_object_names:
        expected_names = ", ".join(
            _sql_string_literal(name) for name in request.expected_object_names
        )
        object_count = (  # noqa: S608 - closed query shape using validated internal identifiers only
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = DATABASE() "
            f"AND table_name IN ({expected_names})"  # noqa: S608
        )
    else:
        object_count = (
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()"
        )
    return f"SELECT DATABASE(), ({object_count})"


def _postgres_verify_query(request: DatabaseVerifyRequest) -> str:
    object_filter = ""
    if request.expected_object_names:
        expected_names = ", ".join(
            _sql_string_literal(name) for name in request.expected_object_names
        )
        object_filter = f" AND c.relname IN ({expected_names})"  # noqa: S608
    return (
        "SELECT current_database(), "
        "("
        "SELECT COUNT(*) "
        "FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
        "AND c.relkind IN ('r', 'v', 'm', 'S', 'f', 'p')"
        f"{object_filter}"  # noqa: S608 - names are validated by DatabaseVerifyRequest
        ")"
    )


@dataclass(frozen=True, slots=True)
class DatabaseCommand:
    """A validated argv tuple from the closed command registry."""

    operation_id: str
    operation: DatabaseOperationKind
    template_id: str
    argv: tuple[str, ...]
    uses_stdin_artifact: bool = False
    registry_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.registry_token is not _REGISTRY_TOKEN:
            raise DatabaseOperationRejected("database command must come from the closed registry")
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        if not self.argv or self.argv[0] not in _ALLOWED_EXECUTABLES:
            raise DatabaseOperationRejected("database executable is not approved")
        if not self.template_id or len(self.template_id) > 100:
            raise DatabaseOperationRejected("database template is invalid")
        if self.template_id not in _ALLOWED_TEMPLATE_IDS:
            raise DatabaseOperationRejected("database template is not approved")
        for value in (self.template_id, *self.argv):
            if (
                not isinstance(value, str)
                or not value
                or any(character in _FORBIDDEN_ARG_CHARS for character in value)
                or any(ord(character) < 32 for character in value)
            ):
                raise DatabaseOperationRejected("database command argument is unsafe")
        if not isinstance(self.operation, DatabaseOperationKind):
            try:
                object.__setattr__(
                    self,
                    "operation",
                    DatabaseOperationKind(str(self.operation).strip().casefold()),
                )
            except ValueError as exc:
                raise DatabaseOperationRejected("database operation is invalid") from exc


class DatabaseCommandRegistry:
    """Build only versioned, typed, non-shell database commands."""

    def build_probe(self, target: DatabaseTarget, *, operation_id: str) -> DatabaseCommand:
        operation_id = validate_operation_id(operation_id)
        if target.engine_family == DatabaseKind.MARIADB_MYSQL:
            return DatabaseCommand(
                operation_id,
                DatabaseOperationKind.DATABASE_PROBE,
                "mysql.probe.logical.v1",
                (
                    "mariadb-admin",
                    "--protocol=TCP",
                    "--host=" + target.database_host,
                    "--port=" + str(target.database_port),
                    "--user=" + target.database_user,
                    "ping",
                ),
                registry_token=_REGISTRY_TOKEN,
            )
        return DatabaseCommand(
            operation_id,
            DatabaseOperationKind.DATABASE_PROBE,
            "postgres.probe.logical.v1",
            (
                "pg_isready",
                "--host=" + target.database_host,
                "--port=" + str(target.database_port),
                "--username=" + target.database_user,
                "--dbname=" + target.logical_database_name,
            ),
            registry_token=_REGISTRY_TOKEN,
        )

    def build_dump(
        self,
        request: DatabaseDumpRequest,
        *,
        output_path: Path,
    ) -> DatabaseCommand:
        target = request.target
        # The adapter validates the path against its exact staging job.  This
        # second lexical check prevents command construction from accepting a
        # path with shell/control characters even for a custom test broker.
        if not output_path.is_absolute() or output_path.name not in {
            "database.sql",
            "database.dump",
        }:
            raise DatabaseArtifactError("database output path is not approved")
        if target.engine_family == DatabaseKind.MARIADB_MYSQL:
            if target.tool_profile not in _MYSQL_PROFILES:
                raise DatabaseOperationRejected("mariadb tool profile is not approved")
            return DatabaseCommand(
                request.operation_id,
                DatabaseOperationKind.LOGICAL_DUMP,
                "mysql.dump.logical.v1",
                (
                    "mariadb-dump",
                    "--single-transaction",
                    "--skip-lock-tables",
                    "--routines",
                    "--events",
                    "--triggers",
                    "--hex-blob",
                    "--no-tablespaces",
                    "--host=" + target.database_host,
                    "--port=" + str(target.database_port),
                    "--user=" + target.database_user,
                    target.logical_database_name,
                    "--result-file=" + str(output_path),
                ),
                registry_token=_REGISTRY_TOKEN,
            )
        if target.tool_profile not in _POSTGRES_PROFILES:
            raise DatabaseOperationRejected("postgresql tool profile is not approved")
        return DatabaseCommand(
            request.operation_id,
            DatabaseOperationKind.LOGICAL_DUMP,
            "postgres.dump.logical.v1",
            (
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--no-comments",
                "--host=" + target.database_host,
                "--port=" + str(target.database_port),
                "--username=" + target.database_user,
                "--file=" + str(output_path),
                target.logical_database_name,
            ),
            registry_token=_REGISTRY_TOKEN,
        )

    def build_restore(
        self,
        request: DatabaseRestoreRequest,
        *,
        artifact_path: Path,
    ) -> DatabaseCommand:
        target = request.target
        if not artifact_path.is_absolute() or artifact_path.name not in {
            "database.sql",
            "database.dump",
        }:
            raise DatabaseArtifactError("database restore artifact path is not approved")
        operation_id = request.operation_id
        if target.engine_family == DatabaseKind.MARIADB_MYSQL:
            if target.engine_family != request.artifact.manifest.engine_family:
                raise DatabaseOperationRejected("restore engine does not match artifact")
            return DatabaseCommand(
                operation_id,
                DatabaseOperationKind.LOGICAL_RESTORE,
                "mysql.restore.logical.v1",
                (
                    "mysql",
                    "--protocol=TCP",
                    "--host=" + target.database_host,
                    "--port=" + str(target.database_port),
                    "--user=" + target.database_user,
                    "--database=" + target.restore_database_name,
                ),
                uses_stdin_artifact=True,
                registry_token=_REGISTRY_TOKEN,
            )
        return DatabaseCommand(
            operation_id,
            DatabaseOperationKind.LOGICAL_RESTORE,
            "postgres.restore.logical.v1",
            (
                "pg_restore",
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--exit-on-error",
                "--host=" + target.database_host,
                "--port=" + str(target.database_port),
                "--username=" + target.database_user,
                "--dbname=" + target.restore_database_name,
            ),
            uses_stdin_artifact=True,
            registry_token=_REGISTRY_TOKEN,
        )

    def build_verify(
        self,
        request: DatabaseVerifyRequest,
        *,
        artifact_path: Path,
    ) -> DatabaseCommand:
        del artifact_path
        target = request.target
        fixed_query = (
            _mysql_verify_query(request)
            if target.engine_family == DatabaseKind.MARIADB_MYSQL
            else _postgres_verify_query(request)
        )
        operation = (
            DatabaseOperationKind.PRE_RESTORE_VERIFY
            if request.require_empty
            else DatabaseOperationKind.POST_RESTORE_VERIFY
        )
        if target.engine_family == DatabaseKind.MARIADB_MYSQL:
            return DatabaseCommand(
                request.operation_id,
                operation,
                "mysql.verify.empty.v1" if request.require_empty else "mysql.verify.restore.v1",
                (
                    "mysql",
                    "--batch",
                    "--skip-column-names",
                    "--protocol=TCP",
                    "--host=" + target.database_host,
                    "--port=" + str(target.database_port),
                    "--user=" + target.database_user,
                    "--database=" + target.restore_database_name,
                    "--execute=" + fixed_query,
                ),
                registry_token=_REGISTRY_TOKEN,
            )
        return DatabaseCommand(
            request.operation_id,
            operation,
            "postgres.verify.empty.v1" if request.require_empty else "postgres.verify.restore.v1",
            (
                "psql",
                "--no-psqlrc",
                "--tuples-only",
                "--no-align",
                "--host=" + target.database_host,
                "--port=" + str(target.database_port),
                "--username=" + target.database_user,
                "--dbname=" + target.restore_database_name,
                "--command=" + fixed_query,
            ),
            registry_token=_REGISTRY_TOKEN,
        )


__all__ = ["DatabaseCommand", "DatabaseCommandRegistry"]
