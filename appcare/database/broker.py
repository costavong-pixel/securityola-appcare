"""Private database credential and subprocess broker boundary.

Only this module may resolve a database credential value.  It uses a minimal
environment and an ephemeral, mode-0600 provider file, then removes that file
before returning.  Commands still come exclusively from
``DatabaseCommandRegistry``.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO

from .commands import DatabaseCommand, DatabaseCommandRegistry
from .contracts import (
    DatabaseArtifactError,
    DatabaseBrokerResult,
    DatabaseCredentialError,
    DatabaseCredentialProvider,
    DatabaseDumpRequest,
    DatabaseExecutionBroker,
    DatabaseKind,
    DatabaseLimits,
    DatabaseOperationKind,
    DatabaseOperationRejected,
    DatabaseOperationStatus,
    DatabaseProbe,
    DatabaseRestoreError,
    DatabaseRestoreRequest,
    DatabaseTarget,
    DatabaseVerifyRequest,
    ResolvedDatabaseCredential,
    validate_database_artifact_path,
    validate_database_name,
)


class DatabaseBrokerError(RuntimeError):
    """An execution failure that is converted to a bounded broker result."""


class UnavailableDatabaseCredentialProvider:
    """Default provider; live credentials are never guessed or synthesized."""

    def resolve(self, _target: DatabaseTarget) -> ResolvedDatabaseCredential:
        raise DatabaseCredentialError("database credential provider is unavailable")


class InMemoryDatabaseCredentialProvider:
    """Test/reference-only provider whose values never leave the broker call."""

    def __init__(self, credentials: Mapping[str, ResolvedDatabaseCredential]) -> None:
        self._credentials = dict(credentials)

    def resolve(self, target: DatabaseTarget) -> ResolvedDatabaseCredential:
        target.credential.require_active()
        try:
            credential = self._credentials[target.credential.reference]
        except KeyError as exc:
            raise DatabaseCredentialError("database credential is unavailable") from exc
        if credential.reference != target.credential.reference:
            raise DatabaseCredentialError("database credential reference mismatch")
        if credential.username != target.database_user:
            raise DatabaseCredentialError("database credential user mismatch")
        return credential


_MARIADB_UNSAFE_STATEMENTS = {
    ("create", "database"),
    ("create", "schema"),
    ("create", "user"),
    ("alter", "user"),
    ("drop", "database"),
    ("drop", "schema"),
    ("drop", "user"),
    ("set", "global"),
    ("install", "plugin"),
    ("load", "data"),
}
_MARIADB_OBJECT_STATEMENTS = {("create", "table"), ("create", "view")}
_MARIADB_UNSAFE_OBJECT_STATEMENTS = {
    ("create", "procedure"),
    ("create", "function"),
    ("create", "event"),
    ("create", "trigger"),
    ("alter", "procedure"),
    ("alter", "function"),
    ("alter", "event"),
    ("alter", "trigger"),
    ("drop", "procedure"),
    ("drop", "function"),
    ("drop", "event"),
    ("drop", "trigger"),
}


def _validate_private_directory(path: Path, *, field_name: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise DatabaseCredentialError(f"{field_name} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise DatabaseCredentialError(f"{field_name} is unsafe")
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise DatabaseCredentialError(f"{field_name} permissions are unsafe")
    getuid = getattr(os, "getuid", None)
    owner_uid = getattr(metadata, "st_uid", None)
    if callable(getuid) and isinstance(owner_uid, int):
        try:
            if owner_uid != getuid():
                raise DatabaseCredentialError(f"{field_name} ownership is unsafe")
        except OSError as exc:
            raise DatabaseCredentialError(f"{field_name} ownership is unavailable") from exc


def _inspect_mariadb_statement(tokens: list[str], *, object_names: list[str]) -> None:
    if not tokens:
        return
    lowered = [token.casefold() for token in tokens]
    normalized = "".join(lowered)
    first = lowered[0].rstrip(";")
    second = lowered[1].rstrip(";") if len(lowered) > 1 else ""
    if "definer" in normalized:
        raise DatabaseRestoreError("mariadb restore contains an unsafe security directive")
    # Routine/event/trigger DDL can change execution context or perform
    # side-effects during restore. Do not rely on the object type appearing
    # in one exact token position: dump tools may emit CREATE OR REPLACE,
    # DEFINER clauses, or executable comments before it. This conservative
    # scan rejects programmable objects while the lexer still ignores quoted
    # strings and ordinary comments.
    if first in {"create", "alter", "drop"} and any(
        object_type in normalized for object_type in ("procedure", "function", "event", "trigger")
    ):
        raise DatabaseRestoreError("mariadb restore contains unsafe programmable object DDL")
    if (
        first == "use"
        or (first, second) in _MARIADB_UNSAFE_STATEMENTS
        or (first, second) in _MARIADB_UNSAFE_OBJECT_STATEMENTS
        or first in {"grant", "revoke"}
        or first in {"delimiter", "source", "system", "pager", "tee"}
    ):
        raise DatabaseRestoreError("mariadb restore contains an unsafe database directive")
    if (first, second) not in _MARIADB_OBJECT_STATEMENTS:
        return
    index = 2
    if lowered[2:5] == ["if", "not", "exists"]:
        index = 5
    if index >= len(tokens):
        return
    object_name = validate_database_name(tokens[index], field_name="restore_object_name")
    if object_name not in object_names:
        object_names.append(object_name)


def inspect_mariadb_restore_artifact(path: Path, *, expected_size: int) -> tuple[str, ...]:
    """Inspect one SQL dump for unsafe directives and restorable object names."""

    descriptor = -1
    stream: BinaryIO | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
    except (OSError, ValueError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise DatabaseArtifactError("restore artifact cannot be inspected") from exc

    assert stream is not None
    total = 0
    statement_tokens: list[str] = []
    token_chars: list[str] = []
    object_names: list[str] = []
    mode = "default"
    executable_prefix = False
    quote_return_mode = "default"

    def flush_token() -> None:
        if token_chars:
            statement_tokens.append("".join(token_chars))
            token_chars.clear()

    def finish_statement() -> None:
        flush_token()
        _inspect_mariadb_statement(statement_tokens, object_names=object_names)
        statement_tokens.clear()

    try:
        while True:
            line = stream.readline(8_193)
            if not line:
                break
            total += len(line)
            if total > expected_size:
                raise DatabaseArtifactError("restore artifact size changed")
            if len(line) > 8_192 and not line.endswith(b"\n"):
                raise DatabaseRestoreError("mariadb restore contains an oversized SQL line")
            try:
                text = line.decode("utf-8").lstrip("\ufeff")
            except UnicodeDecodeError as exc:
                raise DatabaseArtifactError("mariadb restore artifact is not UTF-8 SQL") from exc
            index = 0
            while index < len(text):
                character = text[index]
                next_character = text[index + 1] if index + 1 < len(text) else ""
                if mode == "line_comment":
                    index = len(text)
                    continue
                if mode in {"single_quote", "single_quote_exec"}:
                    if character == "\\" and next_character:
                        index += 2
                        continue
                    if character == "'":
                        mode = quote_return_mode
                    index += 1
                    continue
                if mode in {"double_quote", "double_quote_exec"}:
                    if character == "\\" and next_character:
                        index += 2
                        continue
                    if character == '"':
                        mode = quote_return_mode
                    index += 1
                    continue
                if mode in {"backtick", "backtick_exec"}:
                    if character == "`":
                        flush_token()
                        mode = quote_return_mode
                    else:
                        token_chars.append(character)
                    index += 1
                    continue
                if mode == "block_comment":
                    if character == "*" and next_character == "/":
                        mode = "default"
                        index += 2
                    else:
                        index += 1
                    continue
                if mode == "executable_comment":
                    if (character == "/" and next_character == "*") or character == "#":
                        raise DatabaseRestoreError(
                            "mariadb restore contains an ambiguous executable comment"
                        )
                    if character == "-" and next_character == "-":
                        raise DatabaseRestoreError(
                            "mariadb restore contains an ambiguous executable comment"
                        )
                    if character == "*" and next_character == "/":
                        flush_token()
                        mode = "default"
                        index += 2
                        continue
                    if executable_prefix and (character.isdigit() or character.isspace()):
                        index += 1
                        continue
                    executable_prefix = False
                    if character in {"'", '"', "`"}:
                        flush_token()
                        quote_return_mode = "executable_comment"
                        mode = {
                            "'": "single_quote_exec",
                            '"': "double_quote_exec",
                            "`": "backtick_exec",
                        }[character]
                        index += 1
                        continue
                    if character == ";":
                        finish_statement()
                        index += 1
                        continue
                    if character.isspace() or character in ",()":
                        flush_token()
                        index += 1
                        continue
                    token_chars.append(character)
                    index += 1
                    continue

                if character == "-" and next_character == "-":
                    flush_token()
                    mode = "line_comment"
                    index += 2
                    continue
                if character == "#":
                    flush_token()
                    mode = "line_comment"
                    index += 1
                    continue
                if character == "/" and next_character == "*":
                    flush_token()
                    if index + 2 < len(text) and text[index + 2] == "!":
                        mode = "executable_comment"
                        executable_prefix = True
                        index += 3
                    else:
                        mode = "block_comment"
                        index += 2
                    continue
                if character in {"'", '"', "`"}:
                    flush_token()
                    quote_return_mode = "default"
                    mode = {
                        "'": "single_quote",
                        '"': "double_quote",
                        "`": "backtick",
                    }[character]
                    index += 1
                    continue
                if character == ";":
                    finish_statement()
                    index += 1
                    continue
                if character.isspace() or character in ",()":
                    flush_token()
                    index += 1
                    continue
                token_chars.append(character)
                index += 1
            if mode == "line_comment":
                mode = "default"
            if mode in {"default", "executable_comment"}:
                flush_token()
        if total != expected_size:
            raise DatabaseArtifactError("restore artifact size changed")
        if mode not in {"default"}:
            raise DatabaseArtifactError("mariadb restore artifact is truncated")
        if statement_tokens:
            finish_statement()
    finally:
        stream.close()

    return tuple(object_names)


def _sanitize_output(raw: bytes, *, limit: int) -> str:
    """Return only safe bounded diagnostics; never return secret-shaped text."""

    if not raw:
        return ""
    try:
        text = raw[:limit].decode("utf-8")
    except UnicodeDecodeError:
        return "malformed-output"
    if any(ord(character) < 32 and character not in "\t\n\r" for character in text):
        return "control-data-redacted"
    lowered = text.casefold()
    if any(
        marker in lowered
        for marker in (
            "password=",
            "passwd=",
            "secret=",
            "token=",
            "api_key=",
            "authorization:",
            "private_key=",
        )
    ):
        return "credential-shaped-output-redacted"
    return text[:4096].strip()


def _read_pipe(
    stream: BinaryIO,
    *,
    limit: int,
    output: bytearray,
    overflow: threading.Event,
) -> None:
    while not overflow.is_set():
        remaining = limit - len(output)
        if remaining <= 0:
            overflow.set()
            return
        chunk = stream.read(min(8192, remaining + 1))
        if not chunk:
            return
        if len(chunk) > remaining:
            output.extend(chunk[:remaining])
            overflow.set()
            return
        output.extend(chunk)


def _safe_remove(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        if stat.S_ISDIR(metadata.st_mode):
            children = tuple(path.iterdir())
            if not all(_safe_remove(child) for child in children):
                return False
            path.rmdir()
        else:
            path.unlink()
        return True
    except OSError:
        # Cleanup failure is not allowed to turn into a credential disclosure;
        # the operation is already failed closed and the path is never reused.
        return False


def _file_digest(path: Path, *, limit: int) -> tuple[int, str]:
    if path.is_symlink():
        raise DatabaseArtifactError("database artifact is a symlink")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise DatabaseArtifactError("database artifact cannot be opened") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise DatabaseArtifactError("database artifact is not a regular file")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise DatabaseArtifactError("database artifact exceeds hard cap")
            digest.update(chunk)
    except OSError as exc:
        raise DatabaseArtifactError("database artifact cannot be read") from exc
    finally:
        os.close(descriptor)
    if size == 0:
        raise DatabaseArtifactError("database artifact is empty")
    return size, digest.hexdigest()


class SubprocessDatabaseBroker(DatabaseExecutionBroker):
    """Run only closed database commands with bounded process I/O."""

    def __init__(
        self,
        credential_provider: DatabaseCredentialProvider,
        *,
        filesystem: object,
        registry: DatabaseCommandRegistry | None = None,
        popen_factory: Callable[..., subprocess.Popen[bytes]] | None = None,
    ) -> None:
        from ..backups.paths import BackupFilesystemBoundary

        if not isinstance(filesystem, BackupFilesystemBoundary):
            raise DatabaseArtifactError("database broker filesystem boundary is invalid")
        self._credential_provider = credential_provider
        self._filesystem = filesystem
        self._registry = registry or DatabaseCommandRegistry()
        self._popen_factory = popen_factory or subprocess.Popen

    def run(
        self,
        operation: DatabaseProbe
        | DatabaseDumpRequest
        | DatabaseRestoreRequest
        | DatabaseVerifyRequest,
        *,
        target: DatabaseTarget,
        output_path: Path | None = None,
        cancel_event: object | None = None,
    ) -> DatabaseBrokerResult:
        self._require_reference_target(target)
        self._check_operation_scope(operation, target)
        credential = self._credential_provider.resolve(target)
        self._check_credential_scope(target, credential)
        command: DatabaseCommand
        artifact_path: Path | None = None
        if isinstance(operation, DatabaseProbe):
            command = self._registry.build_probe(target, operation_id=operation.operation_id)
        elif isinstance(operation, DatabaseDumpRequest):
            if output_path is None:
                raise DatabaseArtifactError("database dump output path is required")
            output_path = validate_database_artifact_path(
                output_path,
                filesystem=self._filesystem,
                job_id=operation.job_id,
            )
            command = self._registry.build_dump(operation, output_path=output_path)
            artifact_path = output_path
        elif isinstance(operation, (DatabaseRestoreRequest, DatabaseVerifyRequest)):
            artifact_filesystem = operation.artifact.filesystem
            if artifact_filesystem is None or artifact_filesystem != self._filesystem:
                raise DatabaseArtifactError("database artifact crosses broker filesystem boundary")
            artifact_path = validate_database_artifact_path(
                operation.artifact.artifact_path,
                filesystem=self._filesystem,
                job_id=operation.artifact.staging_job_id,
            )
            if isinstance(operation, DatabaseRestoreRequest):
                if operation.target.engine_family == DatabaseKind.MARIADB_MYSQL:
                    validate_mariadb_restore_artifact(
                        artifact_path,
                        expected_size=operation.artifact.manifest.artifact_size_bytes,
                    )
            command = (
                self._registry.build_restore(operation, artifact_path=artifact_path)
                if isinstance(operation, DatabaseRestoreRequest)
                else self._registry.build_verify(operation, artifact_path=artifact_path)
            )
        else:
            raise DatabaseBrokerError("database operation is not registered")

        credential_directory: Path | None = None
        stdin_handle: BinaryIO | None = None
        result: DatabaseBrokerResult | None = None
        try:
            credential_directory, credential_path = self._create_credential_file(
                operation_id=command.operation_id,
                target=target,
                credential=credential,
            )
            argv, environment = self._attach_credential(command, credential_path, target)
            if command.uses_stdin_artifact:
                if artifact_path is None:
                    raise DatabaseArtifactError("restore artifact is unavailable")
                if not isinstance(operation, (DatabaseRestoreRequest, DatabaseVerifyRequest)):
                    raise DatabaseArtifactError("stdin artifact operation is invalid")
                stdin_handle = self._open_artifact(
                    artifact_path,
                    expected_size=operation.artifact.manifest.artifact_size_bytes,
                    expected_digest=operation.artifact.artifact_digest,
                )
            result = self._execute(
                command,
                argv=argv,
                environment=environment,
                target=target,
                artifact_path=artifact_path,
                stdin_handle=stdin_handle,
                cancel_event=cancel_event,
            )
        except (DatabaseArtifactError, DatabaseCredentialError):
            raise
        finally:
            if stdin_handle is not None:
                stdin_handle.close()
            cleanup_ok = credential_directory is None or _safe_remove(credential_directory)
            if not cleanup_ok and result is None:
                # Never silently leave a secret-bearing provider file behind
                # on an exception path. Surface only a sanitized boundary
                # error; provider output must not escape through the error.
                raise DatabaseCredentialError("database credential cleanup failed")
        if result is not None and not cleanup_ok:
            return replace(
                result,
                status=DatabaseOperationStatus.FAILED,
                reason_code="credential_cleanup_failed",
                artifact_path=None,
                artifact_size_bytes=0,
                artifact_sha256=None,
                sanitized_stderr="credential-cleanup-failed",
            )
        if result is None:
            raise DatabaseBrokerError("database operation produced no result")
        return result

    @staticmethod
    def _require_reference_target(target: DatabaseTarget) -> None:
        if (
            target.environment == "production"
            or target.transport.host not in {"127.0.0.1", "::1"}
            or not target.target_reference.startswith("reference://")
        ):
            raise DatabaseOperationRejected(
                "subprocess database broker is limited to loopback reference targets"
            )

    @staticmethod
    def _check_operation_scope(
        operation: DatabaseProbe
        | DatabaseDumpRequest
        | DatabaseRestoreRequest
        | DatabaseVerifyRequest,
        target: DatabaseTarget,
    ) -> None:
        if isinstance(operation, DatabaseDumpRequest) and operation.target != target:
            raise DatabaseCredentialError("database operation target mismatch")
        if isinstance(operation, (DatabaseRestoreRequest, DatabaseVerifyRequest)):
            requested = operation.target
            expected_reference = requested.isolated_target_reference + ":database"
            if (
                target.tenant_id != requested.tenant_id
                or target.application_id != requested.application_id
                or target.stack_id != requested.stack_id
                or target.environment != requested.environment
                or target.engine_family != requested.engine_family
                or target.target_reference != expected_reference
                or target.database_identifier != operation.artifact.manifest.database_identifier
                or target.logical_database_name != requested.restore_database_name
                or target.database_host != requested.database_host
                or target.database_port != requested.database_port
            ):
                raise DatabaseCredentialError("database restore target mismatch")
        target.credential.require_active()

    @staticmethod
    def _check_credential_scope(
        target: DatabaseTarget, credential: ResolvedDatabaseCredential
    ) -> None:
        if credential.reference != target.credential.reference:
            raise DatabaseCredentialError("database credential reference mismatch")
        if credential.username != target.database_user:
            raise DatabaseCredentialError("database credential user mismatch")

    def _create_credential_file(
        self,
        *,
        operation_id: str,
        target: DatabaseTarget,
        credential: ResolvedDatabaseCredential,
    ) -> tuple[Path, Path]:
        tmp_root = self._filesystem.tmp_root
        tmp_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _validate_private_directory(tmp_root, field_name="database temporary root")
        broker_root = tmp_root / "database-broker"
        broker_root.mkdir(mode=0o700, exist_ok=True)
        _validate_private_directory(broker_root, field_name="database broker root")
        unique = hashlib.sha256(f"{target.target_reference}:{operation_id}".encode()).hexdigest()[
            :32
        ]
        directory = Path(tempfile.mkdtemp(prefix=f"{unique}-", dir=str(broker_root)))
        if os.name != "nt":
            os.chmod(directory, 0o700)
        _validate_private_directory(directory, field_name="database credential directory")
        credential_path = directory / "provider-credential"
        content = f"[client]\nuser={credential.username}\npassword={credential.secret}\n".encode()
        if target.engine_family == DatabaseKind.POSTGRESQL:
            escaped_secret = credential.secret.replace("\\", "\\\\").replace(":", "\\:")
            content = f"*:*:*:{credential.username}:{escaped_secret}\n".encode()
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(credential_path, flags, 0o600)
            try:
                written = 0
                while written < len(content):
                    written += os.write(descriptor, content[written:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            _safe_remove(directory)
            raise DatabaseCredentialError("database credential handoff failed") from exc
        return directory, credential_path

    @staticmethod
    def _attach_credential(
        command: DatabaseCommand,
        credential_path: Path,
        target: DatabaseTarget,
    ) -> tuple[tuple[str, ...], dict[str, str]]:
        argv = command.argv
        if target.engine_family == DatabaseKind.MARIADB_MYSQL:
            argv = (argv[0], f"--defaults-extra-file={credential_path}", *argv[1:])
            return argv, {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        return argv, {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PGPASSFILE": str(credential_path),
        }

    @staticmethod
    def _open_artifact(path: Path, *, expected_size: int, expected_digest: str) -> BinaryIO:
        if path.is_symlink():
            raise DatabaseArtifactError("restore artifact is a symlink")
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
                raise DatabaseArtifactError("restore artifact is not manifest-sized")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > expected_size:
                    raise DatabaseArtifactError("restore artifact exceeds manifest size")
                digest.update(chunk)
            if size != expected_size or digest.hexdigest() != expected_digest:
                raise DatabaseArtifactError("restore artifact checksum mismatch")
            os.lseek(descriptor, 0, os.SEEK_SET)
            stream = os.fdopen(descriptor, "rb")
            descriptor = -1
            return stream
        except DatabaseArtifactError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except (OSError, ValueError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise DatabaseArtifactError("restore artifact cannot be opened") from exc

    def _execute(
        self,
        command: DatabaseCommand,
        *,
        argv: tuple[str, ...],
        environment: dict[str, str],
        target: DatabaseTarget,
        artifact_path: Path | None,
        stdin_handle: BinaryIO | None,
        cancel_event: object | None,
    ) -> DatabaseBrokerResult:
        limits: DatabaseLimits = target.limits
        timeout = {
            DatabaseOperationKind.DATABASE_PROBE: limits.probe_timeout_seconds,
            DatabaseOperationKind.LOGICAL_DUMP: limits.dump_timeout_seconds,
            DatabaseOperationKind.LOGICAL_RESTORE: limits.restore_timeout_seconds,
            DatabaseOperationKind.PRE_RESTORE_VERIFY: limits.verify_timeout_seconds,
            DatabaseOperationKind.POST_RESTORE_VERIFY: limits.verify_timeout_seconds,
        }[command.operation]
        stdout = bytearray()
        stderr = bytearray()
        stdout_overflow = threading.Event()
        stderr_overflow = threading.Event()
        process: subprocess.Popen[bytes] | None = None
        timed_out = False
        cancelled = False
        try:
            process = self._popen_factory(
                argv,
                shell=False,
                stdin=stdin_handle if stdin_handle is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                close_fds=True,
                start_new_session=True,
            )
            if process.stdout is None or process.stderr is None:
                raise DatabaseBrokerError("database process pipes unavailable")
            stdout_thread = threading.Thread(
                target=_read_pipe,
                args=(process.stdout,),
                kwargs={
                    "limit": limits.max_stdout_bytes,
                    "output": stdout,
                    "overflow": stdout_overflow,
                },
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=_read_pipe,
                args=(process.stderr,),
                kwargs={
                    "limit": limits.max_stderr_bytes,
                    "output": stderr,
                    "overflow": stderr_overflow,
                },
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if stdout_overflow.is_set() or stderr_overflow.is_set():
                    self._terminate(process)
                    break
                if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                    cancelled = True
                    self._terminate(process)
                    break
                if artifact_path is not None and artifact_path.exists():
                    if artifact_path.is_symlink():
                        self._terminate(process)
                        break
                    try:
                        if artifact_path.stat().st_size > limits.max_artifact_bytes:
                            self._terminate(process)
                            break
                    except OSError:
                        self._terminate(process)
                        break
                if time.monotonic() >= deadline:
                    timed_out = True
                    self._terminate(process)
                    break
                time.sleep(0.01)
            try:
                returncode = process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._terminate(process)
                returncode = None
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)
            if cancelled:
                status = DatabaseOperationStatus.CANCELLED
                reason = "operation_cancelled"
            elif timed_out:
                status = DatabaseOperationStatus.TIMED_OUT
                reason = "operation_timed_out"
            elif stdout_overflow.is_set() or stderr_overflow.is_set():
                status = DatabaseOperationStatus.OUTPUT_LIMITED
                reason = "output_limit_exceeded"
            elif (
                artifact_path is not None
                and artifact_path.exists()
                and artifact_path.stat().st_size > limits.max_artifact_bytes
            ):
                status = DatabaseOperationStatus.OUTPUT_LIMITED
                reason = "artifact_limit_exceeded"
            elif returncode == 255:
                status = DatabaseOperationStatus.DISCONNECTED
                reason = "database_process_disconnected"
            elif returncode != 0:
                status = DatabaseOperationStatus.FAILED
                reason = "database_command_failed"
            else:
                status = DatabaseOperationStatus.PASSED
                reason = "ok"
            artifact_size = 0
            artifact_sha256: str | None = None
            if (
                status == DatabaseOperationStatus.PASSED
                and command.operation == DatabaseOperationKind.LOGICAL_DUMP
            ):
                if artifact_path is None:
                    status = DatabaseOperationStatus.FAILED
                    reason = "dump_artifact_missing"
                else:
                    try:
                        artifact_size, artifact_sha256 = _file_digest(
                            artifact_path,
                            limit=limits.max_artifact_bytes,
                        )
                    except DatabaseArtifactError:
                        status = DatabaseOperationStatus.FAILED
                        reason = "dump_artifact_invalid"
            observed_database_name: str | None = None
            restored_object_count: int | None = None
            if status == DatabaseOperationStatus.PASSED and command.operation in {
                DatabaseOperationKind.PRE_RESTORE_VERIFY,
                DatabaseOperationKind.POST_RESTORE_VERIFY,
            }:
                try:
                    observed_database_name, restored_object_count = self._parse_verification_output(
                        command,
                        bytes(stdout),
                    )
                except DatabaseBrokerError:
                    status = DatabaseOperationStatus.FAILED
                    reason = "verification_output_invalid"
            if (
                status != DatabaseOperationStatus.PASSED
                and artifact_path is not None
                and command.operation == DatabaseOperationKind.LOGICAL_DUMP
            ):
                _safe_remove(artifact_path)
            return DatabaseBrokerResult(
                operation_id=command.operation_id,
                operation=command.operation,
                status=status,
                reason_code=reason,
                template_id=command.template_id,
                returncode=returncode,
                artifact_path=artifact_path if status == DatabaseOperationStatus.PASSED else None,
                artifact_size_bytes=artifact_size,
                artifact_sha256=artifact_sha256,
                stdout_bytes=len(stdout),
                stderr_bytes=len(stderr),
                sanitized_stderr=_sanitize_output(bytes(stderr), limit=limits.max_stderr_bytes),
                observed_database_name=observed_database_name,
                restored_object_count=restored_object_count,
                timed_out=timed_out,
                cancelled=cancelled,
                output_limited=stdout_overflow.is_set() or stderr_overflow.is_set(),
                disconnected=returncode == 255,
            )
        except (OSError, DatabaseBrokerError):
            if process is not None:
                self._terminate(process)
            if (
                artifact_path is not None
                and command.operation == DatabaseOperationKind.LOGICAL_DUMP
            ):
                _safe_remove(artifact_path)
            return DatabaseBrokerResult(
                operation_id=command.operation_id,
                operation=command.operation,
                status=DatabaseOperationStatus.FAILED,
                reason_code="database_process_unavailable",
                template_id=command.template_id,
                artifact_path=None,
                sanitized_stderr="process-unavailable",
            )

    @staticmethod
    def _parse_verification_output(
        command: DatabaseCommand,
        stdout: bytes,
    ) -> tuple[str, int]:
        try:
            text = stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DatabaseBrokerError("verification output is not UTF-8") from exc
        rows = [line.strip() for line in text.splitlines() if line.strip()]
        if len(rows) != 1:
            raise DatabaseBrokerError("verification output row count is invalid")
        separator = "\t" if command.template_id.startswith("mysql.") else "|"
        columns = [column.strip() for column in rows[0].split(separator)]
        if len(columns) != 2:
            raise DatabaseBrokerError("verification output shape is invalid")
        observed_database_name = validate_database_name(
            columns[0],
            field_name="observed_database_name",
        )
        try:
            restored_object_count = int(columns[1], 10)
        except ValueError as exc:
            raise DatabaseBrokerError("verification object count is invalid") from exc
        if restored_object_count < 0:
            raise DatabaseBrokerError("verification object count is invalid")
        return observed_database_name, restored_object_count

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            killpg = getattr(os, "killpg", None)
            getpgid = getattr(os, "getpgid", None)
            if os.name != "nt" and process.pid is not None and killpg and getpgid:
                killpg(getpgid(process.pid), getattr(__import__("signal"), "SIGKILL", 9))
            else:
                process.kill()
        except OSError:
            try:
                process.kill()
            except OSError:
                return


def validate_mariadb_restore_artifact(path: Path, *, expected_size: int) -> None:
    """Reject directives that could escape the selected restore database."""
    inspect_mariadb_restore_artifact(path, expected_size=expected_size)


__all__ = [
    "DatabaseBrokerError",
    "InMemoryDatabaseCredentialProvider",
    "SubprocessDatabaseBroker",
    "UnavailableDatabaseCredentialProvider",
    "inspect_mariadb_restore_artifact",
    "validate_mariadb_restore_artifact",
]
