"""Strict, read-only Linux/SSH execution and inventory boundary."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

from .linux_ssh_commands import CommandRegistry, RemoteCommand
from .linux_ssh_contracts import (
    ApplicationRootVerification,
    BoundedLimits,
    ConnectionProbe,
    CredentialBoundaryError,
    CredentialProvider,
    EvidenceClass,
    FilesystemMetadataRead,
    HostInventory,
    HostKeyScanner,
    HostKeyVerificationError,
    InMemoryOperationLedger,
    InventoryRecord,
    LinuxInventorySnapshot,
    LinuxOperation,
    LinuxTarget,
    NetworkBindingRead,
    OperationKind,
    OperationLedger,
    OperationStatus,
    ParsedHostKey,
    ProcessResult,
    ProcessRunner,
    RemoteExecutionResult,
    ResolvedCredential,
    RuntimeMetadataRead,
    ServiceMetadataRead,
    StorageMetadataRead,
    WebServerMetadataRead,
    parse_host_key_line,
    validate_operation_id,
    validate_string,
)

DEFAULT_KNOWN_HOSTS_ROOT = Path("/var/lib/securityola/appcare/ssh/known_hosts")
_ALLOWED_CUSTODY_ROOTS = tuple(
    Path(item)
    for item in (
        "/etc/securityola/appcare",
        "/var/lib/securityola/appcare",
        "/opt/securityola/appcare-backup-provider",
    )
)
_ALLOWED_LOCAL_BOUNDARY_ROOTS = tuple(
    Path(item)
    for item in (
        "/etc/securityola/appcare",
        "/var/lib/securityola/appcare",
        "/var/log/securityola/appcare",
        "/opt/securityola/appcare-staging",
        "/opt/securityola/appcare-reference-production",
        "/opt/securityola/appcare-backup-provider",
    )
)
_ALLOWED_EXECUTABLES = frozenset({"ssh", "ssh-keyscan"})
_POLL_INTERVAL_SECONDS = 0.01
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def _read_bounded(
    stream: BinaryIO,
    *,
    limit: int,
    output: bytearray,
    limited: threading.Event,
) -> None:
    while not limited.is_set():
        remaining = limit - len(output)
        if remaining <= 0:
            limited.set()
            return
        chunk = stream.read(min(4096, remaining + 1))
        if not chunk:
            return
        if len(chunk) > remaining:
            output.extend(chunk[:remaining])
            limited.set()
            return
        output.extend(chunk)


class OpenSSHProcessRunner:
    """Run only coordinator-built ssh/ssh-keyscan argv with bounded pipes."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        stdout_limit: int,
        stderr_limit: int,
    ) -> ProcessResult:
        if not argv or argv[0] not in _ALLOWED_EXECUTABLES:
            raise CredentialBoundaryError("process executable is not approved")
        if any(not isinstance(argument, str) or not argument for argument in argv):
            raise CredentialBoundaryError("process argument is invalid")
        try:
            process = subprocess.Popen(  # noqa: S603 - argv is closed and shell-free
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
            )
        except OSError:
            return ProcessResult(None, b"", b"", disconnected=True)
        if process.stdout is None or process.stderr is None:
            process.kill()
            process.wait()
            return ProcessResult(None, b"", b"", disconnected=True)

        stdout = bytearray()
        stderr = bytearray()
        limited = threading.Event()
        stdout_thread = threading.Thread(
            target=_read_bounded,
            args=(process.stdout,),
            kwargs={"limit": stdout_limit, "output": stdout, "limited": limited},
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_read_bounded,
            args=(process.stderr,),
            kwargs={"limit": stderr_limit, "output": stderr, "limited": limited},
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        timed_out = False
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            if limited.is_set():
                process.kill()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                break
            time.sleep(_POLL_INTERVAL_SECONDS)
        try:
            returncode = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = None
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        return ProcessResult(
            returncode,
            bytes(stdout),
            bytes(stderr),
            timed_out=timed_out,
            output_limited=limited.is_set() and not timed_out,
            disconnected=returncode == 255,
        )


class OpenSshHostKeyScanner:
    def __init__(self, runner: ProcessRunner) -> None:
        self._runner = runner

    def scan(self, target: LinuxTarget, *, limits: BoundedLimits) -> tuple[str, ...]:
        timeout = max(1, int(limits.connection_timeout_seconds + 0.999))
        result = self._runner.run(
            ("ssh-keyscan", "-T", str(timeout), "-p", str(target.ssh_port), target.host),
            timeout_seconds=limits.connection_timeout_seconds,
            stdout_limit=limits.max_stdout_bytes,
            stderr_limit=limits.max_stderr_bytes,
        )
        if (
            result.returncode != 0
            or result.timed_out
            or result.output_limited
            or result.disconnected
        ):
            raise HostKeyVerificationError("host key scan failed")
        try:
            decoded = result.stdout.decode("ascii")
        except UnicodeDecodeError as exc:
            raise HostKeyVerificationError("host key scan is malformed") from exc
        lines = tuple(
            stripped
            for stripped in (line.strip() for line in decoded.splitlines())
            if stripped and not stripped.startswith("#")
        )
        if not lines or len(lines) > limits.max_records:
            raise HostKeyVerificationError("host key scan is malformed")
        return lines


@dataclass(frozen=True, slots=True)
class VerifiedHostKey:
    parsed: ParsedHostKey
    known_hosts_path: Path


class KnownHostsStore:
    """Target-scoped known-hosts material under an AppCare-owned root."""

    def __init__(self, root: Path = DEFAULT_KNOWN_HOSTS_ROOT) -> None:
        if not root.is_absolute():
            raise HostKeyVerificationError("known-hosts root must be absolute")
        self._root = root

    def persist(self, target: LinuxTarget, parsed: ParsedHostKey) -> VerifiedHostKey:
        self._ensure_directory(self._root, mode=0o700)
        target_dir = (
            self._root / hashlib.sha256(target.target_reference.encode("utf-8")).hexdigest()
        )
        self._ensure_directory(target_dir, mode=0o700)
        known_hosts_path = target_dir / "known_hosts"
        host_token = f"[{target.host}]:{target.ssh_port}"
        line = f"{host_token} {parsed.key_type} {parsed.key_data}\n".encode("ascii")
        existing = self._read_known_hosts(known_hosts_path)
        if existing is not None:
            if existing != line:
                raise HostKeyVerificationError("known-hosts file changed") from None
            return VerifiedHostKey(parsed, known_hosts_path)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= _O_NOFOLLOW
        try:
            descriptor = os.open(str(known_hosts_path), flags, 0o600)
        except FileExistsError:
            existing = self._read_known_hosts(known_hosts_path)
            if existing != line:
                raise HostKeyVerificationError("known-hosts file changed") from None
            return VerifiedHostKey(parsed, known_hosts_path)
        except OSError as exc:
            raise HostKeyVerificationError("known-hosts file cannot be created") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise HostKeyVerificationError("known-hosts file is not regular")
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(line):
                offset += os.write(descriptor, line[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return VerifiedHostKey(parsed, known_hosts_path)

    @staticmethod
    def _ensure_directory(path: Path, *, mode: int) -> None:
        if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
            raise HostKeyVerificationError("known-hosts directory path is unsafe")
        current = Path(path.anchor)
        for part in path.parts:
            if part == path.anchor:
                continue
            current /= part
            try:
                descriptor = os.open(str(current), os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
            except FileNotFoundError:
                try:
                    os.mkdir(str(current), mode)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise HostKeyVerificationError("known-hosts directory is unavailable") from exc
                try:
                    descriptor = os.open(str(current), os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
                except OSError as exc:
                    raise HostKeyVerificationError("known-hosts directory is unsafe") from exc
            except OSError as exc:
                raise HostKeyVerificationError("known-hosts directory is unsafe") from exc
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise HostKeyVerificationError("known-hosts path is not a directory")
                if current == path and metadata.st_mode & 0o077:
                    raise HostKeyVerificationError("known-hosts directory permissions are unsafe")
            finally:
                os.close(descriptor)

    @staticmethod
    def _read_known_hosts(path: Path) -> bytes | None:
        try:
            descriptor = os.open(str(path), os.O_RDONLY | _O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise HostKeyVerificationError("known-hosts file is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise HostKeyVerificationError("known-hosts file permissions are unsafe")
            content = bytearray()
            while len(content) <= 4096:
                chunk = os.read(descriptor, 4097 - len(content))
                if not chunk:
                    return bytes(content)
                content.extend(chunk)
                if len(content) > 4096:
                    raise HostKeyVerificationError("known-hosts file is too large")
            raise HostKeyVerificationError("known-hosts file is too large")
        except OSError as exc:
            raise HostKeyVerificationError("known-hosts file is unreadable") from exc
        finally:
            os.close(descriptor)


def verify_host_key(
    target: LinuxTarget,
    *,
    scanner: HostKeyScanner,
    store: KnownHostsStore,
    limits: BoundedLimits,
) -> VerifiedHostKey:
    lines = scanner.scan(target, limits=limits)
    parsed = tuple(parse_host_key_line(line) for line in lines)
    matches = tuple(
        item for item in parsed if item.fingerprint == target.expected_host_key_fingerprint
    )
    if len(matches) != 1:
        raise HostKeyVerificationError("host key fingerprint mismatch")
    return store.persist(target, matches[0])


class LinuxSSHClient:
    """Typed Linux client; the default evidence mode is fixture-only."""

    def __init__(
        self,
        target: LinuxTarget,
        *,
        credential_provider: CredentialProvider,
        runner: ProcessRunner,
        known_hosts: KnownHostsStore,
        scanner: HostKeyScanner | None = None,
        limits: BoundedLimits | None = None,
        operation_ledger: OperationLedger | None = None,
        command_registry: CommandRegistry | None = None,
    ) -> None:
        self.target = target
        self._credential_provider = credential_provider
        self._runner = runner
        self._known_hosts = known_hosts
        self._scanner = scanner or OpenSshHostKeyScanner(runner)
        self._limits = limits or BoundedLimits()
        self._ledger = operation_ledger or InMemoryOperationLedger()
        self._commands = command_registry or CommandRegistry()
        self._evidence_class = EvidenceClass.FIXTURE

    @classmethod
    def for_live(
        cls,
        target: LinuxTarget,
        *,
        credential_provider: CredentialProvider,
        known_hosts_root: Path = DEFAULT_KNOWN_HOSTS_ROOT,
        limits: BoundedLimits | None = None,
        operation_ledger: OperationLedger | None = None,
    ) -> LinuxSSHClient:
        if not known_hosts_root.is_absolute() or any(
            part in {".", ".."} for part in known_hosts_root.parts
        ):
            raise HostKeyVerificationError("live known-hosts root is unsafe")
        runner = OpenSSHProcessRunner()
        client = cls(
            target,
            credential_provider=credential_provider,
            runner=runner,
            known_hosts=KnownHostsStore(known_hosts_root),
            scanner=OpenSshHostKeyScanner(runner),
            limits=limits,
            operation_ledger=operation_ledger,
        )
        if not any(
            known_hosts_root == root or root in known_hosts_root.parents
            for root in _ALLOWED_LOCAL_BOUNDARY_ROOTS
        ):
            raise HostKeyVerificationError("live known-hosts root is outside AppCare")
        client._evidence_class = EvidenceClass.REAL_TARGET
        return client

    def execute(self, operation: LinuxOperation) -> RemoteExecutionResult:
        operation_id = validate_operation_id(operation.operation_id)
        if not self._ledger.claim(
            target_reference=self.target.target_reference,
            operation_id=operation_id,
        ):
            return self._result(
                operation,
                OperationStatus.REPLAYED,
                "operation_replayed",
            )
        credential = self._credential_provider.resolve(self.target)
        try:
            return self._execute_with_credential(operation, credential)
        finally:
            try:
                self._release_credential(credential)
            except Exception:
                self._ledger.abandon(
                    target_reference=self.target.target_reference,
                    operation_id=operation_id,
                )
                raise

    def _execute_with_credential(
        self, operation: LinuxOperation, credential: ResolvedCredential
    ) -> RemoteExecutionResult:
        if credential.credential_reference != self.target.credential_reference:
            raise CredentialBoundaryError("resolved credential reference mismatches target")
        self._validate_credential_handle(credential.identity_file)
        verified_key = verify_host_key(
            self.target,
            scanner=self._scanner,
            store=self._known_hosts,
            limits=self._limits,
        )
        commands = self._commands.commands_for(operation, target=self.target, limits=self._limits)
        records: list[InventoryRecord] = []
        failures: list[RemoteExecutionResult] = []
        for command in commands:
            result = self._execute_command(
                operation, command, credential.identity_file, verified_key
            )
            if result.status == OperationStatus.PASSED:
                records.extend(result.records)
                if len(records) > self._limits.max_records:
                    return self._result(
                        operation,
                        OperationStatus.OUTPUT_LIMITED,
                        "record_limit_exceeded",
                        records=(),
                    )
                continue
            failures.append(result)
            if operation.kind in {
                OperationKind.CONNECTION_PROBE,
                OperationKind.HOST_INVENTORY,
                OperationKind.SAFE_FILE_READ,
                OperationKind.FILESYSTEM_METADATA_READ,
                OperationKind.APPLICATION_ROOT_VERIFICATION,
                OperationKind.STORAGE_METADATA_READ,
            }:
                return self._result(
                    operation,
                    result.status,
                    result.reason_code,
                    records=tuple(records),
                    stdout_bytes=result.stdout_bytes,
                    stderr_bytes=result.stderr_bytes,
                )
        if failures:
            return self._result(
                operation,
                OperationStatus.PARTIAL,
                "inventory_partial",
                records=tuple(records),
                stdout_bytes=sum(item.stdout_bytes for item in failures),
                stderr_bytes=sum(item.stderr_bytes for item in failures),
            )
        return self._result(operation, OperationStatus.PASSED, "ok", records=tuple(records))

    def _release_credential(self, credential: ResolvedCredential) -> None:
        release = getattr(self._credential_provider, "release", None)
        if release is not None:
            cast(Callable[[ResolvedCredential], None], release)(credential)

    def collect_inventory(self, operation_id: str) -> LinuxInventorySnapshot:
        base = validate_operation_id(operation_id)
        connection = self.execute(ConnectionProbe(f"{base}:connect"))
        if not connection.passed:
            inventory = self._result(
                HostInventory(f"{base}:inventory"),
                OperationStatus.PARTIAL,
                "connection_required",
            )
            return LinuxInventorySnapshot(self.target, connection, inventory, ())

        host = self.execute(HostInventory(f"{base}:host"))
        records = list(host.records)
        required_ok = host.passed
        for index, root in enumerate(self.target.approved_application_roots):
            root_result = self.execute(ApplicationRootVerification(f"{base}:root:{index}", root))
            records.extend(root_result.records)
            required_ok = required_ok and root_result.passed
            metadata_result = self.execute(FilesystemMetadataRead(f"{base}:metadata:{index}", root))
            records.extend(metadata_result.records)
        optional_operations: list[LinuxOperation] = [
            WebServerMetadataRead(f"{base}:web"),
            RuntimeMetadataRead(f"{base}:runtime"),
            NetworkBindingRead(f"{base}:network"),
        ]
        optional_operations.extend(
            ServiceMetadataRead(f"{base}:service:{index}", service)
            for index, service in enumerate(self.target.approved_service_names)
        )
        optional_operations.extend(
            StorageMetadataRead(f"{base}:storage:{index}", root)
            for index, root in enumerate(self.target.approved_application_roots)
        )
        for optional in optional_operations:
            optional_result = self.execute(optional)
            records.extend(optional_result.records)
        status = OperationStatus.PASSED if required_ok else OperationStatus.PARTIAL
        inventory = self._result(
            HostInventory(f"{base}:inventory"),
            status,
            "ok" if required_ok else "inventory_required_observation_failed",
            records=tuple(records[: self._limits.max_records]),
        )
        return LinuxInventorySnapshot(
            self.target,
            connection,
            inventory,
            tuple(records[: self._limits.max_records]),
        )

    def _execute_command(
        self,
        operation: LinuxOperation,
        command: RemoteCommand,
        identity_file: str,
        verified_key: VerifiedHostKey,
    ) -> RemoteExecutionResult:
        argv = self._ssh_argv(command, identity_file, verified_key)
        process = self._runner.run(
            argv,
            timeout_seconds=self._limits.command_timeout_seconds,
            stdout_limit=self._limits.max_stdout_bytes,
            stderr_limit=self._limits.max_stderr_bytes,
        )
        stdout_bytes = len(process.stdout)
        stderr_bytes = len(process.stderr)
        if process.output_limited:
            return self._result(
                operation,
                OperationStatus.OUTPUT_LIMITED,
                "output_limit_exceeded",
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
            )
        if process.timed_out:
            return self._result(
                operation,
                OperationStatus.TIMED_OUT,
                "command_timeout",
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
            )
        if process.disconnected:
            return self._result(
                operation,
                OperationStatus.DISCONNECTED,
                "remote_disconnect",
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
            )
        if process.returncode != 0:
            return self._result(
                operation,
                OperationStatus.FAILED,
                "remote_command_failed",
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
            )
        try:
            records = self._parse_command(command, process.stdout, process.stderr)
        except HostKeyVerificationError:
            return self._result(
                operation,
                OperationStatus.HOST_IDENTITY_FAILED,
                "remote_hostname_mismatch",
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
            )
        except ValueError:
            return self._result(
                operation,
                OperationStatus.MALFORMED,
                "remote_output_malformed",
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
            )
        return self._result(
            operation,
            OperationStatus.PASSED,
            "ok",
            records=records,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
        )

    def _ssh_argv(
        self,
        command: RemoteCommand,
        identity_file: str,
        verified_key: VerifiedHostKey,
    ) -> tuple[str, ...]:
        connect_timeout = max(1, int(self._limits.connection_timeout_seconds + 0.999))
        return (
            "ssh",
            "-p",
            str(self.target.ssh_port),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={verified_key.known_hosts_path}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "UpdateHostkeys=no",
            "-o",
            f"HostKeyAlgorithms={verified_key.parsed.key_type}",
            "-o",
            f"ConnectTimeout={connect_timeout}",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=1",
            "-i",
            identity_file,
            f"{self.target.remote_user}@{self.target.host}",
            *command.argv,
        )

    def _parse_command(
        self,
        command: RemoteCommand,
        stdout: bytes,
        stderr: bytes,
    ) -> tuple[InventoryRecord, ...]:
        if command.operation == OperationKind.CONNECTION_PROBE:
            if stdout or stderr:
                validate_string(
                    (stdout + (b"\n" + stderr if stderr else b"")).decode("utf-8"),
                    field_name="connection_probe_output",
                    maximum=self._limits.max_text_length,
                )
            return ()
        if command.operation == OperationKind.SAFE_FILE_READ:
            return self._parse_safe_file(command, stdout)
        if command.step == "resolved_root":
            resolved = validate_string(
                stdout.decode("utf-8").strip(),
                field_name="resolved_root",
                maximum=1024,
            )
            expected_root = command.argv[-1]
            if resolved != expected_root:
                raise ValueError("approved root resolved outside its lexical boundary")
            return (
                self._record(
                    command,
                    "filesystem_root",
                    expected_root,
                    {"resolved": True},
                ),
            )
        text = (stdout + (b"\n" + stderr if stderr else b"")).decode("utf-8")
        if command.operation == OperationKind.HOST_INVENTORY:
            return self._parse_host_inventory(command, text)
        if command.operation in {
            OperationKind.FILESYSTEM_METADATA_READ,
            OperationKind.APPLICATION_ROOT_VERIFICATION,
        }:
            return self._parse_filesystem_metadata(command, text)
        if command.operation == OperationKind.SERVICE_METADATA_READ:
            return self._parse_key_value(command, text, "service")
        return self._parse_generic(command, text)

    def _parse_host_inventory(
        self, command: RemoteCommand, text: str
    ) -> tuple[InventoryRecord, ...]:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise ValueError("host inventory is empty")
        if command.step == "hostname":
            hostname = validate_string(lines[0], field_name="hostname", maximum=253).casefold()
            if hostname != self.target.expected_hostname:
                raise HostKeyVerificationError("remote hostname mismatch")
            return (self._record(command, "host_identity", hostname, {"hostname": hostname}),)
        if command.step == "kernel":
            kernel = validate_string(lines[0], field_name="kernel", maximum=256)
            return (self._record(command, "kernel", "kernel", {"release": kernel}),)
        allowed = {"ID", "VERSION_ID", "NAME", "PRETTY_NAME"}
        records: list[InventoryRecord] = []
        for line in lines:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key not in allowed:
                continue
            value = value.strip().strip('"')
            safe_value = validate_string(value, field_name=key, maximum=256)
            records.append(
                self._record(
                    command, "operating_system", key.casefold(), {key.casefold(): safe_value}
                )
            )
        if not records:
            raise ValueError("operating system metadata is empty")
        return tuple(records)

    def _parse_filesystem_metadata(
        self, command: RemoteCommand, text: str
    ) -> tuple[InventoryRecord, ...]:
        parts = text.strip().split(",")
        expected = 6 if command.operation == OperationKind.FILESYSTEM_METADATA_READ else 5
        if len(parts) != expected:
            raise ValueError("filesystem metadata is malformed")
        expected_root = (
            command.argv[-1]
            if command.operation
            in {
                OperationKind.FILESYSTEM_METADATA_READ,
                OperationKind.APPLICATION_ROOT_VERIFICATION,
            }
            else ""
        )
        if parts[0] != expected_root:
            raise ValueError("filesystem root identity mismatch")
        kind = validate_string(parts[1], field_name="file_type", maximum=64)
        if kind.casefold() in {
            "symbolic link",
            "fifo",
            "socket",
            "character special file",
            "block special file",
        }:
            raise ValueError("unsafe filesystem type")
        metadata: dict[str, object] = {"file_type": kind}
        for key, value in zip(("owner", "group", "mode"), parts[2:5], strict=False):
            metadata[key] = validate_string(value, field_name=key, maximum=128)
        if expected == 6:
            metadata["bytes"] = self._bounded_integer(parts[5], "bytes")
        return (self._record(command, "filesystem", expected_root, metadata),)

    def _parse_safe_file(
        self, command: RemoteCommand, stdout: bytes
    ) -> tuple[InventoryRecord, ...]:
        if command.step == "file_metadata":
            text = stdout.decode("utf-8").strip()
            file_type, separator, size = text.partition(":")
            if not separator or file_type.casefold() != "regular file":
                raise ValueError("safe file is not regular")
            return (
                self._record(
                    command,
                    "safe_file",
                    command.argv[-1],
                    {"file_type": file_type, "bytes": self._bounded_integer(size, "bytes")},
                ),
            )
        if command.step == "resolved_path":
            resolved = validate_string(
                stdout.decode("utf-8").strip(),
                field_name="resolved_path",
                maximum=1024,
            )
            if resolved != command.argv[-1]:
                raise ValueError("safe file resolved outside approved root")
            return (
                self._record(
                    command,
                    "safe_file",
                    resolved,
                    {"resolved": True},
                ),
            )
        if b"\x00" in stdout:
            return (
                self._record(
                    command,
                    "safe_file_content",
                    command.argv[-1],
                    {
                        "binary": True,
                        "bytes": len(stdout),
                        "sha256": hashlib.sha256(stdout).hexdigest(),
                    },
                ),
            )
        text = stdout.decode("utf-8")
        if any(ord(character) < 32 and character not in "\t\n\r" for character in text):
            raise ValueError("safe file content contains control data")
        validate_string(
            text or "empty",
            field_name="safe_file_content",
            maximum=self._limits.max_text_length,
        )
        if any(
            marker in text.casefold()
            for marker in ("password=", "secret=", "token=", "api_key=", "private_key=")
        ):
            raise ValueError("safe file content is secret-shaped")
        return (
            self._record(
                command,
                "safe_file_content",
                command.argv[-1],
                {
                    "binary": False,
                    "bytes": len(stdout),
                    "line_count": len(text.splitlines()),
                    "sha256": hashlib.sha256(stdout).hexdigest(),
                },
            ),
        )

    def _parse_key_value(
        self, command: RemoteCommand, text: str, record_type: str
    ) -> tuple[InventoryRecord, ...]:
        metadata: dict[str, object] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            safe_key = key.strip().casefold()
            if safe_key not in {"id", "loadstate", "activestate", "substate", "fragmentpath"}:
                continue
            metadata[safe_key] = validate_string(value.strip(), field_name=safe_key, maximum=512)
        if not metadata:
            raise ValueError(f"{record_type} metadata is empty")
        return (self._record(command, record_type, command.argv[-1], metadata),)

    def _parse_generic(self, command: RemoteCommand, text: str) -> tuple[InventoryRecord, ...]:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise ValueError("inventory output is empty")
        if len(lines) > self._limits.max_records:
            raise ValueError("inventory record limit exceeded")
        records: list[InventoryRecord] = []
        for index, line in enumerate(lines):
            safe_line = validate_string(line, field_name="inventory_line", maximum=512)
            records.append(
                self._record(
                    command,
                    command.step,
                    f"{command.step}-{index}",
                    {"summary": safe_line},
                )
            )
        return tuple(records)

    def _record(
        self,
        command: RemoteCommand,
        record_type: str,
        identity: str,
        metadata: dict[str, object],
    ) -> InventoryRecord:
        return InventoryRecord(
            tenant_id=self.target.tenant_id,
            application_id=self.target.application_id,
            target_reference=self.target.target_reference,
            record_type=record_type,
            identity=identity,
            metadata=metadata,
            source_reference=f"linux-ssh/{command.operation.value}/{command.step}",
            evidence_class=self._evidence_class,
            observed_at=datetime.now(UTC),
        )

    @staticmethod
    def _bounded_integer(value: str, field_name: str) -> int:
        try:
            number = int(value)
        except ValueError as exc:
            raise ValueError(f"{field_name} is malformed") from exc
        if number < 0:
            raise ValueError(f"{field_name} is malformed")
        return number

    def _result(
        self,
        operation: LinuxOperation,
        status: OperationStatus,
        reason_code: str,
        *,
        records: tuple[InventoryRecord, ...] = (),
        stdout_bytes: int = 0,
        stderr_bytes: int = 0,
    ) -> RemoteExecutionResult:
        return RemoteExecutionResult(
            operation_id=operation.operation_id,
            operation=operation.kind,
            tenant_id=self.target.tenant_id,
            application_id=self.target.application_id,
            target_reference=self.target.target_reference,
            status=status,
            reason_code=reason_code,
            records=records,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            evidence_class=self._evidence_class,
        )

    def _validate_credential_handle(self, identity_file: str) -> None:
        path = Path(identity_file)
        if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
            raise CredentialBoundaryError("credential handle is outside custody")
        if not any(path == root or root in path.parents for root in _ALLOWED_CUSTODY_ROOTS):
            raise CredentialBoundaryError("credential handle is outside AppCare custody")
        if isinstance(self._runner, OpenSSHProcessRunner):
            try:
                current = Path(path.anchor)
                for part in path.parts[1:]:
                    current /= part
                    try:
                        metadata = os.lstat(current)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISLNK(metadata.st_mode):
                        raise CredentialBoundaryError("credential custody crosses a symlink")
                metadata = os.stat(path, follow_symlinks=False)
            except OSError as exc:
                raise CredentialBoundaryError("credential handle is unavailable") from exc
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o007 or path.is_symlink():
                raise CredentialBoundaryError("credential handle permissions are unsafe")


__all__ = [
    "DEFAULT_KNOWN_HOSTS_ROOT",
    "HostKeyVerificationError",
    "KnownHostsStore",
    "LinuxSSHClient",
    "OpenSSHProcessRunner",
    "OpenSshHostKeyScanner",
    "VerifiedHostKey",
    "verify_host_key",
]
