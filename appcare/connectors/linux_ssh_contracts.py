"""Typed, secret-free contracts for the generic Linux/SSH connector.

The module deliberately contains no free-form command or raw credential field.
It is safe to import from readiness/evidence code without enabling execution.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..readiness.contracts import (
    CapabilityEvidence,
    CapabilityStatus,
    EvidenceClass,
    ReadinessValidationError,
    validate_evidence_reference,
    validate_scope_segment,
)
from ..services.security import contains_credential_like, is_secret_key


class LinuxSSHError(ValueError):
    """Base error for a rejected or unsafe Linux/SSH operation."""


class TargetValidationError(LinuxSSHError):
    """A Linux target is outside the approved identity or path boundary."""


class CredentialBoundaryError(LinuxSSHError):
    """Credential custody or lifecycle validation failed."""


class HostKeyVerificationError(LinuxSSHError):
    """The pre-registered SSH host identity could not be verified."""


class OperationRejected(LinuxSSHError):
    """A typed operation or its inputs are not allowed."""


class OperationStatus(StrEnum):
    PASSED = "passed"
    PARTIAL = "partial"
    PERMISSION_DENIED = "permission_denied"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMITED = "output_limited"
    HOST_IDENTITY_FAILED = "host_identity_failed"
    CREDENTIAL_DENIED = "credential_denied"
    MALFORMED = "malformed"
    DISCONNECTED = "disconnected"
    FAILED = "failed"
    REPLAYED = "replayed"


class OperationKind(StrEnum):
    CONNECTION_PROBE = "connection_probe"
    HOST_INVENTORY = "host_inventory"
    FILESYSTEM_METADATA_READ = "filesystem_metadata_read"
    SAFE_FILE_READ = "safe_file_read"
    SERVICE_METADATA_READ = "service_metadata_read"
    WEB_SERVER_METADATA_READ = "web_server_metadata_read"
    RUNTIME_METADATA_READ = "runtime_metadata_read"
    NETWORK_BINDING_READ = "network_binding_read"
    STORAGE_METADATA_READ = "storage_metadata_read"
    APPLICATION_ROOT_VERIFICATION = "application_root_verification"


class CapabilityClass(StrEnum):
    INVENTORY_READ = "inventory_read"
    FILESYSTEM_READ = "filesystem_read"
    MONITORING_READ = "monitoring_read"
    DATABASE_BACKUP = "database_backup"
    STAGING_CONTROL = "staging_control"
    DEPLOYMENT_CONTROL = "deployment_control"
    PRODUCTION_WRITE = "production_write"


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


_SAFE_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SAFE_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_METADATA_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
DEFAULT_OPERATION_LEDGER_PATH = Path("/var/lib/securityola/appcare/ssh/operation-ledger.db")
LIVE_INVENTORY_RECEIPT_VERIFY_KEY = Path(
    "/etc/securityola/appcare/live-inventory/receipt-signing-public-key"
)
LIVE_INVENTORY_RECEIPT_ATTESTOR_SOCKET = Path(
    "/run/securityola/appcare/live-inventory-attestor.sock"
)
LIVE_RECEIPT_SIGNATURE_ALGORITHM = "ed25519-v1"
_LIVE_RECEIPT_SIGNATURE_BYTES = 64


def _current_uid() -> int:
    if os.name != "posix":
        return -1
    getuid = cast(Callable[[], int], getattr(os, "getuid"))  # noqa: B009
    return getuid()


_FORBIDDEN_INPUT_CHARS = frozenset("\x00\n\r;|&$><*?{}[]()!") | {chr(96)}
_SECRET_ASSIGNMENT = re.compile(
    r"(?:password|passphrase|secret|token|api[_-]?key|authorization|"
    r"private[_-]?key|credential)\s*=",
    re.IGNORECASE,
)
_SECRET_PATH_PARTS = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "authorized_keys",
        "shadow",
        "passwd",
        "credentials",
        "credential",
        "secrets",
        "private",
    }
)
_ALLOWED_KEY_TYPES = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    }
)
SYSTEM_METADATA_PATHS: Final = frozenset({"/etc/os-release", "/etc/hostname"})
READ_ONLY_CAPABILITY_CLASSES: Final = frozenset(
    {
        CapabilityClass.INVENTORY_READ,
        CapabilityClass.FILESYSTEM_READ,
        CapabilityClass.MONITORING_READ,
    }
)
DENIED_CAPABILITY_CLASSES: Final = frozenset(
    {
        CapabilityClass.DATABASE_BACKUP,
        CapabilityClass.STAGING_CONTROL,
        CapabilityClass.DEPLOYMENT_CONTROL,
        CapabilityClass.PRODUCTION_WRITE,
    }
)


def validate_host(value: object, *, field_name: str = "host") -> str:
    if not isinstance(value, str):
        raise TargetValidationError(f"{field_name} is invalid")
    candidate = value.strip().casefold()
    if (
        not candidate
        or len(candidate) > 253
        or any(
            character in _FORBIDDEN_INPUT_CHARS or character.isspace() for character in candidate
        )
        or "/" in candidate
        or "@" in candidate
        or "://" in candidate
        or ".." in candidate
    ):
        raise TargetValidationError(f"{field_name} is invalid")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    labels = candidate.rstrip(".").split(".")
    if not labels or any(_SAFE_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise TargetValidationError(f"{field_name} is invalid")
    return ".".join(labels)


def validate_hostname(value: object, *, field_name: str = "expected_hostname") -> str:
    if not isinstance(value, str):
        raise TargetValidationError(f"{field_name} is invalid")
    candidate = value.strip().casefold().rstrip(".")
    if not candidate or len(candidate) > 253:
        raise TargetValidationError(f"{field_name} is invalid")
    labels = candidate.split(".")
    if any(_SAFE_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise TargetValidationError(f"{field_name} is invalid")
    return ".".join(labels)


def validate_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_535:
        raise TargetValidationError("ssh_port is invalid")
    return value


def validate_fingerprint(value: object) -> str:
    if not isinstance(value, str):
        raise HostKeyVerificationError("host key fingerprint is required")
    candidate = value.strip()
    if _FINGERPRINT.fullmatch(candidate) is None:
        raise HostKeyVerificationError("host key fingerprint is malformed")
    encoded = candidate.split(":", 1)[1]
    try:
        decoded = base64.b64decode(encoded + "=", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HostKeyVerificationError("host key fingerprint is malformed") from exc
    if len(decoded) != hashlib.sha256().digest_size:
        raise HostKeyVerificationError("host key fingerprint is malformed")
    return candidate


def validate_credential_reference(value: object) -> str:
    if not isinstance(value, str):
        raise CredentialBoundaryError("credential reference is invalid")
    candidate = value.strip()
    if (
        len(candidate) > 240
        or ".." in candidate
        or contains_credential_like(candidate)
        or not re.fullmatch(
            r"(?:vault|secret|appcare-secret)://[a-z0-9][a-z0-9._/-]{2,240}",
            candidate,
            re.I,
        )
    ):
        raise CredentialBoundaryError("credential reference is invalid")
    return candidate


def validate_remote_user(value: object) -> str:
    if not isinstance(value, str):
        raise TargetValidationError("remote_user is invalid")
    candidate = value.strip().casefold()
    if candidate == "root" or _SAFE_USER.fullmatch(candidate) is None:
        raise TargetValidationError("remote_user must be a non-root account")
    return candidate


def validate_identifier(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TargetValidationError(f"{field_name} is invalid")
    candidate = value.strip()
    if (
        _SAFE_IDENTIFIER.fullmatch(candidate) is None
        or ".." in candidate
        or any(
            character in _FORBIDDEN_INPUT_CHARS or character.isspace() for character in candidate
        )
    ):
        raise TargetValidationError(f"{field_name} is invalid")
    return candidate


def validate_operation_id(value: object) -> str:
    if not isinstance(value, str) or _SAFE_OPERATION_ID.fullmatch(value.strip()) is None:
        raise OperationRejected("operation_id is invalid")
    return value.strip()


def validate_absolute_root(value: object) -> str:
    if not isinstance(value, str):
        raise TargetValidationError("approved root is invalid")
    candidate = value.strip()
    if (
        not candidate.startswith("/")
        or candidate != str(PurePosixPath(candidate))
        or candidate == "/"
        or any(
            character in _FORBIDDEN_INPUT_CHARS or character.isspace() or ord(character) < 32
            for character in candidate
        )
        or "," in candidate
    ):
        raise TargetValidationError("approved root is invalid")
    parts = PurePosixPath(candidate).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise TargetValidationError("approved root is invalid")
    if candidate in {"/root", "/home", "/var", "/etc", "/proc", "/sys"}:
        raise TargetValidationError("approved root is too broad")
    return candidate


def validate_relative_path(value: object) -> str:
    if not isinstance(value, str):
        raise OperationRejected("relative path is invalid")
    candidate = value.strip()
    if (
        not candidate
        or candidate.startswith("/")
        or "\\" in candidate
        or "%" in candidate
        or any(
            character in _FORBIDDEN_INPUT_CHARS or character.isspace() or ord(character) < 32
            for character in candidate
        )
    ):
        raise OperationRejected("relative path is invalid")
    parts = candidate.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise OperationRejected("relative path is invalid")
    if any(part.casefold() in _SECRET_PATH_PARTS for part in parts):
        raise OperationRejected("secret-bearing path is denied")
    return candidate


def join_approved_path(root: str, relative_path: str) -> str:
    approved_root = validate_absolute_root(root)
    relative = validate_relative_path(relative_path)
    joined = str(PurePosixPath(approved_root, relative))
    if joined != approved_root and not joined.startswith(f"{approved_root}/"):
        raise OperationRejected("path escapes approved root")
    return joined


def validate_system_metadata_path(value: object) -> str:
    if not isinstance(value, str) or value.strip() not in SYSTEM_METADATA_PATHS:
        raise OperationRejected("system metadata path is not approved")
    return value.strip()


def validate_string(value: object, *, field_name: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise LinuxSSHError(f"{field_name} is malformed")
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > maximum
        or any(ord(character) < 32 for character in candidate)
        or contains_credential_like(candidate)
        or _SECRET_ASSIGNMENT.search(candidate) is not None
    ):
        raise LinuxSSHError(f"{field_name} is unsafe")
    return candidate


def _identifier_tuple(values: Sequence[str], *, field_name: str) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise TargetValidationError(f"{field_name} is invalid")
    normalized = tuple(validate_identifier(value, field_name=field_name) for value in values)
    if len(normalized) != len(set(normalized)):
        raise TargetValidationError(f"{field_name} contains duplicates")
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class LinuxTarget:
    tenant_id: str
    application_id: str
    environment: str
    host: str
    expected_hostname: str
    ssh_port: int
    expected_host_key_fingerprint: str
    credential_reference: str
    remote_user: str
    approved_application_roots: tuple[str, ...]
    approved_service_names: tuple[str, ...]
    approved_database_identifiers: tuple[str, ...]
    target_reference: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "tenant_id", validate_scope_segment(self.tenant_id, field_name="tenant_id")
        )
        object.__setattr__(
            self,
            "application_id",
            validate_scope_segment(self.application_id, field_name="application_id"),
        )
        environment = validate_scope_segment(self.environment, field_name="environment").casefold()
        if environment not in {"development", "staging", "production"}:
            raise TargetValidationError("environment is invalid")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "host", validate_host(self.host))
        object.__setattr__(self, "expected_hostname", validate_hostname(self.expected_hostname))
        object.__setattr__(self, "ssh_port", validate_port(self.ssh_port))
        object.__setattr__(
            self,
            "expected_host_key_fingerprint",
            validate_fingerprint(self.expected_host_key_fingerprint),
        )
        object.__setattr__(
            self,
            "credential_reference",
            validate_credential_reference(self.credential_reference),
        )
        object.__setattr__(self, "remote_user", validate_remote_user(self.remote_user))
        roots = tuple(validate_absolute_root(item) for item in self.approved_application_roots)
        if not roots or len(roots) != len(set(roots)):
            raise TargetValidationError("at least one unique approved root is required")
        for index, root in enumerate(roots):
            if any(
                other != root and (root.startswith(f"{other}/") or other.startswith(f"{root}/"))
                for other in roots[:index]
            ):
                raise TargetValidationError("approved roots overlap")
        object.__setattr__(self, "approved_application_roots", tuple(sorted(roots)))
        object.__setattr__(
            self,
            "approved_service_names",
            _identifier_tuple(
                self.approved_service_names,
                field_name="approved_service_name",
            ),
        )
        object.__setattr__(
            self,
            "approved_database_identifiers",
            _identifier_tuple(
                self.approved_database_identifiers,
                field_name="approved_database_identifier",
            ),
        )
        object.__setattr__(
            self,
            "target_reference",
            validate_scope_segment(self.target_reference, field_name="target_reference"),
        )
        if not _is_ip(self.host) and self.host != self.expected_hostname:
            raise TargetValidationError("DNS host and expected hostname do not match")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class BoundedLimits:
    connection_timeout_seconds: float = 8.0
    command_timeout_seconds: float = 12.0
    max_stdout_bytes: int = 65_536
    max_stderr_bytes: int = 8_192
    max_records: int = 128
    max_file_bytes: int = 32_768
    max_text_length: int = 2_048

    def __post_init__(self) -> None:
        if not 0.5 <= self.connection_timeout_seconds <= 60:
            raise OperationRejected("connection timeout is outside bounds")
        if not 0.5 <= self.command_timeout_seconds <= 120:
            raise OperationRejected("command timeout is outside bounds")
        for name in (
            "max_stdout_bytes",
            "max_stderr_bytes",
            "max_records",
            "max_file_bytes",
            "max_text_length",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise OperationRejected(f"{name} is invalid")


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    """A private runtime handle; it is never included in result/evidence models."""

    credential_reference: str
    identity_file: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "credential_reference", validate_credential_reference(self.credential_reference)
        )
        if (
            not isinstance(self.identity_file, str)
            or not self.identity_file.startswith("/")
            or ".." in PurePosixPath(self.identity_file).parts
            or any(
                character in _FORBIDDEN_INPUT_CHARS or character.isspace()
                for character in self.identity_file
            )
        ):
            raise CredentialBoundaryError("credential handle is invalid")


class CredentialProvider(Protocol):
    def resolve(self, target: LinuxTarget) -> ResolvedCredential:
        """Resolve an opaque target reference at the private transport boundary."""


@dataclass(frozen=True, slots=True)
class LinuxCredentialMetadata:
    credential_reference: str
    tenant_id: str
    application_id: str
    version: int = 1
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "credential_reference",
            validate_credential_reference(self.credential_reference),
        )
        object.__setattr__(
            self, "tenant_id", validate_scope_segment(self.tenant_id, field_name="tenant_id")
        )
        object.__setattr__(
            self,
            "application_id",
            validate_scope_segment(self.application_id, field_name="application_id"),
        )
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise CredentialBoundaryError("credential version is invalid")
        if self.issued_at.tzinfo is None or (
            self.expires_at is not None and self.expires_at.tzinfo is None
        ):
            raise CredentialBoundaryError("credential timestamps must be timezone-aware")
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise CredentialBoundaryError("credential expiry is invalid")

    def status(self, now: datetime | None = None) -> CredentialStatus:
        current = now or datetime.now(UTC)
        if self.revoked_at is not None:
            return CredentialStatus.REVOKED
        if self.expires_at is not None and self.expires_at <= current:
            return CredentialStatus.EXPIRED
        return CredentialStatus.ACTIVE


class LinuxCredentialRegistry:
    """Metadata-only lifecycle registry; raw credential material is impossible."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str], LinuxCredentialMetadata] = {}

    def register(self, metadata: LinuxCredentialMetadata) -> LinuxCredentialMetadata:
        key = (metadata.tenant_id, metadata.application_id, metadata.credential_reference)
        if key in self._records:
            raise CredentialBoundaryError("credential reference already exists")
        self._records[key] = metadata
        return metadata

    def get(
        self, *, tenant_id: str, application_id: str, credential_reference: str
    ) -> LinuxCredentialMetadata:
        try:
            return self._records[
                (
                    validate_scope_segment(tenant_id, field_name="tenant_id"),
                    validate_scope_segment(application_id, field_name="application_id"),
                    validate_credential_reference(credential_reference),
                )
            ]
        except KeyError as exc:
            raise CredentialBoundaryError("credential reference is unavailable") from exc

    def revoke(
        self,
        *,
        tenant_id: str,
        application_id: str,
        credential_reference: str,
        now: datetime | None = None,
    ) -> LinuxCredentialMetadata:
        current = self.get(
            tenant_id=tenant_id,
            application_id=application_id,
            credential_reference=credential_reference,
        )
        revoked = LinuxCredentialMetadata(
            credential_reference=current.credential_reference,
            tenant_id=current.tenant_id,
            application_id=current.application_id,
            version=current.version,
            issued_at=current.issued_at,
            expires_at=current.expires_at,
            revoked_at=now or datetime.now(UTC),
        )
        self._records[(current.tenant_id, current.application_id, current.credential_reference)] = (
            revoked
        )
        return revoked

    def rotate(
        self,
        *,
        tenant_id: str,
        application_id: str,
        old_credential_reference: str,
        replacement: LinuxCredentialMetadata,
        now: datetime | None = None,
    ) -> LinuxCredentialMetadata:
        old = self.get(
            tenant_id=tenant_id,
            application_id=application_id,
            credential_reference=old_credential_reference,
        )
        if (
            replacement.tenant_id != old.tenant_id
            or replacement.application_id != old.application_id
            or replacement.version <= old.version
            or replacement.credential_reference == old.credential_reference
        ):
            raise CredentialBoundaryError("credential rotation crosses scope or version")
        self.revoke(
            tenant_id=tenant_id,
            application_id=application_id,
            credential_reference=old_credential_reference,
            now=now,
        )
        return self.register(replacement)


class OperationLedger(Protocol):
    @property
    def durable(self) -> bool:
        """Whether claims survive process restart and use an atomic store."""

    def claim(self, *, target_reference: str, operation_id: str) -> bool:
        """Atomically claim an operation identity once."""


class LiveReceiptAttestor(Protocol):
    """Root-controlled signer for receipts derived from live transport evidence."""

    def attest(self, message: bytes) -> bytes:
        """Return a detached Ed25519 signature from an independent signer."""


def _validate_operation_ledger_path(value: object) -> Path:
    if (
        not isinstance(value, Path)
        or not value.is_absolute()
        or value == Path(value.anchor)
        or any(part in {".", ".."} for part in value.parts)
    ):
        raise CredentialBoundaryError("operation ledger path is unsafe")
    if os.name == "posix":
        current = Path(value.anchor)
        for part in value.parts[1:-1]:
            current /= part
            try:
                metadata = os.lstat(current)
            except (FileNotFoundError, OSError) as exc:
                raise CredentialBoundaryError("operation ledger directory is unavailable") from exc
            mode = stat.S_IMODE(metadata.st_mode)
            owner_is_trusted = metadata.st_uid in {0, _current_uid()}
            shared_sticky_directory = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or not owner_is_trusted
                or (mode & 0o022 and not shared_sticky_directory)
            ):
                raise CredentialBoundaryError("operation ledger directory is unsafe")
    return value


def _prepare_operation_ledger_file(path: Path) -> None:
    if path.is_symlink():
        raise CredentialBoundaryError("operation ledger is a symlink")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CredentialBoundaryError("operation ledger is not a regular file")
        if os.name == "posix" and (
            metadata.st_uid not in {0, _current_uid()} or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise CredentialBoundaryError("operation ledger permissions are unsafe")
    except CredentialBoundaryError:
        raise
    except OSError as exc:
        raise CredentialBoundaryError("operation ledger is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class SqliteOperationLedger:
    """Durable single-use SSH operation claims for the live connector."""

    __slots__ = ("_path",)

    def __init__(self, path: Path = DEFAULT_OPERATION_LEDGER_PATH) -> None:
        self._path = _validate_operation_ledger_path(path)
        _prepare_operation_ledger_file(self._path)
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ssh_operation_claims (
                    target_reference TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    claimed_at TEXT NOT NULL,
                    PRIMARY KEY (target_reference, operation_id)
                )
                """
            )
            connection.commit()
        except sqlite3.Error as exc:
            raise CredentialBoundaryError("operation ledger schema is unavailable") from exc
        finally:
            connection.close()

    @property
    def durable(self) -> bool:
        return True

    @property
    def path(self) -> Path:
        return self._path

    def claim(self, *, target_reference: str, operation_id: str) -> bool:
        target = validate_scope_segment(target_reference, field_name="target_reference")
        operation = validate_operation_id(operation_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO ssh_operation_claims
                    (target_reference, operation_id, claimed_at)
                VALUES (?, ?, ?)
                """,
                (target, operation, datetime.now(UTC).isoformat()),
            )
            accepted = cursor.rowcount == 1
            connection.commit()
            return accepted
        except sqlite3.Error as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise CredentialBoundaryError("operation ledger is unavailable") from exc
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as exc:
            raise CredentialBoundaryError("operation ledger is unavailable") from exc


class InMemoryOperationLedger:
    """Thread-safe fixture ledger; never use it for live SSH execution."""

    durable = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._claimed: set[tuple[str, str]] = set()

    def claim(self, *, target_reference: str, operation_id: str) -> bool:
        key = (
            validate_scope_segment(target_reference, field_name="target_reference"),
            validate_operation_id(operation_id),
        )
        with self._lock:
            if key in self._claimed:
                return False
            self._claimed.add(key)
            return True


@dataclass(frozen=True, slots=True)
class ConnectionProbe:
    operation_id: str
    kind: OperationKind = field(init=False, default=OperationKind.CONNECTION_PROBE)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))


@dataclass(frozen=True, slots=True)
class HostInventory:
    operation_id: str
    kind: OperationKind = field(init=False, default=OperationKind.HOST_INVENTORY)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))


@dataclass(frozen=True, slots=True)
class FilesystemMetadataRead:
    operation_id: str
    approved_root: str
    kind: OperationKind = field(init=False, default=OperationKind.FILESYSTEM_METADATA_READ)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(self, "approved_root", validate_absolute_root(self.approved_root))


@dataclass(frozen=True, slots=True)
class SafeFileRead:
    operation_id: str
    approved_root: str
    relative_path: str
    kind: OperationKind = field(init=False, default=OperationKind.SAFE_FILE_READ)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(self, "approved_root", validate_absolute_root(self.approved_root))
        object.__setattr__(self, "relative_path", validate_relative_path(self.relative_path))


@dataclass(frozen=True, slots=True)
class ServiceMetadataRead:
    operation_id: str
    service_name: str
    kind: OperationKind = field(init=False, default=OperationKind.SERVICE_METADATA_READ)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(
            self, "service_name", validate_identifier(self.service_name, field_name="service_name")
        )


@dataclass(frozen=True, slots=True)
class WebServerMetadataRead:
    operation_id: str
    kind: OperationKind = field(init=False, default=OperationKind.WEB_SERVER_METADATA_READ)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))


@dataclass(frozen=True, slots=True)
class RuntimeMetadataRead:
    operation_id: str
    kind: OperationKind = field(init=False, default=OperationKind.RUNTIME_METADATA_READ)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))


@dataclass(frozen=True, slots=True)
class NetworkBindingRead:
    operation_id: str
    kind: OperationKind = field(init=False, default=OperationKind.NETWORK_BINDING_READ)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))


@dataclass(frozen=True, slots=True)
class StorageMetadataRead:
    operation_id: str
    approved_root: str
    kind: OperationKind = field(init=False, default=OperationKind.STORAGE_METADATA_READ)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(self, "approved_root", validate_absolute_root(self.approved_root))


@dataclass(frozen=True, slots=True)
class ApplicationRootVerification:
    operation_id: str
    approved_root: str
    kind: OperationKind = field(init=False, default=OperationKind.APPLICATION_ROOT_VERIFICATION)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(self, "approved_root", validate_absolute_root(self.approved_root))


type LinuxOperation = (
    ConnectionProbe
    | HostInventory
    | FilesystemMetadataRead
    | SafeFileRead
    | ServiceMetadataRead
    | WebServerMetadataRead
    | RuntimeMetadataRead
    | NetworkBindingRead
    | StorageMetadataRead
    | ApplicationRootVerification
)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_limited: bool = False
    disconnected: bool = False


class ProcessRunner(Protocol):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        stdout_limit: int,
        stderr_limit: int,
    ) -> ProcessResult:
        """Run a coordinator-built executable argv without a shell."""


class HostKeyScanner(Protocol):
    def scan(self, target: LinuxTarget, *, limits: BoundedLimits) -> tuple[str, ...]:
        """Return bounded public-key lines for the target address."""


@dataclass(frozen=True, slots=True)
class ParsedHostKey:
    key_type: str
    key_data: str
    fingerprint: str


def parse_host_key_line(line: str) -> ParsedHostKey:
    if not isinstance(line, str) or any(ord(character) < 32 for character in line):
        raise HostKeyVerificationError("host key observation is malformed")
    parts = line.strip().split()
    if len(parts) < 3 or parts[1] not in _ALLOWED_KEY_TYPES:
        raise HostKeyVerificationError("host key observation is malformed")
    key_data = parts[2]
    try:
        key_blob = base64.b64decode(key_data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HostKeyVerificationError("host key observation is malformed") from exc
    if not key_blob:
        raise HostKeyVerificationError("host key observation is malformed")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode(
        "ascii"
    ).rstrip("=")
    return ParsedHostKey(parts[1], key_data, fingerprint)


@dataclass(frozen=True, slots=True)
class InventoryRecord:
    tenant_id: str
    application_id: str
    target_reference: str
    record_type: str
    identity: str
    metadata: Mapping[str, object]
    source_reference: str
    evidence_class: EvidenceClass
    observed_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "tenant_id", validate_scope_segment(self.tenant_id, field_name="tenant_id")
        )
        object.__setattr__(
            self,
            "application_id",
            validate_scope_segment(self.application_id, field_name="application_id"),
        )
        object.__setattr__(
            self,
            "target_reference",
            validate_scope_segment(self.target_reference, field_name="target_reference"),
        )
        object.__setattr__(
            self, "record_type", validate_scope_segment(self.record_type, field_name="record_type")
        )
        object.__setattr__(
            self, "identity", validate_string(self.identity, field_name="identity", maximum=256)
        )
        object.__setattr__(
            self,
            "source_reference",
            validate_evidence_reference(self.source_reference, field_name="source_reference"),
        )
        if not isinstance(self.evidence_class, EvidenceClass):
            try:
                object.__setattr__(
                    self,
                    "evidence_class",
                    EvidenceClass(str(self.evidence_class).strip().casefold()),
                )
            except ValueError as exc:
                raise LinuxSSHError("evidence class is invalid") from exc
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise LinuxSSHError("observation timestamp must be timezone-aware")
        normalized: dict[str, object] = {}
        if not isinstance(self.metadata, Mapping) or len(self.metadata) > 32:
            raise LinuxSSHError("inventory metadata is malformed")
        for key, value in self.metadata.items():
            if not isinstance(key, str) or _SAFE_METADATA_KEY.fullmatch(key) is None:
                raise LinuxSSHError("inventory metadata key is unsafe")
            if is_secret_key(key) or contains_credential_like(value):
                raise LinuxSSHError("inventory metadata contains credential-like data")
            if value is not None and not isinstance(value, (str, int, float, bool)):
                raise LinuxSSHError("inventory metadata value is unsupported")
            if isinstance(value, str):
                normalized[key] = validate_string(value, field_name=key, maximum=512)
            else:
                normalized[key] = value
        object.__setattr__(self, "metadata", dict(sorted(normalized.items())))

    def canonical_payload(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "target_reference": self.target_reference,
            "record_type": self.record_type,
            "identity": self.identity,
            "metadata": dict(self.metadata),
            "source_reference": self.source_reference,
            "evidence_class": self.evidence_class.value,
            "observed_at": self.observed_at.astimezone(UTC).isoformat(),
        }

    @property
    def evidence_digest(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def required_inventory_records_complete(
    target: LinuxTarget, records: Sequence[InventoryRecord]
) -> bool:
    """Verify the coordinator-owned minimum inventory observation set."""

    if any(not isinstance(record, InventoryRecord) for record in records):
        return False
    if any(not isinstance(record.metadata, Mapping) for record in records):
        return False
    if any(
        record.tenant_id != target.tenant_id
        or record.application_id != target.application_id
        or record.target_reference != target.target_reference
        for record in records
    ):
        return False

    required: list[tuple[str, str, str, Callable[[Mapping[str, object]], bool]]] = []

    def add(
        operation: OperationKind,
        step: str,
        record_type: str,
        identity: str,
        validator: Callable[[Mapping[str, object]], bool],
    ) -> None:
        required.append((f"linux-ssh/{operation.value}/{step}", record_type, identity, validator))

    def non_empty_text(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def host_identity(metadata: Mapping[str, object]) -> bool:
        return metadata.get("hostname") == target.expected_hostname

    def kernel(metadata: Mapping[str, object]) -> bool:
        return non_empty_text(metadata.get("release"))

    def os_id(metadata: Mapping[str, object]) -> bool:
        return non_empty_text(metadata.get("id"))

    def os_version(metadata: Mapping[str, object]) -> bool:
        return non_empty_text(metadata.get("version_id"))

    def resolved_root(metadata: Mapping[str, object]) -> bool:
        return metadata.get("resolved") is True

    def root_metadata(metadata: Mapping[str, object]) -> bool:
        return all(
            non_empty_text(metadata.get(key)) for key in ("file_type", "owner", "group", "mode")
        )

    def filesystem_metadata(metadata: Mapping[str, object]) -> bool:
        bytes_value = metadata.get("bytes")
        device = metadata.get("device")
        inode = metadata.get("inode")
        return (
            root_metadata(metadata)
            and isinstance(bytes_value, int)
            and not isinstance(bytes_value, bool)
            and bytes_value >= 0
            and isinstance(device, int)
            and not isinstance(device, bool)
            and device >= 0
            and isinstance(inode, int)
            and not isinstance(inode, bool)
            and inode >= 0
        )

    add(
        OperationKind.HOST_INVENTORY,
        "hostname",
        "host_identity",
        target.expected_hostname,
        host_identity,
    )
    add(OperationKind.HOST_INVENTORY, "kernel", "kernel", "kernel", kernel)
    add(OperationKind.HOST_INVENTORY, "os_release", "operating_system", "id", os_id)
    add(
        OperationKind.HOST_INVENTORY,
        "os_release",
        "operating_system",
        "version_id",
        os_version,
    )
    for root in target.approved_application_roots:
        add(
            OperationKind.APPLICATION_ROOT_VERIFICATION,
            "resolved_root",
            "filesystem_root",
            root,
            resolved_root,
        )
        add(
            OperationKind.APPLICATION_ROOT_VERIFICATION,
            "root",
            "filesystem",
            root,
            root_metadata,
        )
        add(
            OperationKind.FILESYSTEM_METADATA_READ,
            "resolved_root",
            "filesystem_root",
            root,
            resolved_root,
        )
        add(
            OperationKind.FILESYSTEM_METADATA_READ,
            "metadata",
            "filesystem",
            root,
            filesystem_metadata,
        )

    for source, record_type, identity, validator in required:
        matches = tuple(
            record
            for record in records
            if record.source_reference == source
            and record.record_type == record_type
            and record.identity == identity
        )
        if len(matches) != 1 or not validator(matches[0].metadata):
            return False

    # OS release may include optional NAME/PRETTY_NAME records. Every other
    # required source must contain exactly the one typed observation expected.
    allowed_by_source: dict[str, set[tuple[str, str]]] = {}
    for source, record_type, identity, _ in required:
        allowed_by_source.setdefault(source, set()).add((record_type, identity))
    os_source = f"linux-ssh/{OperationKind.HOST_INVENTORY.value}/os_release"
    allowed_by_source[os_source].update(
        {
            ("operating_system", "name"),
            ("operating_system", "pretty_name"),
        }
    )
    for source, allowed in allowed_by_source.items():
        source_records = tuple(record for record in records if record.source_reference == source)
        if any((record.record_type, record.identity) not in allowed for record in source_records):
            return False
        for record_type, identity in allowed:
            if (
                sum(
                    record.record_type == record_type and record.identity == identity
                    for record in source_records
                )
                > 1
            ):
                return False
    return True


@dataclass(frozen=True, slots=True)
class RemoteExecutionResult:
    operation_id: str
    operation: OperationKind
    tenant_id: str
    application_id: str
    target_reference: str
    status: OperationStatus
    reason_code: str
    records: tuple[InventoryRecord, ...] = ()
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(
            self, "tenant_id", validate_scope_segment(self.tenant_id, field_name="tenant_id")
        )
        object.__setattr__(
            self,
            "application_id",
            validate_scope_segment(self.application_id, field_name="application_id"),
        )
        object.__setattr__(
            self,
            "target_reference",
            validate_scope_segment(self.target_reference, field_name="target_reference"),
        )
        if not isinstance(self.operation, OperationKind):
            object.__setattr__(
                self,
                "operation",
                OperationKind(str(self.operation).strip().casefold()),
            )
        if not isinstance(self.status, OperationStatus):
            object.__setattr__(
                self,
                "status",
                OperationStatus(str(self.status).strip().casefold()),
            )
        object.__setattr__(
            self, "reason_code", validate_scope_segment(self.reason_code, field_name="reason_code")
        )
        if not isinstance(self.evidence_class, EvidenceClass):
            object.__setattr__(
                self,
                "evidence_class",
                EvidenceClass(str(self.evidence_class).strip().casefold()),
            )
        if self.stdout_bytes < 0 or self.stderr_bytes < 0:
            raise LinuxSSHError("output byte counts are invalid")
        if len(self.records) > 128:
            raise LinuxSSHError("too many inventory records")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise LinuxSSHError("observation timestamp must be timezone-aware")

    @property
    def passed(self) -> bool:
        return self.status == OperationStatus.PASSED

    @property
    def evidence_digest(self) -> str:
        payload = {
            "operation_id": self.operation_id,
            "operation": self.operation.value,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "target_reference": self.target_reference,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "records": [record.canonical_payload() for record in self.records],
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "evidence_class": self.evidence_class.value,
            "observed_at": self.observed_at.astimezone(UTC).isoformat(),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


LIVE_INVENTORY_RECEIPT_ROOT: Final = Path("/var/lib/securityola/appcare/evidence/live-inventory")
_MAX_LIVE_RECEIPT_BYTES: Final = 64 * 1024


def _live_source_binding_payload(
    target: LinuxTarget,
    records: Sequence[InventoryRecord],
) -> dict[str, object]:
    """Persist the typed target-host identity used by live revision capture."""

    host_records = tuple(
        record
        for record in records
        if record.source_reference == "linux-ssh/host_inventory/hostname"
        and record.record_type == "host_identity"
        and record.identity == target.expected_hostname
    )
    roots: list[dict[str, object]] = []
    for approved_root in target.approved_application_roots:
        matches = tuple(
            record
            for record in records
            if record.source_reference == "linux-ssh/filesystem_metadata_read/metadata"
            and record.record_type == "filesystem"
            and record.identity == approved_root
        )
        if len(matches) != 1:
            continue
        record = matches[0]
        device = record.metadata.get("device")
        inode = record.metadata.get("inode")
        roots.append(
            {
                "approved_root": approved_root,
                "device": device,
                "inode": inode,
                "record_evidence_digest": record.evidence_digest,
            }
        )
    return {
        "host_identity": host_records[0].identity if len(host_records) == 1 else None,
        "host_record_evidence_digest": (
            host_records[0].evidence_digest if len(host_records) == 1 else None
        ),
        "roots": roots,
    }


def _live_snapshot_receipt_payload(
    target: LinuxTarget,
    connection: RemoteExecutionResult,
    inventory: RemoteExecutionResult,
    records: Sequence[InventoryRecord],
    *,
    receipt_path: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "receipt_signature_algorithm": LIVE_RECEIPT_SIGNATURE_ALGORITHM,
        "sealed": True,
        "receipt_path": receipt_path,
        "target": {
            "tenant_id": target.tenant_id,
            "application_id": target.application_id,
            "environment": target.environment,
            "host": target.host,
            "expected_hostname": target.expected_hostname,
            "ssh_port": target.ssh_port,
            "expected_host_key_fingerprint": target.expected_host_key_fingerprint,
            "credential_reference": target.credential_reference,
            "remote_user": target.remote_user,
            "approved_application_roots": list(target.approved_application_roots),
            "approved_service_names": list(target.approved_service_names),
            "approved_database_identifiers": list(target.approved_database_identifiers),
            "target_reference": target.target_reference,
        },
        "connection_operation_id": connection.operation_id,
        "connection_evidence_digest": connection.evidence_digest,
        "inventory_operation_id": inventory.operation_id,
        "inventory_evidence_digest": inventory.evidence_digest,
        "record_evidence_digests": [record.evidence_digest for record in records],
        "source_binding": _live_source_binding_payload(target, records),
        "evidence_reference": (
            f"live://{target.target_reference}/inventory/{inventory.evidence_digest}"
        ),
    }


def live_snapshot_receipt_path(target: LinuxTarget, operation_id: str) -> Path:
    operation = validate_operation_id(operation_id)
    return LIVE_INVENTORY_RECEIPT_ROOT / target.target_reference / f"{operation}.json"


def _read_live_receipt(path: Path) -> dict[str, object] | None:
    if not _is_safe_live_receipt_path(path):
        return None
    if not _trusted_receipt_ancestry(path.parent):
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not _trusted_receipt_file_metadata(metadata)
            or metadata.st_size > _MAX_LIVE_RECEIPT_BYTES
        ):
            return None
        content = bytearray()
        while len(content) <= _MAX_LIVE_RECEIPT_BYTES:
            chunk = os.read(descriptor, _MAX_LIVE_RECEIPT_BYTES + 1 - len(content))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > _MAX_LIVE_RECEIPT_BYTES:
            return None
    except OSError:
        return None
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(bytes(content).decode("utf-8"))
    except (UnicodeError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _is_safe_live_receipt_path(path: Path) -> bool:
    if not path.is_absolute() or path.is_symlink():
        return False
    try:
        root = LIVE_INVENTORY_RECEIPT_ROOT
        return (
            root == path.parents[1]
            and root.resolve(strict=True) == root
            and path.parent.resolve(strict=True) == path.parent
        )
    except (IndexError, OSError, RuntimeError):
        return False


def _trusted_receipt_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or (
        metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX
    ):
        return False
    return os.name != "posix" or metadata.st_uid in {0, _current_uid()}


def _trusted_receipt_file_metadata(metadata: os.stat_result) -> bool:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
        return False
    return os.name != "posix" or metadata.st_uid in {0, _current_uid()}


def _trusted_receipt_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return _trusted_receipt_file_metadata(metadata)


def _trusted_receipt_ancestry(path: Path) -> bool:
    if not path.is_absolute():
        return False
    current = path
    while True:
        if not _trusted_receipt_directory(current):
            return False
        if current == Path(current.anchor):
            return True
        current = current.parent


def _receipt_digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _receipt_signature_message(payload: Mapping[str, object], digest: str) -> bytes:
    signed = dict(payload)
    signed["receipt_digest"] = digest
    return json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _read_receipt_verify_key() -> bytes | None:
    path = LIVE_INVENTORY_RECEIPT_VERIFY_KEY
    if os.name == "posix":
        if not _trusted_receipt_ancestry(path.parent):
            return None
        try:
            metadata = path.lstat()
        except OSError:
            return None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_size != 32
        ):
            return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != 32
            or (os.name == "posix" and (metadata.st_uid != 0 or metadata.st_mode & 0o022))
        ):
            return None
        content = os.read(descriptor, 33)
        if len(content) != 32:
            return None
        return content
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _verify_receipt_auth(
    payload: Mapping[str, object],
    supplied_digest: object,
    supplied_signature: object,
) -> bool:
    if (
        not isinstance(supplied_digest, str)
        or len(supplied_digest) != 64
        or any(character not in "0123456789abcdef" for character in supplied_digest)
        or payload.get("receipt_signature_algorithm") != LIVE_RECEIPT_SIGNATURE_ALGORITHM
        or not isinstance(supplied_signature, str)
    ):
        return False
    try:
        signature = base64.b64decode(supplied_signature, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return False
    if len(signature) != _LIVE_RECEIPT_SIGNATURE_BYTES:
        return False
    expected_digest = _receipt_digest(payload)
    if not hmac.compare_digest(supplied_digest, expected_digest):
        return False
    key_material = _read_receipt_verify_key()
    if key_material is None:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(key_material)
        key.verify(signature, _receipt_signature_message(payload, supplied_digest))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def verify_live_snapshot_receipt(snapshot: LinuxInventorySnapshot) -> bool:
    """Validate the durable, sanitized receipt emitted by live transport."""

    if snapshot._live_receipt_path is None:
        return False
    expected_path = live_snapshot_receipt_path(snapshot.target, snapshot.inventory.operation_id)
    if Path(snapshot._live_receipt_path) != expected_path:
        return False
    payload = _read_live_receipt(expected_path)
    if payload is None:
        return False
    supplied_signature = payload.pop("receipt_signature", None)
    supplied_digest = payload.pop("receipt_digest", None)
    if not _verify_receipt_auth(payload, supplied_digest, supplied_signature):
        return False
    expected = _live_snapshot_receipt_payload(
        snapshot.target,
        snapshot.connection,
        snapshot.inventory,
        snapshot.records,
        receipt_path=expected_path.as_posix(),
    )
    return payload == expected


def verify_live_capture_receipt_reference(
    path: str,
    *,
    tenant_id: str,
    application_id: str,
    target_reference: str,
    host_identity: str,
    approved_root: str,
    inventory_evidence_digest: str | None,
    evidence_reference: str,
    source_host_identity: str | None = None,
    source_root_identity: tuple[int, int] | None = None,
) -> bool:
    """Validate a live revision's reference against the durable receipt."""

    receipt_path = Path(path)
    try:
        validate_operation_id(receipt_path.stem)
    except (LinuxSSHError, ValueError):
        return False
    if receipt_path.parent != LIVE_INVENTORY_RECEIPT_ROOT / target_reference:
        return False
    if not _trusted_receipt_directory(LIVE_INVENTORY_RECEIPT_ROOT):
        return False
    payload = _read_live_receipt(receipt_path)
    if payload is None:
        return False
    supplied_signature = payload.pop("receipt_signature", None)
    supplied_digest = payload.pop("receipt_digest", None)
    if not _verify_receipt_auth(payload, supplied_digest, supplied_signature):
        return False
    target = payload.get("target")
    if not isinstance(target, dict):
        return False
    roots = target.get("approved_application_roots")
    source_binding = payload.get("source_binding")
    if (
        source_host_identity is None
        or source_root_identity is None
        or not isinstance(source_binding, dict)
        or source_binding.get("host_identity") != source_host_identity
        or source_host_identity != host_identity
    ):
        return False
    binding_roots = source_binding.get("roots")
    record_digests = payload.get("record_evidence_digests")
    host_record_digest = source_binding.get("host_record_evidence_digest")
    if (
        not isinstance(roots, (tuple, list))
        or any(not isinstance(root, str) for root in roots)
        or not isinstance(binding_roots, (tuple, list))
        or len(binding_roots) != len(roots)
        or not isinstance(record_digests, (tuple, list))
        or not isinstance(host_record_digest, str)
        or len(host_record_digest) != 64
        or any(character not in "0123456789abcdef" for character in host_record_digest)
        or host_record_digest not in record_digests
    ):
        return False
    seen_roots: set[str] = set()
    selected_root_binding: dict[str, object] | None = None
    for binding in binding_roots:
        if not isinstance(binding, dict):
            return False
        bound_root = binding.get("approved_root")
        device = binding.get("device")
        inode = binding.get("inode")
        record_digest = binding.get("record_evidence_digest")
        if (
            not isinstance(bound_root, str)
            or bound_root in seen_roots
            or not isinstance(roots, (tuple, list))
            or bound_root not in roots
            or isinstance(device, bool)
            or not isinstance(device, int)
            or device < 0
            or isinstance(inode, bool)
            or not isinstance(inode, int)
            or inode < 0
            or not isinstance(record_digest, str)
            or len(record_digest) != 64
            or any(character not in "0123456789abcdef" for character in record_digest)
            or record_digest not in record_digests
        ):
            return False
        seen_roots.add(bound_root)
        if bound_root == approved_root:
            selected_root_binding = binding
    if (
        not isinstance(roots, (tuple, list))
        or seen_roots != set(roots)
        or selected_root_binding is None
        or selected_root_binding.get("device") != source_root_identity[0]
        or selected_root_binding.get("inode") != source_root_identity[1]
    ):
        return False
    return (
        payload.get("schema_version") == 1
        and payload.get("sealed") is True
        and payload.get("receipt_path") == receipt_path.as_posix()
        and target.get("tenant_id") == tenant_id
        and target.get("application_id") == application_id
        and target.get("target_reference") == target_reference
        and target.get("expected_hostname") == host_identity
        and isinstance(roots, (tuple, list))
        and approved_root in roots
        and (
            inventory_evidence_digest is None
            or payload.get("inventory_evidence_digest") == inventory_evidence_digest
        )
        and payload.get("evidence_reference") == evidence_reference
    )


@dataclass(frozen=True, slots=True)
class LinuxInventorySnapshot:
    target: LinuxTarget
    connection: RemoteExecutionResult
    inventory: RemoteExecutionResult
    records: tuple[InventoryRecord, ...]
    _live_receipt_path: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self.connection.tenant_id != self.target.tenant_id
            or self.inventory.tenant_id != self.target.tenant_id
            or self.connection.application_id != self.target.application_id
            or self.inventory.application_id != self.target.application_id
            or self.connection.target_reference != self.target.target_reference
            or self.inventory.target_reference != self.target.target_reference
        ):
            raise ReadinessValidationError("Linux inventory crosses target scope")
        object.__setattr__(self, "records", tuple(self.records))
        if len(self.records) > 128:
            raise LinuxSSHError("inventory record limit exceeded")

    @property
    def complete(self) -> bool:
        return self._inventory_supported

    @property
    def live_attested(self) -> bool:
        """True only for snapshots emitted by the live transport boundary."""

        return verify_live_snapshot_receipt(self)

    @property
    def live_receipt_path(self) -> str | None:
        return self._live_receipt_path

    def live_source_binding(self, approved_root: str) -> tuple[str, tuple[int, int]] | None:
        """Return the target-host identity bound to required live observations."""

        if not self.complete or not self.live_attested:
            return None
        if approved_root not in self.target.approved_application_roots:
            return None
        host_records = tuple(
            record
            for record in self.records
            if record.source_reference == "linux-ssh/host_inventory/hostname"
            and record.record_type == "host_identity"
            and record.identity == self.target.expected_hostname
        )
        root_records = tuple(
            record
            for record in self.records
            if record.source_reference == "linux-ssh/filesystem_metadata_read/metadata"
            and record.record_type == "filesystem"
            and record.identity in self.target.approved_application_roots
        )
        if len(host_records) != 1 or len(root_records) != len(
            self.target.approved_application_roots
        ):
            return None
        root_record = next(
            (record for record in root_records if record.identity == approved_root),
            None,
        )
        if root_record is None:
            return None
        device = root_record.metadata.get("device")
        inode = root_record.metadata.get("inode")
        if (
            isinstance(device, bool)
            or not isinstance(device, int)
            or device < 0
            or isinstance(inode, bool)
            or not isinstance(inode, int)
            or inode < 0
        ):
            return None
        return self.target.expected_hostname, (device, inode)

    @property
    def _inventory_supported(self) -> bool:
        return (
            self._result_matches_target(self.connection)
            and self._result_matches_target(self.inventory)
            and self.connection.operation == OperationKind.CONNECTION_PROBE
            and self.connection.passed
            and self.inventory.operation == OperationKind.HOST_INVENTORY
            and self.inventory.passed
            and self.connection.evidence_class == self.inventory.evidence_class
            and self.inventory.records == self.records
            and all(
                record.evidence_class == self.inventory.evidence_class for record in self.records
            )
            and required_inventory_records_complete(self.target, self.records)
        )

    def _result_matches_target(self, result: RemoteExecutionResult) -> bool:
        return (
            result.tenant_id == self.target.tenant_id
            and result.application_id == self.target.application_id
            and result.target_reference == self.target.target_reference
        )

    @property
    def evidence_class(self) -> EvidenceClass:
        return self.inventory.evidence_class

    def capability_evidence(self, *, stack_id: str) -> tuple[CapabilityEvidence, ...]:
        stack = validate_scope_segment(stack_id, field_name="stack_id")
        evidence: list[CapabilityEvidence] = []
        inventory_supported = self._inventory_supported
        connection_supported = (
            self._result_matches_target(self.connection)
            and self.connection.operation == OperationKind.CONNECTION_PROBE
            and self.connection.passed
            and self.connection.evidence_class == self.inventory.evidence_class
        )
        for capability, result in (
            ("connect", self.connection),
            ("inventory", self.inventory),
        ):
            supported = connection_supported if capability == "connect" else inventory_supported
            status = CapabilityStatus.SUPPORTED if supported else CapabilityStatus.UNSUPPORTED
            evidence.append(
                CapabilityEvidence(
                    tenant_id=self.target.tenant_id,
                    application_id=self.target.application_id,
                    stack_id=stack,
                    capability=capability,
                    status=status,
                    evidence_class=result.evidence_class,
                    evidence_ref=(
                        f"linux-ssh/{self.target.target_reference}/{result.operation_id}"
                    ),
                    observed_at=result.observed_at,
                )
            )
        return tuple(evidence)


__all__ = [
    "ApplicationRootVerification",
    "BoundedLimits",
    "CapabilityClass",
    "ConnectionProbe",
    "CredentialBoundaryError",
    "CredentialProvider",
    "CredentialStatus",
    "DEFAULT_OPERATION_LEDGER_PATH",
    "DENIED_CAPABILITY_CLASSES",
    "EvidenceClass",
    "FilesystemMetadataRead",
    "HostInventory",
    "HostKeyScanner",
    "HostKeyVerificationError",
    "InMemoryOperationLedger",
    "InventoryRecord",
    "LIVE_INVENTORY_RECEIPT_VERIFY_KEY",
    "LIVE_INVENTORY_RECEIPT_ATTESTOR_SOCKET",
    "LIVE_RECEIPT_SIGNATURE_ALGORITHM",
    "LiveReceiptAttestor",
    "LinuxCredentialMetadata",
    "LinuxCredentialRegistry",
    "LinuxInventorySnapshot",
    "LinuxOperation",
    "LinuxSSHError",
    "LinuxTarget",
    "NetworkBindingRead",
    "OperationKind",
    "OperationLedger",
    "OperationRejected",
    "OperationStatus",
    "SqliteOperationLedger",
    "ParsedHostKey",
    "ProcessResult",
    "ProcessRunner",
    "READ_ONLY_CAPABILITY_CLASSES",
    "RemoteExecutionResult",
    "ResolvedCredential",
    "RuntimeMetadataRead",
    "SafeFileRead",
    "ServiceMetadataRead",
    "StorageMetadataRead",
    "SYSTEM_METADATA_PATHS",
    "TargetValidationError",
    "WebServerMetadataRead",
    "join_approved_path",
    "parse_host_key_line",
    "required_inventory_records_complete",
    "validate_absolute_root",
    "validate_credential_reference",
    "validate_fingerprint",
    "validate_host",
    "validate_hostname",
    "validate_identifier",
    "validate_operation_id",
    "validate_port",
    "validate_relative_path",
    "validate_remote_user",
    "validate_system_metadata_path",
]
