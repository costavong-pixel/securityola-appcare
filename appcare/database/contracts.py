"""Typed, fail-closed contracts for bounded database backup operations.

Spec 015 deliberately exposes no free-form SQL, shell, argv, binary path, or
credential value.  The contracts bind every operation to the existing Spec
014 Linux target and to the existing AppCare backup filesystem boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ..backups.contracts import validate_backup_id
from ..connectors.linux_ssh_contracts import (
    LinuxTarget,
    validate_fingerprint,
    validate_host,
    validate_port,
)
from ..readiness.contracts import (
    EvidenceClass,
    validate_digest,
    validate_evidence_reference,
    validate_revision,
    validate_scope_segment,
)
from ..services.security import contains_credential_like

if TYPE_CHECKING:
    from ..backups.paths import BackupFilesystemBoundary


class DatabaseBoundaryError(ValueError):
    """Base error for a rejected database target or operation."""


class DatabaseTargetError(DatabaseBoundaryError):
    """A database target is malformed or crosses an approved scope."""


class DatabaseCredentialError(DatabaseBoundaryError):
    """Credential metadata or runtime custody is invalid."""


class DatabaseOperationRejected(DatabaseBoundaryError):
    """A typed operation is outside the closed database execution surface."""


class DatabaseArtifactError(DatabaseBoundaryError):
    """A dump artifact, manifest, or checksum is invalid."""


class DatabaseRestoreError(DatabaseBoundaryError):
    """A restore target or restore provenance is invalid."""


class DatabaseKind(StrEnum):
    MARIADB_MYSQL = "mariadb_mysql"
    POSTGRESQL = "postgresql"


class DatabaseDumpFormat(StrEnum):
    SQL = "sql"
    POSTGRES_CUSTOM = "postgres_custom"


class DatabaseConsistency(StrEnum):
    TRANSACTIONAL_SNAPSHOT = "transactional_snapshot"
    BEST_EFFORT_LOGICAL = "best_effort_logical"


class DatabaseOperationKind(StrEnum):
    DATABASE_PROBE = "database_probe"
    LOGICAL_DUMP = "logical_dump"
    LOGICAL_RESTORE = "logical_restore"
    PRE_RESTORE_VERIFY = "pre_restore_verify"
    POST_RESTORE_VERIFY = "post_restore_verify"


class DatabaseOperationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    OUTPUT_LIMITED = "output_limited"
    DISCONNECTED = "disconnected"
    PERMISSION_DENIED = "permission_denied"
    RESTART_RECOVERY_REQUIRED = "restart_recovery_required"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class DatabaseCleanupStatus(StrEnum):
    NONE = "none"
    REQUIRED = "required"
    CLEANED = "cleaned"
    QUARANTINED = "quarantined"


class DatabaseCredentialStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


MAX_DATABASE_ARTIFACT_BYTES = 536_870_912
MAX_DATABASE_STDERR_BYTES = 65_536
MAX_DATABASE_STDOUT_BYTES = 262_144
MAX_DATABASE_RECORDS = 1_024

_SAFE_DB_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_SAFE_DB_USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,62}$", re.IGNORECASE)
_SAFE_TOOL_PROFILE = re.compile(r"^[a-z][a-z0-9.-]{2,63}$")
_SAFE_TEMPLATE_ID = re.compile(r"^[a-z][a-z0-9.-]{2,99}$")
_SAFE_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_SAFE_HEX = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_COMMAND_CHARS = frozenset("\x00\n\r;|&$><*?{}[]()!`")


def _enum[T: StrEnum](value: object, enum_type: type[T], *, field_name: str) -> T:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise DatabaseBoundaryError(f"{field_name} is invalid")
    try:
        return enum_type(value.strip().casefold())
    except ValueError as exc:
        raise DatabaseBoundaryError(f"{field_name} is invalid") from exc


def validate_database_name(value: object, *, field_name: str = "database_name") -> str:
    if not isinstance(value, str):
        raise DatabaseTargetError(f"{field_name} is invalid")
    candidate = value.strip()
    if (
        _SAFE_DB_NAME.fullmatch(candidate) is None
        or ".." in candidate
        or any(
            character in _FORBIDDEN_COMMAND_CHARS or character.isspace() for character in candidate
        )
    ):
        raise DatabaseTargetError(f"{field_name} is invalid")
    return candidate


def validate_database_user(value: object) -> str:
    if not isinstance(value, str) or _SAFE_DB_USER.fullmatch(value.strip()) is None:
        raise DatabaseTargetError("database user is invalid")
    return value.strip()


def validate_operation_id(value: object) -> str:
    if not isinstance(value, str) or _SAFE_OPERATION_ID.fullmatch(value.strip()) is None:
        raise DatabaseOperationRejected("operation_id is invalid")
    return value.strip()


def validate_idempotency_key(value: object) -> str:
    if not isinstance(value, str) or _SAFE_IDEMPOTENCY.fullmatch(value.strip()) is None:
        raise DatabaseOperationRejected("idempotency key is invalid")
    return value.strip()


def validate_tool_profile(value: object) -> str:
    if not isinstance(value, str) or _SAFE_TOOL_PROFILE.fullmatch(value.strip()) is None:
        raise DatabaseTargetError("tool profile is invalid")
    return value.strip().casefold()


def validate_template_id(value: object) -> str:
    if not isinstance(value, str) or _SAFE_TEMPLATE_ID.fullmatch(value.strip().casefold()) is None:
        raise DatabaseOperationRejected("template id is invalid")
    return value.strip().casefold()


def validate_digest_hex(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _SAFE_HEX.fullmatch(value.strip().casefold()) is None:
        raise DatabaseArtifactError(f"{field_name} is invalid")
    return value.strip().casefold()


def validate_aware_timestamp(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise DatabaseBoundaryError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def validate_database_host(value: object) -> str:
    try:
        candidate = validate_host(value, field_name="database_host")
    except ValueError as exc:
        raise DatabaseTargetError("database host is invalid") from exc
    if candidate in {"0.0.0.0", "::", "::0"}:  # noqa: S104 - reject unrestricted binds
        raise DatabaseTargetError("database host must not be an unrestricted bind")
    return candidate


def _safe_text(value: object, *, field_name: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise DatabaseBoundaryError(f"{field_name} is invalid")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(character) < 32 for character in normalized)
        or contains_credential_like(normalized)
    ):
        raise DatabaseBoundaryError(f"{field_name} is unsafe")
    return normalized


@dataclass(frozen=True, slots=True)
class DatabaseLimits:
    """Hard limits from Spec 015; callers may lower but never raise them."""

    probe_timeout_seconds: float = 15.0
    dump_timeout_seconds: float = 900.0
    restore_timeout_seconds: float = 1_200.0
    verify_timeout_seconds: float = 60.0
    max_artifact_bytes: int = MAX_DATABASE_ARTIFACT_BYTES
    max_stderr_bytes: int = MAX_DATABASE_STDERR_BYTES
    max_stdout_bytes: int = MAX_DATABASE_STDOUT_BYTES
    max_records: int = MAX_DATABASE_RECORDS

    def __post_init__(self) -> None:
        for name, maximum in (
            ("probe_timeout_seconds", 60.0),
            ("dump_timeout_seconds", 3_600.0),
            ("restore_timeout_seconds", 3_600.0),
            ("verify_timeout_seconds", 300.0),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise DatabaseOperationRejected(f"{name} is invalid")
            if not math.isfinite(float(value)) or not 0.5 <= float(value) <= maximum:
                raise DatabaseOperationRejected(f"{name} is outside bounds")
        for name, lower, upper in (
            ("max_artifact_bytes", 1, MAX_DATABASE_ARTIFACT_BYTES),
            ("max_stderr_bytes", 1, MAX_DATABASE_STDERR_BYTES),
            ("max_stdout_bytes", 1, MAX_DATABASE_STDOUT_BYTES),
            ("max_records", 1, MAX_DATABASE_RECORDS),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise DatabaseOperationRejected(f"{name} is outside bounds")


@dataclass(frozen=True, slots=True)
class DatabaseTransportBinding:
    """A database operation's already-verified Spec 014 transport identity."""

    tenant_id: str
    application_id: str
    target_reference: str
    host: str
    ssh_port: int
    expected_host_key_fingerprint: str
    evidence_reference: str

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
            self, "target_reference", validate_evidence_reference(self.target_reference)
        )
        object.__setattr__(self, "host", validate_host(self.host))
        object.__setattr__(self, "ssh_port", validate_port(self.ssh_port))
        object.__setattr__(
            self,
            "expected_host_key_fingerprint",
            validate_fingerprint(self.expected_host_key_fingerprint),
        )
        object.__setattr__(
            self,
            "evidence_reference",
            validate_evidence_reference(self.evidence_reference),
        )

    @classmethod
    def from_linux_target(
        cls, target: LinuxTarget, *, evidence_reference: str
    ) -> DatabaseTransportBinding:
        return cls(
            tenant_id=target.tenant_id,
            application_id=target.application_id,
            target_reference=target.target_reference,
            host=target.host,
            ssh_port=target.ssh_port,
            expected_host_key_fingerprint=target.expected_host_key_fingerprint,
            evidence_reference=evidence_reference,
        )

    def validate_scope(self, *, tenant_id: str, application_id: str) -> None:
        if self.tenant_id != tenant_id or self.application_id != application_id:
            raise DatabaseTargetError("transport binding crosses tenant/application scope")


@dataclass(frozen=True, slots=True)
class DatabaseCredentialReference:
    """Metadata-only database credential reference; it cannot hold a secret."""

    reference: str
    tenant_id: str
    application_id: str
    version: int = 1
    status: DatabaseCredentialStatus = DatabaseCredentialStatus.ACTIVE
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reference, str):
            raise DatabaseCredentialError("credential reference is invalid")
        normalized = self.reference.strip()
        if not re.fullmatch(
            r"(?:vault|secret|appcare-secret)://[a-z0-9][a-z0-9._/-]{2,240}", normalized, re.I
        ):
            raise DatabaseCredentialError("credential reference is invalid")
        if ".." in normalized or contains_credential_like(normalized):
            raise DatabaseCredentialError("credential reference is invalid")
        object.__setattr__(self, "reference", normalized)
        object.__setattr__(
            self, "tenant_id", validate_scope_segment(self.tenant_id, field_name="tenant_id")
        )
        object.__setattr__(
            self,
            "application_id",
            validate_scope_segment(self.application_id, field_name="application_id"),
        )
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise DatabaseCredentialError("credential version is invalid")
        object.__setattr__(
            self,
            "status",
            _enum(self.status, DatabaseCredentialStatus, field_name="credential_status"),
        )
        object.__setattr__(
            self, "issued_at", validate_aware_timestamp(self.issued_at, field_name="issued_at")
        )
        if self.expires_at is not None:
            object.__setattr__(
                self,
                "expires_at",
                validate_aware_timestamp(self.expires_at, field_name="expires_at"),
            )
            if self.expires_at <= self.issued_at:
                raise DatabaseCredentialError("credential expiry is invalid")
        if self.revoked_at is not None:
            object.__setattr__(
                self,
                "revoked_at",
                validate_aware_timestamp(self.revoked_at, field_name="revoked_at"),
            )

    def active(self, *, now: datetime | None = None) -> bool:
        current = validate_aware_timestamp(now or datetime.now(UTC), field_name="now")
        return (
            self.status == DatabaseCredentialStatus.ACTIVE
            and self.revoked_at is None
            and (self.expires_at is None or self.expires_at > current)
        )

    def require_active(self, *, now: datetime | None = None) -> None:
        if not self.active(now=now):
            raise DatabaseCredentialError("database credential is not active")


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedDatabaseCredential:
    """Private runtime credential handle; never included in evidence or repr."""

    reference: str
    username: str
    secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.reference, str) or not self.reference.strip():
            raise DatabaseCredentialError("resolved credential reference is invalid")
        object.__setattr__(self, "reference", self.reference.strip())
        object.__setattr__(self, "username", validate_database_user(self.username))
        if (
            not isinstance(self.secret, str)
            or not self.secret
            or "\x00" in self.secret
            or "\n" in self.secret
            or "\r" in self.secret
        ):
            raise DatabaseCredentialError("resolved credential material is invalid")

    def __repr__(self) -> str:
        return (
            f"ResolvedDatabaseCredential(reference={self.reference!r}, "
            f"username={self.username!r}, secret=<redacted>)"
        )


class DatabaseCredentialProvider(Protocol):
    def resolve(self, target: DatabaseTarget) -> ResolvedDatabaseCredential:
        """Resolve one opaque reference inside the private broker boundary."""


@dataclass(frozen=True, slots=True)
class DatabaseTarget:
    tenant_id: str
    application_id: str
    stack_id: str
    environment: str
    engine_family: DatabaseKind
    database_identifier: str
    logical_database_name: str
    transport: DatabaseTransportBinding
    credential: DatabaseCredentialReference
    target_reference: str
    approved_database_identifiers: tuple[str, ...] = ()
    database_user: str = "appcare"
    database_host: str = "127.0.0.1"
    database_port: int = 0
    tool_profile: str = ""
    consistency: DatabaseConsistency = DatabaseConsistency.TRANSACTIONAL_SNAPSHOT
    limits: DatabaseLimits = field(default_factory=DatabaseLimits)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "application_id", "stack_id"):
            object.__setattr__(
                self, name, validate_scope_segment(getattr(self, name), field_name=name)
            )
        environment = validate_scope_segment(self.environment, field_name="environment").casefold()
        if environment not in {"development", "staging", "test", "production"}:
            raise DatabaseTargetError("database environment is invalid")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self,
            "engine_family",
            _enum(self.engine_family, DatabaseKind, field_name="engine_family"),
        )
        object.__setattr__(
            self,
            "database_identifier",
            validate_database_name(self.database_identifier, field_name="database_identifier"),
        )
        object.__setattr__(
            self,
            "logical_database_name",
            validate_database_name(self.logical_database_name, field_name="logical_database_name"),
        )
        self.transport.validate_scope(tenant_id=self.tenant_id, application_id=self.application_id)
        if self.transport.target_reference == self.target_reference:
            raise DatabaseTargetError(
                "database target reference must be distinct from transport target"
            )
        object.__setattr__(
            self, "target_reference", validate_evidence_reference(self.target_reference)
        )
        if (
            self.credential.tenant_id != self.tenant_id
            or self.credential.application_id != self.application_id
        ):
            raise DatabaseCredentialError("database credential crosses target scope")
        approved_database_identifiers = tuple(
            sorted(
                {
                    validate_database_name(value, field_name="approved_database_identifier")
                    for value in self.approved_database_identifiers
                }
            )
        )
        if not approved_database_identifiers:
            raise DatabaseTargetError("approved database identity is required")
        if (
            self.database_identifier not in approved_database_identifiers
            or self.logical_database_name not in approved_database_identifiers
        ):
            raise DatabaseTargetError("database identity is not approved by target inventory")
        object.__setattr__(self, "approved_database_identifiers", approved_database_identifiers)
        object.__setattr__(self, "database_user", validate_database_user(self.database_user))
        object.__setattr__(self, "database_host", validate_database_host(self.database_host))
        port = self.database_port
        if port == 0:
            port = 3306 if self.engine_family == DatabaseKind.MARIADB_MYSQL else 5432
        object.__setattr__(self, "database_port", validate_port(port))
        profile = self.tool_profile.strip().casefold() if isinstance(self.tool_profile, str) else ""
        if not profile:
            profile = (
                "mariadb-logical-v1"
                if self.engine_family == DatabaseKind.MARIADB_MYSQL
                else "postgresql-custom-v1"
            )
        object.__setattr__(self, "tool_profile", validate_tool_profile(profile))
        object.__setattr__(
            self,
            "consistency",
            _enum(self.consistency, DatabaseConsistency, field_name="consistency"),
        )
        if not isinstance(self.limits, DatabaseLimits):
            raise DatabaseTargetError("database limits are invalid")
        if (
            self.engine_family == DatabaseKind.POSTGRESQL
            and self.tool_profile != "postgresql-custom-v1"
        ):
            raise DatabaseTargetError("postgresql tool profile is not approved")
        if (
            self.engine_family == DatabaseKind.MARIADB_MYSQL
            and self.tool_profile != "mariadb-logical-v1"
        ):
            raise DatabaseTargetError("mariadb tool profile is not approved")
        if self.database_host not in {"127.0.0.1", "::1", self.transport.host}:
            raise DatabaseTargetError("database endpoint is not bound to the Linux target")

    @classmethod
    def from_linux_target(
        cls,
        target: LinuxTarget,
        *,
        stack_id: str,
        engine_family: DatabaseKind,
        database_identifier: str,
        logical_database_name: str,
        credential: DatabaseCredentialReference,
        transport_evidence_reference: str,
        target_reference: str,
        database_user: str = "appcare",
        database_host: str = "127.0.0.1",
        database_port: int = 0,
        consistency: DatabaseConsistency = DatabaseConsistency.TRANSACTIONAL_SNAPSHOT,
        limits: DatabaseLimits | None = None,
    ) -> DatabaseTarget:
        transport = DatabaseTransportBinding.from_linux_target(
            target,
            evidence_reference=transport_evidence_reference,
        )
        return cls(
            tenant_id=target.tenant_id,
            application_id=target.application_id,
            stack_id=stack_id,
            environment=target.environment,
            engine_family=engine_family,
            database_identifier=database_identifier,
            logical_database_name=logical_database_name,
            transport=transport,
            credential=credential,
            target_reference=target_reference,
            approved_database_identifiers=target.approved_database_identifiers,
            database_user=database_user,
            database_host=database_host,
            database_port=database_port,
            consistency=consistency,
            limits=limits or DatabaseLimits(),
        )


@dataclass(frozen=True, slots=True)
class DatabaseProbe:
    operation_id: str
    kind: DatabaseOperationKind = field(init=False, default=DatabaseOperationKind.DATABASE_PROBE)

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))


@dataclass(frozen=True, slots=True)
class DatabaseDumpRequest:
    target: DatabaseTarget
    backup_id: str
    idempotency_key: str
    job_id: str
    source_revision: str | None = None
    application_artifact_digest: str | None = None
    requested_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    operation_id: str = "database-dump"

    def __post_init__(self) -> None:
        object.__setattr__(self, "backup_id", validate_backup_id(self.backup_id))
        object.__setattr__(self, "idempotency_key", validate_idempotency_key(self.idempotency_key))
        object.__setattr__(self, "job_id", validate_scope_segment(self.job_id, field_name="job_id"))
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(
            self,
            "requested_at",
            validate_aware_timestamp(self.requested_at, field_name="requested_at"),
        )
        if (self.source_revision is None) != (self.application_artifact_digest is None):
            raise DatabaseArtifactError(
                "source revision and application artifact digest must be paired"
            )
        if self.source_revision is not None:
            object.__setattr__(self, "source_revision", validate_revision(self.source_revision))
            object.__setattr__(
                self,
                "application_artifact_digest",
                validate_digest(
                    self.application_artifact_digest, field_name="application_artifact_digest"
                ),
            )


@dataclass(frozen=True, slots=True)
class DatabaseRestoreTarget:
    tenant_id: str
    application_id: str
    stack_id: str
    environment: str
    engine_family: DatabaseKind
    isolated_target_reference: str
    restore_database_name: str
    transport: DatabaseTransportBinding
    credential: DatabaseCredentialReference
    cleanup_owner_reference: str
    verification_profile: str
    approved_database_identifiers: tuple[str, ...] = ()
    database_user: str = "appcare"
    database_host: str = "127.0.0.1"
    database_port: int = 0
    existing_authoritative_database: bool = False

    def __post_init__(self) -> None:
        for name in ("tenant_id", "application_id", "stack_id"):
            object.__setattr__(
                self, name, validate_scope_segment(getattr(self, name), field_name=name)
            )
        environment = validate_scope_segment(self.environment, field_name="environment").casefold()
        if environment not in {"development", "staging", "test"}:
            raise DatabaseRestoreError("production restore target is forbidden")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self,
            "engine_family",
            _enum(self.engine_family, DatabaseKind, field_name="engine_family"),
        )
        object.__setattr__(
            self,
            "isolated_target_reference",
            validate_evidence_reference(self.isolated_target_reference),
        )
        object.__setattr__(
            self,
            "restore_database_name",
            validate_database_name(self.restore_database_name, field_name="restore_database_name"),
        )
        self.transport.validate_scope(tenant_id=self.tenant_id, application_id=self.application_id)
        if (
            self.credential.tenant_id != self.tenant_id
            or self.credential.application_id != self.application_id
        ):
            raise DatabaseCredentialError("restore credential crosses target scope")
        approved_database_identifiers = tuple(
            sorted(
                {
                    validate_database_name(value, field_name="approved_restore_database_identifier")
                    for value in self.approved_database_identifiers
                }
            )
        )
        if not approved_database_identifiers:
            raise DatabaseRestoreError("registered isolated database identity is required")
        if self.restore_database_name not in approved_database_identifiers:
            raise DatabaseRestoreError("restore database is not approved by target registry")
        object.__setattr__(self, "approved_database_identifiers", approved_database_identifiers)
        object.__setattr__(
            self,
            "cleanup_owner_reference",
            validate_evidence_reference(self.cleanup_owner_reference),
        )
        object.__setattr__(
            self, "verification_profile", validate_tool_profile(self.verification_profile)
        )
        object.__setattr__(self, "database_user", validate_database_user(self.database_user))
        object.__setattr__(self, "database_host", validate_database_host(self.database_host))
        port = self.database_port
        if port == 0:
            port = 3306 if self.engine_family == DatabaseKind.MARIADB_MYSQL else 5432
        object.__setattr__(self, "database_port", validate_port(port))
        if self.existing_authoritative_database:
            raise DatabaseRestoreError("restore target is already authoritative")
        if self.database_host not in {"127.0.0.1", "::1", self.transport.host}:
            raise DatabaseRestoreError("restore database endpoint is not bound to the Linux target")


class DatabaseRestoreTargetRegistry(Protocol):
    """Authoritative registry for isolated, non-production restore targets."""

    def resolve(
        self,
        requested: DatabaseRestoreTarget,
        *,
        source_manifest: DatabaseManifest,
    ) -> DatabaseRestoreTarget:
        """Return the registered target or reject an unregistered request."""

    def quarantine(
        self,
        requested: DatabaseRestoreTarget,
        *,
        source_manifest: DatabaseManifest,
        cleanup_reference: str,
        reason_code: str,
    ) -> str:
        """Mark one restore target unusable until an external reset occurs."""


@dataclass(frozen=True, slots=True)
class DatabaseManifest:
    backup_id: str
    tenant_id: str
    application_id: str
    stack_id: str
    target_reference: str
    transport_target_reference: str
    engine_family: DatabaseKind
    database_identifier: str
    logical_database_name: str
    dump_format: DatabaseDumpFormat
    tool_profile: str
    artifact_size_bytes: int
    artifact_sha256: str
    consistency: DatabaseConsistency
    limitation_codes: tuple[str, ...]
    created_at: datetime
    source_revision: str | None = None
    application_artifact_digest: str | None = None
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE

    def __post_init__(self) -> None:
        object.__setattr__(self, "backup_id", validate_backup_id(self.backup_id))
        for name in ("tenant_id", "application_id", "stack_id"):
            object.__setattr__(
                self, name, validate_scope_segment(getattr(self, name), field_name=name)
            )
        object.__setattr__(
            self, "target_reference", validate_evidence_reference(self.target_reference)
        )
        object.__setattr__(
            self,
            "transport_target_reference",
            validate_evidence_reference(self.transport_target_reference),
        )
        object.__setattr__(
            self,
            "engine_family",
            _enum(self.engine_family, DatabaseKind, field_name="engine_family"),
        )
        object.__setattr__(
            self,
            "database_identifier",
            validate_database_name(self.database_identifier, field_name="database_identifier"),
        )
        object.__setattr__(
            self,
            "logical_database_name",
            validate_database_name(self.logical_database_name, field_name="logical_database_name"),
        )
        object.__setattr__(
            self,
            "dump_format",
            _enum(self.dump_format, DatabaseDumpFormat, field_name="dump_format"),
        )
        object.__setattr__(self, "tool_profile", validate_tool_profile(self.tool_profile))
        if isinstance(self.artifact_size_bytes, bool) or not isinstance(
            self.artifact_size_bytes, int
        ):
            raise DatabaseArtifactError("artifact size is invalid")
        if not 1 <= self.artifact_size_bytes <= MAX_DATABASE_ARTIFACT_BYTES:
            raise DatabaseArtifactError("artifact size is outside bounds")
        object.__setattr__(
            self,
            "artifact_sha256",
            validate_digest_hex(self.artifact_sha256, field_name="artifact_sha256"),
        )
        object.__setattr__(
            self,
            "consistency",
            _enum(self.consistency, DatabaseConsistency, field_name="consistency"),
        )
        normalized_limitations: list[str] = []
        for code in self.limitation_codes:
            if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", code):
                raise DatabaseArtifactError("limitation code is invalid")
            normalized_limitations.append(code)
        object.__setattr__(self, "limitation_codes", tuple(sorted(set(normalized_limitations))))
        object.__setattr__(
            self, "created_at", validate_aware_timestamp(self.created_at, field_name="created_at")
        )
        object.__setattr__(
            self,
            "evidence_class",
            _enum(self.evidence_class, EvidenceClass, field_name="evidence_class"),
        )
        if (self.source_revision is None) != (self.application_artifact_digest is None):
            raise DatabaseArtifactError(
                "source revision and application artifact digest must be paired"
            )
        if self.source_revision is not None:
            object.__setattr__(self, "source_revision", validate_revision(self.source_revision))
            object.__setattr__(
                self,
                "application_artifact_digest",
                validate_digest(
                    self.application_artifact_digest, field_name="application_artifact_digest"
                ),
            )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "backup_id": self.backup_id,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "stack_id": self.stack_id,
            "target_reference": self.target_reference,
            "transport_target_reference": self.transport_target_reference,
            "engine_family": self.engine_family.value,
            "database_identifier": self.database_identifier,
            "logical_database_name": self.logical_database_name,
            "dump_format": self.dump_format.value,
            "tool_profile": self.tool_profile,
            "artifact_size_bytes": self.artifact_size_bytes,
            "artifact_sha256": self.artifact_sha256,
            "consistency": self.consistency.value,
            "limitation_codes": list(self.limitation_codes),
            "created_at": self.created_at.isoformat(),
            "source_revision": self.source_revision,
            "application_artifact_digest": self.application_artifact_digest,
            "evidence_class": self.evidence_class.value,
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_database_artifact_path(
    path: Path,
    *,
    filesystem: BackupFilesystemBoundary,
    job_id: str,
    filename: str | None = None,
) -> Path:
    """Validate one file exactly inside one AppCare staging job."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise DatabaseArtifactError("artifact path must be absolute")
    expected_parent = filesystem.staging_path(job_id)
    if filename is not None and path.name != filename:
        raise DatabaseArtifactError("artifact filename is not approved")
    if path.parent != expected_parent:
        raise DatabaseArtifactError("artifact path is outside the staging job")
    if path.is_symlink():
        raise DatabaseArtifactError("artifact path is a symlink")
    try:
        resolved = path.resolve(strict=False)
        parent_resolved = expected_parent.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise DatabaseArtifactError("artifact path cannot be resolved") from exc
    if resolved.parent != parent_resolved or resolved.name != path.name:
        raise DatabaseArtifactError("artifact path crosses a symlink")
    if any(character in _FORBIDDEN_COMMAND_CHARS or character.isspace() for character in path.name):
        raise DatabaseArtifactError("artifact filename is unsafe")
    return path


@dataclass(frozen=True, slots=True)
class DatabaseDumpArtifact:
    manifest: DatabaseManifest
    artifact_path: Path
    staging_job_id: str
    filesystem: BackupFilesystemBoundary | None = None
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE

    def __post_init__(self) -> None:
        from ..backups.paths import BackupFilesystemBoundary

        filesystem = self.filesystem or BackupFilesystemBoundary.canonical()
        object.__setattr__(self, "filesystem", filesystem)
        object.__setattr__(
            self,
            "evidence_class",
            _enum(self.evidence_class, EvidenceClass, field_name="evidence_class"),
        )
        if self.manifest.evidence_class != self.evidence_class:
            raise DatabaseArtifactError("artifact evidence class does not match manifest")
        object.__setattr__(
            self,
            "staging_job_id",
            validate_scope_segment(self.staging_job_id, field_name="staging_job_id"),
        )
        validate_database_artifact_path(
            self.artifact_path,
            filesystem=filesystem,
            job_id=self.staging_job_id,
        )
        if self.manifest.artifact_size_bytes > MAX_DATABASE_ARTIFACT_BYTES:
            raise DatabaseArtifactError("artifact exceeds hard cap")

    @property
    def artifact_digest(self) -> str:
        return self.manifest.artifact_sha256

    @property
    def manifest_digest(self) -> str:
        return self.manifest.digest

    @property
    def evidence_digest(self) -> str:
        payload = {
            "manifest_digest": self.manifest_digest,
            "artifact_digest": self.artifact_digest,
            "artifact_path": self.artifact_path.name,
            "staging_job_id": self.staging_job_id,
            "evidence_class": self.evidence_class.value,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class DatabaseBrokerResult:
    operation_id: str
    operation: DatabaseOperationKind
    status: DatabaseOperationStatus
    reason_code: str
    template_id: str
    returncode: int | None = None
    artifact_path: Path | None = None
    artifact_size_bytes: int = 0
    artifact_sha256: str | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    sanitized_stderr: str = ""
    observed_database_name: str | None = None
    restored_object_count: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    output_limited: bool = False
    disconnected: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(
            self, "operation", _enum(self.operation, DatabaseOperationKind, field_name="operation")
        )
        object.__setattr__(
            self,
            "status",
            _enum(self.status, DatabaseOperationStatus, field_name="status"),
        )
        object.__setattr__(
            self, "reason_code", validate_scope_segment(self.reason_code, field_name="reason_code")
        )
        object.__setattr__(self, "template_id", validate_template_id(self.template_id))
        for name in ("artifact_size_bytes", "stdout_bytes", "stderr_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise DatabaseOperationRejected(f"{name} is invalid")
        if self.artifact_sha256 is not None:
            object.__setattr__(
                self,
                "artifact_sha256",
                validate_digest_hex(self.artifact_sha256, field_name="artifact_sha256"),
            )
        if (self.observed_database_name is None) != (self.restored_object_count is None):
            raise DatabaseOperationRejected("verification broker details are incomplete")
        if self.observed_database_name is not None:
            if self.operation not in {
                DatabaseOperationKind.PRE_RESTORE_VERIFY,
                DatabaseOperationKind.POST_RESTORE_VERIFY,
            }:
                raise DatabaseOperationRejected("verification broker details are out of scope")
            object.__setattr__(
                self,
                "observed_database_name",
                validate_database_name(
                    self.observed_database_name,
                    field_name="observed_database_name",
                ),
            )
        if self.restored_object_count is not None and (
            isinstance(self.restored_object_count, bool)
            or not isinstance(self.restored_object_count, int)
            or self.restored_object_count < 0
        ):
            raise DatabaseOperationRejected("verification restored object count is invalid")
        if self.sanitized_stderr and contains_credential_like(self.sanitized_stderr):
            raise DatabaseOperationRejected("sanitized stderr contains credential-like data")
        if len(self.sanitized_stderr) > 4_096:
            raise DatabaseOperationRejected("sanitized stderr is too large")

    @property
    def passed(self) -> bool:
        return self.status == DatabaseOperationStatus.PASSED


@dataclass(frozen=True, slots=True)
class DatabaseDumpResult:
    request: DatabaseDumpRequest
    status: DatabaseOperationStatus
    reason_code: str
    artifact: DatabaseDumpArtifact | None = None
    broker: DatabaseBrokerResult | None = None
    limitation_codes: tuple[str, ...] = ()
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "status", _enum(self.status, DatabaseOperationStatus, field_name="status")
        )
        object.__setattr__(
            self, "reason_code", validate_scope_segment(self.reason_code, field_name="reason_code")
        )
        object.__setattr__(self, "limitation_codes", tuple(sorted(set(self.limitation_codes))))
        object.__setattr__(
            self,
            "evidence_class",
            _enum(self.evidence_class, EvidenceClass, field_name="evidence_class"),
        )
        if self.status == DatabaseOperationStatus.PASSED and self.artifact is None:
            raise DatabaseArtifactError("passed dump result requires an artifact")

    @property
    def passed(self) -> bool:
        return self.status == DatabaseOperationStatus.PASSED and self.artifact is not None


@dataclass(frozen=True, slots=True)
class DatabaseRestoreRequest:
    artifact: DatabaseDumpArtifact
    target: DatabaseRestoreTarget
    idempotency_key: str
    operation_id: str = "database-restore"
    requested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "idempotency_key", validate_idempotency_key(self.idempotency_key))
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(
            self,
            "requested_at",
            validate_aware_timestamp(self.requested_at, field_name="requested_at"),
        )
        manifest = self.artifact.manifest
        if (
            manifest.tenant_id != self.target.tenant_id
            or manifest.application_id != self.target.application_id
            or manifest.stack_id != self.target.stack_id
            or manifest.engine_family != self.target.engine_family
        ):
            raise DatabaseRestoreError("restore artifact crosses target scope")


@dataclass(frozen=True, slots=True)
class DatabaseVerifyRequest:
    """Typed post-restore verification request with no caller SQL."""

    artifact: DatabaseDumpArtifact
    target: DatabaseRestoreTarget
    idempotency_key: str
    expected_object_names: tuple[str, ...] = ()
    require_empty: bool = False
    operation_id: str = "database-verify"
    requested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "idempotency_key", validate_idempotency_key(self.idempotency_key))
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(
            self,
            "expected_object_names",
            tuple(
                sorted(
                    {
                        validate_database_name(
                            value,
                            field_name="expected_object_name",
                        )
                        for value in self.expected_object_names
                    }
                )
            ),
        )
        if not isinstance(self.require_empty, bool):
            raise DatabaseOperationRejected("require_empty is invalid")
        if self.require_empty and self.expected_object_names:
            raise DatabaseOperationRejected("pre-restore verification cannot expect objects")
        if len(self.expected_object_names) > MAX_DATABASE_RECORDS:
            raise DatabaseOperationRejected("verification expected object set is outside bounds")
        object.__setattr__(
            self,
            "requested_at",
            validate_aware_timestamp(self.requested_at, field_name="requested_at"),
        )
        manifest = self.artifact.manifest
        if (
            manifest.tenant_id != self.target.tenant_id
            or manifest.application_id != self.target.application_id
            or manifest.stack_id != self.target.stack_id
            or manifest.engine_family != self.target.engine_family
        ):
            raise DatabaseRestoreError("verification artifact crosses target scope")


@dataclass(frozen=True, slots=True)
class DatabaseVerificationResult:
    operation_id: str
    status: DatabaseOperationStatus
    reason_code: str
    target_reference: str
    backup_id: str
    artifact_digest: str
    manifest_digest: str
    observed_database_name: str | None = None
    restored_object_count: int = 0
    broker: DatabaseBrokerResult | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", validate_operation_id(self.operation_id))
        object.__setattr__(
            self, "status", _enum(self.status, DatabaseOperationStatus, field_name="status")
        )
        object.__setattr__(
            self, "reason_code", validate_scope_segment(self.reason_code, field_name="reason_code")
        )
        object.__setattr__(
            self, "target_reference", validate_evidence_reference(self.target_reference)
        )
        object.__setattr__(self, "backup_id", validate_backup_id(self.backup_id))
        object.__setattr__(
            self,
            "artifact_digest",
            validate_digest_hex(self.artifact_digest, field_name="artifact_digest"),
        )
        object.__setattr__(
            self,
            "manifest_digest",
            validate_digest_hex(self.manifest_digest, field_name="manifest_digest"),
        )
        if self.observed_database_name is not None:
            object.__setattr__(
                self,
                "observed_database_name",
                validate_database_name(
                    self.observed_database_name,
                    field_name="observed_database_name",
                ),
            )
        if (
            isinstance(self.restored_object_count, bool)
            or not isinstance(self.restored_object_count, int)
            or self.restored_object_count < 0
        ):
            raise DatabaseOperationRejected("restored object count is invalid")
        if self.status == DatabaseOperationStatus.PASSED and (
            self.observed_database_name is None or self.restored_object_count < 1
        ):
            raise DatabaseOperationRejected("passed verification requires identity and objects")

    @property
    def passed(self) -> bool:
        return self.status == DatabaseOperationStatus.PASSED


@dataclass(frozen=True, slots=True)
class DatabaseRestoreEvidence:
    request: DatabaseRestoreRequest
    status: DatabaseOperationStatus
    reason_code: str
    artifact_digest: str
    manifest_digest: str
    restored_digest: str | None
    verification: DatabaseVerificationResult | None
    cleanup_status: DatabaseCleanupStatus = DatabaseCleanupStatus.NONE
    cleanup_reference: str | None = None
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "status", _enum(self.status, DatabaseOperationStatus, field_name="status")
        )
        object.__setattr__(
            self, "reason_code", validate_scope_segment(self.reason_code, field_name="reason_code")
        )
        object.__setattr__(
            self,
            "artifact_digest",
            validate_digest_hex(self.artifact_digest, field_name="artifact_digest"),
        )
        object.__setattr__(
            self,
            "manifest_digest",
            validate_digest_hex(self.manifest_digest, field_name="manifest_digest"),
        )
        if self.restored_digest is not None:
            object.__setattr__(
                self,
                "restored_digest",
                validate_digest_hex(self.restored_digest, field_name="restored_digest"),
            )
        object.__setattr__(
            self,
            "evidence_class",
            _enum(self.evidence_class, EvidenceClass, field_name="evidence_class"),
        )
        object.__setattr__(
            self,
            "cleanup_status",
            _enum(self.cleanup_status, DatabaseCleanupStatus, field_name="cleanup_status"),
        )
        if self.cleanup_reference is not None:
            object.__setattr__(
                self,
                "cleanup_reference",
                validate_evidence_reference(self.cleanup_reference),
            )
        if self.cleanup_status == DatabaseCleanupStatus.NONE and self.cleanup_reference is not None:
            raise DatabaseRestoreError("cleanup reference requires a cleanup disposition")
        if self.cleanup_status != DatabaseCleanupStatus.NONE and self.cleanup_reference is None:
            raise DatabaseRestoreError("cleanup disposition requires a cleanup reference")
        if self.status == DatabaseOperationStatus.PASSED:
            if (
                self.restored_digest != self.artifact_digest
                or self.verification is None
                or not self.verification.passed
                or self.cleanup_status != DatabaseCleanupStatus.NONE
                or self.cleanup_reference is not None
            ):
                raise DatabaseRestoreError(
                    "passed restore evidence is not checksum/verification bound"
                )

    @property
    def passed(self) -> bool:
        return self.status == DatabaseOperationStatus.PASSED


class DatabaseExecutionBroker(Protocol):
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
        """Run one closed typed operation without exposing raw output."""


class DatabaseOperationLedgerProtocol(Protocol):
    """Durable operation ledger required by production adapters."""

    def claim(
        self, *, scope: str, idempotency_key: str, request_digest: str
    ) -> tuple[str, object | None]:
        """Atomically claim one operation or return a safe replay decision."""

    def complete(self, *, scope: str, idempotency_key: str, outcome: object) -> None:
        """Persist a sanitized terminal outcome."""

    def mark_restart_recovery(self) -> None:
        """Mark unfinished operations so a restart cannot replay them silently."""


# Compatibility names used by the Spec 015 contract package.
DatabaseBackupRequest = DatabaseDumpRequest
DatabaseBackupResult = DatabaseDumpResult
DatabaseRestoreResult = DatabaseRestoreEvidence


__all__ = [
    "DatabaseArtifactError",
    "DatabaseBackupRequest",
    "DatabaseBackupResult",
    "DatabaseBoundaryError",
    "DatabaseBrokerResult",
    "DatabaseCleanupStatus",
    "DatabaseConsistency",
    "DatabaseCredentialError",
    "DatabaseCredentialProvider",
    "DatabaseCredentialReference",
    "DatabaseCredentialStatus",
    "DatabaseDumpArtifact",
    "DatabaseDumpFormat",
    "DatabaseDumpRequest",
    "DatabaseDumpResult",
    "DatabaseExecutionBroker",
    "DatabaseKind",
    "DatabaseLimits",
    "DatabaseManifest",
    "DatabaseOperationKind",
    "DatabaseOperationLedgerProtocol",
    "DatabaseOperationStatus",
    "DatabaseOperationRejected",
    "DatabaseProbe",
    "DatabaseRestoreError",
    "DatabaseRestoreEvidence",
    "DatabaseRestoreRequest",
    "DatabaseRestoreResult",
    "DatabaseRestoreTarget",
    "DatabaseRestoreTargetRegistry",
    "DatabaseTarget",
    "DatabaseTargetError",
    "DatabaseTransportBinding",
    "DatabaseVerificationResult",
    "DatabaseVerifyRequest",
    "EvidenceClass",
    "MAX_DATABASE_ARTIFACT_BYTES",
    "MAX_DATABASE_STDERR_BYTES",
    "MAX_DATABASE_STDOUT_BYTES",
    "ResolvedDatabaseCredential",
    "validate_database_artifact_path",
    "validate_database_host",
    "validate_database_name",
    "validate_database_user",
    "validate_idempotency_key",
    "validate_operation_id",
    "validate_scope_segment",
    "validate_template_id",
]
