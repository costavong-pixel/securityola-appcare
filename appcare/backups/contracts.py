"""Validated provider-neutral contracts for AppCare backup workflows."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from ..services.security import contains_credential_like, is_safe_credential_reference

if TYPE_CHECKING:
    from .models import BackupArtifact, BackupComponent, EncryptedEnvelope, VaultReceipt
    from .paths import BackupFilesystemBoundary

BackupProvider = Literal["backblaze-b2", "aws-s3-glacier-deep-archive", "isolated-test-vault"]
BackupEnvironment = Literal["development", "staging", "test", "production"]

_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,499}$")
_FORBIDDEN_MARKERS = (
    "wordpress",
    "barnd",
    "shield",
    "api.securityola.com",
    "/var/www",
    "\\var\\www",
    "production-server",
    "/root",
    "/home/debian/apps/appcare-opencode",
)
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMPONENT_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class BackupBoundaryError(ValueError):
    """A target, destination, or restore path is outside AppCare scope."""


def _safe_reference(value: str, *, field: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 500
        or _SAFE_REFERENCE.fullmatch(normalized) is None
        or ".." in normalized
        or any(character.isspace() or ord(character) < 32 for character in normalized)
        or contains_credential_like(normalized)
    ):
        raise BackupBoundaryError(f"{field} is unsafe")
    lowered = normalized.casefold()
    if any(marker in lowered for marker in _FORBIDDEN_MARKERS):
        raise BackupBoundaryError(f"{field} is outside the AppCare boundary")
    return normalized


def validate_path_segment(value: str, *, field: str = "path segment") -> str:
    """Validate one user-controlled path segment without path semantics."""

    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > 128
        or ".." in value
        or _PATH_SEGMENT.fullmatch(value) is None
    ):
        raise BackupBoundaryError(f"{field} is unsafe")
    lowered = value.casefold()
    if any(marker in lowered for marker in _FORBIDDEN_MARKERS):
        raise BackupBoundaryError(f"{field} is outside the AppCare boundary")
    return value


def _safe_identifier(value: str, *, field: str) -> str:
    return validate_path_segment(value, field=field)


def validate_backup_id(value: str) -> str:
    """Validate the single path segment used by vault and restore stores."""

    return validate_path_segment(value, field="backup_id")


def validate_isolated_root(root: Path, *, field: str) -> Path:
    """Return a canonical, non-symlinked root for isolated test data."""

    if not root.is_absolute():
        raise BackupBoundaryError(f"{field} must be absolute")
    try:
        absolute = Path(os.path.abspath(root))
        resolved = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise BackupBoundaryError(f"{field} cannot be resolved") from exc
    if os.path.normcase(os.fspath(absolute)) != os.path.normcase(os.fspath(resolved)):
        raise BackupBoundaryError(f"{field} cannot cross a symlink")
    normalized = str(resolved).casefold().replace("\\", "/")
    if any(marker in normalized for marker in _FORBIDDEN_MARKERS):
        raise BackupBoundaryError(f"{field} is outside the AppCare isolation boundary")
    if resolved == Path(resolved.anchor) or any(
        part.casefold() == "production" for part in resolved.parts
    ):
        raise BackupBoundaryError(f"{field} is too broad")
    return resolved


def validate_isolated_child(root: Path, name: str, *, field: str) -> Path:
    """Validate an internal restore/vault directory without following links."""

    validate_path_segment(name, field=field)
    canonical_root = validate_isolated_root(root, field=f"{field} root")
    child = canonical_root / name
    if child.is_symlink():
        raise BackupBoundaryError(f"{field} cannot cross a symlink")
    try:
        absolute = Path(os.path.abspath(child))
        resolved = child.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise BackupBoundaryError(f"{field} cannot be resolved") from exc
    if os.path.normcase(os.fspath(absolute)) != os.path.normcase(os.fspath(resolved)):
        raise BackupBoundaryError(f"{field} cannot cross a symlink")
    if os.path.normcase(os.fspath(resolved.parent)) != os.path.normcase(os.fspath(canonical_root)):
        raise BackupBoundaryError(f"{field} crossed the isolation boundary")
    return resolved


@dataclass(frozen=True, slots=True)
class BackupTarget:
    """The tenant-owned AppCare application being snapshotted."""

    tenant_id: str
    application_id: str
    environment: BackupEnvironment
    source_reference: str

    def __post_init__(self) -> None:
        _safe_identifier(self.tenant_id, field="tenant_id")
        _safe_identifier(self.application_id, field="application_id")
        if self.environment not in {"development", "staging", "test", "production"}:
            raise BackupBoundaryError("backup environment is unsupported")
        _safe_reference(self.source_reference, field="source_reference")


@dataclass(frozen=True, slots=True)
class BackupDestination:
    """A named destination; credentials are references, never values."""

    provider: BackupProvider
    namespace: str
    region: str
    retention_until: datetime
    immutable: bool = True
    credential_reference: str | None = None

    def __post_init__(self) -> None:
        if self.provider not in {
            "backblaze-b2",
            "aws-s3-glacier-deep-archive",
            "isolated-test-vault",
        }:
            raise BackupBoundaryError("backup provider is unsupported")
        _safe_reference(self.namespace, field="backup namespace")
        _safe_reference(self.region, field="backup region")
        if not self.immutable:
            raise BackupBoundaryError("backup destination must be immutable")
        retention = self.retention_until
        if retention.tzinfo is None:
            raise BackupBoundaryError("retention timestamp must be timezone-aware")
        if self.provider == "isolated-test-vault":
            if self.credential_reference is not None:
                raise BackupBoundaryError("test vault cannot carry a credential reference")
        elif not is_safe_credential_reference(self.credential_reference):
            raise BackupBoundaryError("cloud destination requires an opaque credential reference")

    @property
    def external(self) -> bool:
        return self.provider != "isolated-test-vault"


@dataclass(frozen=True, slots=True)
class RestoreTarget:
    """An isolated restore rehearsal rooted in the canonical filesystem boundary."""

    tenant_id: str
    application_id: str
    environment: Literal["development", "staging", "test"]
    root: Path
    isolation_id: str
    filesystem: "BackupFilesystemBoundary | None" = None

    def __post_init__(self) -> None:
        _safe_identifier(self.tenant_id, field="restore tenant_id")
        _safe_identifier(self.application_id, field="restore application_id")
        if self.environment not in {"development", "staging", "test"}:
            raise BackupBoundaryError("restore target cannot be production")
        _safe_identifier(self.isolation_id, field="isolation_id")
        if self.filesystem is None:
            from .paths import BackupFilesystemBoundary as _BackupFilesystemBoundary

            filesystem = _BackupFilesystemBoundary.canonical()
        else:
            filesystem = self.filesystem
        expected_root = filesystem.restore_rehearsal_path(
            self.tenant_id,
            self.application_id,
            self.isolation_id,
        )
        provided_root = validate_isolated_root(self.root, field="restore root")
        if provided_root != expected_root:
            raise BackupBoundaryError("restore root is outside the canonical rehearsal path")
        object.__setattr__(self, "root", expected_root)
        object.__setattr__(self, "filesystem", filesystem)


class BackupSource(Protocol):
    """Produce tenant-owned components without exposing provider credentials."""

    def snapshot(self, target: BackupTarget) -> tuple[BackupComponent, ...]:
        """Return the complete source snapshot for one validated target."""


class EnvelopeEncryptor(Protocol):
    """Encrypt/decrypt bytes with a custody-managed key reference."""

    key_reference: str

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> EncryptedEnvelope:
        """Return an encrypted envelope; never serialize the raw key."""

    def decrypt(self, envelope: EncryptedEnvelope, *, associated_data: bytes) -> bytes:
        """Decrypt and authenticate an envelope."""


class BackupVault(Protocol):
    """The only persistence boundary used by the coordinator."""

    destination: BackupDestination

    def put(self, artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt:
        """Store an immutable artifact or return a safe idempotent receipt."""

    def get(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
    ) -> BackupArtifact:
        """Read one artifact inside the caller's tenant/application scope."""

    def delete(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        now: datetime,
    ) -> None:
        """Delete only after retention expiry; locked deletion must fail."""


def utc(value: datetime) -> datetime:
    """Normalize an aware timestamp to UTC for canonical evidence."""

    if value.tzinfo is None:
        raise BackupBoundaryError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def validate_component_name(value: str) -> str:
    normalized = value.strip().casefold()
    if _COMPONENT_NAME.fullmatch(normalized) is None:
        raise BackupBoundaryError("backup component name is unsafe")
    return normalized


def validate_metadata(metadata: Mapping[str, object]) -> None:
    """Reject credential-like metadata before it can enter job evidence."""

    for key, value in metadata.items():
        if str(key) in {"key_reference", "credential_reference"}:
            if value is not None and not is_safe_credential_reference(value):
                raise BackupBoundaryError("backup custody reference is unsafe")
            continue
        if any(marker in str(key).casefold() for marker in ("secret", "token", "password", "key")):
            raise BackupBoundaryError("backup metadata contains a secret field")
        if isinstance(value, str) and contains_credential_like(value):
            raise BackupBoundaryError("backup metadata contains a credential-like value")
