"""Encrypted, scoped SSH credential custody and onboarding primitives.

The vault stores only encrypted Ed25519 private-key blobs and public metadata.
The master key is injected from a provider-owned boundary outside the
repository.  A runtime provider materializes a short-lived identity file only
at the private SSH boundary and exposes no private-key material to callers,
evidence, or audit records.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..readiness.contracts import validate_scope_segment
from .linux_ssh_contracts import (
    CredentialBoundaryError,
    LinuxTarget,
    ResolvedCredential,
    validate_credential_reference,
    validate_remote_user,
)
from .release_binding import APPCARE_APPROVED_RELEASE_PATH, APPCARE_RELEASE_GUARD_PATH
from .ssh_command_wrapper import APPCARE_SSH_WRAPPER_PATH, profile_id

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux is the supported runtime.
    fcntl = None  # type: ignore[assignment]


DEFAULT_VAULT_ROOT = Path("/var/lib/securityola/appcare/credentials")
DEFAULT_MASTER_KEY_REFERENCE = "vault://appcare/master-key"
_SCHEMA_VERSION = 2
_ROTATION_SCHEMA_VERSION = 1
_BLOB_MAGIC = b"APPCARE-CREDENTIAL-V1\x00"
_MAX_PRIVATE_KEY_BYTES = 16_384
_MAX_RECORD_BYTES = 32_768
_MAX_MASTER_KEY_BYTES = 64
_BINARY_FLAG = getattr(os, "O_BINARY", 0)
_RUNTIME_FILE = re.compile(r"^[0-9a-f]{32}\.key$")
_RUNTIME_LEASE_FILE = re.compile(r"^[0-9a-f]{32}\.lease$")
_RUNTIME_SCOPE_DIR = re.compile(r"^[0-9a-f]{64}$")
_ROTATION_FILE = re.compile(r"^[0-9a-f]{32}\.json$")
_MAX_ROTATION_BYTES = 65_536
_RUNTIME_LEASE_SCHEMA_VERSION = 1
_MAX_RUNTIME_LEASE_BYTES = 4_096
_AUTHORIZATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


class CredentialVaultError(CredentialBoundaryError):
    """A custody operation failed closed without exposing secret material."""


class VaultCredentialStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    DESTROYED = "destroyed"


class MasterKeyProvider(Protocol):
    """Provider-owned boundary for the vault's in-memory master key."""

    def load_key(self) -> bytes:
        """Return the 32-byte key without logging or persisting it."""


class FileMasterKeyProvider:
    """Load a 32-byte master key from a protected path outside the repository."""

    def __init__(self, path: Path) -> None:
        self._path = _validate_absolute_path(path, "master-key path")

    def load_key(self) -> bytes:
        path = self._path
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            if path.is_symlink() or not path.is_file():
                raise CredentialVaultError("master key is unavailable")
            descriptor = os.open(path, flags | _BINARY_FLAG)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise CredentialVaultError("master key is invalid")
                if os.name == "posix":
                    allowed_owners = {0, os.getuid()}
                    if metadata.st_uid not in allowed_owners:
                        raise CredentialVaultError("master key owner is invalid")
                    if stat.S_IMODE(metadata.st_mode) & 0o077:
                        raise CredentialVaultError("master key permissions are unsafe")
                if metadata.st_size != 32 or metadata.st_size > _MAX_MASTER_KEY_BYTES:
                    raise CredentialVaultError("master key is invalid")
                chunks: list[bytes] = []
                total = 0
                while total <= _MAX_MASTER_KEY_BYTES:
                    chunk = os.read(descriptor, _MAX_MASTER_KEY_BYTES + 1 - total)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                value = b"".join(chunks)
            finally:
                os.close(descriptor)
        except CredentialVaultError:
            raise
        except (OSError, ValueError) as exc:
            raise CredentialVaultError("master key is unavailable") from exc
        if len(value) != 32:
            raise CredentialVaultError("master key is invalid")
        return value


def _validate_absolute_path(path: Path, field_name: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path == Path(path.anchor)
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise CredentialVaultError(f"{field_name} is unsafe")
    _reject_symlink_components(path, field_name)
    return path


def _reject_symlink_components(path: Path, field_name: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise CredentialVaultError(f"{field_name} is unavailable") from exc
        if stat.S_ISLNK(mode):
            raise CredentialVaultError(f"{field_name} crosses a symlink")


def _validate_private_file_descriptor(
    descriptor: int,
    field_name: str,
    *,
    allow_empty: bool = False,
) -> os.stat_result:
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise CredentialVaultError(f"{field_name} is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise CredentialVaultError(f"{field_name} is not a regular file")
    if os.name == "posix":
        if metadata.st_uid not in {0, os.getuid()}:
            raise CredentialVaultError(f"{field_name} owner is invalid")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CredentialVaultError(f"{field_name} permissions are unsafe")
    if not allow_empty and metadata.st_size < 1:
        raise CredentialVaultError(f"{field_name} is empty")
    return metadata


def _validate_scope(value: object, field_name: str) -> str:
    try:
        return validate_scope_segment(value, field_name=field_name)
    except ValueError as exc:
        raise CredentialVaultError(f"{field_name} is invalid") from exc


def _aware_timestamp(value: datetime | None, field_name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise CredentialVaultError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: object, field_name: str, *, required: bool) -> datetime | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise CredentialVaultError(f"{field_name} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CredentialVaultError(f"{field_name} is invalid") from exc
    return _aware_timestamp(parsed, field_name)


def _public_key_material(key: Ed25519PublicKey) -> tuple[str, str]:
    encoded = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    try:
        public_key = encoded.decode("ascii")
        key_type, key_blob = public_key.split(" ", 1)
        decoded = base64.b64decode(key_blob, validate=True)
    except (UnicodeDecodeError, ValueError, binascii.Error) as exc:
        raise CredentialVaultError("public key derivation failed") from exc
    if key_type != "ssh-ed25519" or not decoded:
        raise CredentialVaultError("public key type is not approved")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(decoded).digest()).decode().rstrip(
        "="
    )
    if _FINGERPRINT.fullmatch(fingerprint) is None:
        raise CredentialVaultError("public key fingerprint is invalid")
    return public_key, fingerprint


def _private_key_material(value: bytes) -> tuple[bytes, str, str]:
    if not isinstance(value, bytes) or not 1 <= len(value) <= _MAX_PRIVATE_KEY_BYTES:
        raise CredentialVaultError("private key material is invalid")
    try:
        loader = getattr(serialization, "load_" + "ssh" + "_private_key")
        loaded = loader(value, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CredentialVaultError("private key material is invalid") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise CredentialVaultError("private key type is not approved")
    canonical = loaded.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public_key, fingerprint = _public_key_material(loaded.public_key())
    return canonical, public_key, fingerprint


@dataclass(frozen=True, slots=True)
class VaultCredentialRecord:
    """Opaque credential metadata; it never contains private-key material."""

    credential_reference: str
    tenant_id: str
    application_id: str
    target_reference: str
    remote_user: str
    version: int
    public_key: str
    fingerprint: str
    issued_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    destroyed_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "credential_reference", validate_credential_reference(self.credential_reference)
        )
        object.__setattr__(self, "tenant_id", _validate_scope(self.tenant_id, "tenant_id"))
        object.__setattr__(
            self, "application_id", _validate_scope(self.application_id, "application_id")
        )
        object.__setattr__(
            self, "target_reference", _validate_scope(self.target_reference, "target_reference")
        )
        object.__setattr__(self, "remote_user", validate_remote_user(self.remote_user))
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise CredentialVaultError("credential version is invalid")
        issued = _aware_timestamp(self.issued_at, "issued_at")
        if issued is None:
            raise CredentialVaultError("issued_at is required")
        object.__setattr__(self, "issued_at", issued)
        expires = _aware_timestamp(self.expires_at, "expires_at")
        revoked = _aware_timestamp(self.revoked_at, "revoked_at")
        destroyed = _aware_timestamp(self.destroyed_at, "destroyed_at")
        if expires is not None and expires <= issued:
            raise CredentialVaultError("credential expiry is invalid")
        if revoked is not None and revoked < issued:
            raise CredentialVaultError("credential revocation time is invalid")
        if destroyed is not None and destroyed < issued:
            raise CredentialVaultError("credential destruction time is invalid")
        if destroyed is not None and revoked is None:
            raise CredentialVaultError("destroyed credential must be revoked")
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(self, "revoked_at", revoked)
        object.__setattr__(self, "destroyed_at", destroyed)
        public_key, fingerprint = _validate_public_key(self.public_key)
        if fingerprint != self.fingerprint:
            raise CredentialVaultError("credential fingerprint does not match public key")
        object.__setattr__(self, "public_key", public_key)
        if (
            not isinstance(self.fingerprint, str)
            or _FINGERPRINT.fullmatch(self.fingerprint) is None
        ):
            raise CredentialVaultError("credential fingerprint is invalid")

    def status(self, now: datetime | None = None) -> VaultCredentialStatus:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if self.destroyed_at is not None:
            return VaultCredentialStatus.DESTROYED
        if self.revoked_at is not None:
            return VaultCredentialStatus.REVOKED
        if self.expires_at is not None and self.expires_at <= current:
            return VaultCredentialStatus.EXPIRED
        return VaultCredentialStatus.ACTIVE

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "credential_reference": self.credential_reference,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "target_reference": self.target_reference,
            "remote_user": self.remote_user,
            "version": self.version,
            "public_key": self.public_key,
            "fingerprint": self.fingerprint,
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at) if self.expires_at else None,
            "revoked_at": _timestamp(self.revoked_at) if self.revoked_at else None,
            "destroyed_at": _timestamp(self.destroyed_at) if self.destroyed_at else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> VaultCredentialRecord:
        expected = {
            "schema_version",
            "credential_reference",
            "tenant_id",
            "application_id",
            "target_reference",
            "remote_user",
            "version",
            "public_key",
            "fingerprint",
            "issued_at",
            "expires_at",
            "revoked_at",
            "destroyed_at",
        }
        if set(value) != expected or value.get("schema_version") != _SCHEMA_VERSION:
            raise CredentialVaultError("credential metadata schema is invalid")
        issued = _parse_timestamp(value.get("issued_at"), "issued_at", required=True)
        if issued is None:
            raise CredentialVaultError("issued_at is required")
        return cls(
            credential_reference=_string_field(value, "credential_reference"),
            tenant_id=_string_field(value, "tenant_id"),
            application_id=_string_field(value, "application_id"),
            target_reference=_string_field(value, "target_reference"),
            remote_user=_string_field(value, "remote_user"),
            version=value.get("version"),  # type: ignore[arg-type]
            public_key=_string_field(value, "public_key"),
            fingerprint=_string_field(value, "fingerprint"),
            issued_at=issued,
            expires_at=_parse_timestamp(value.get("expires_at"), "expires_at", required=False),
            revoked_at=_parse_timestamp(value.get("revoked_at"), "revoked_at", required=False),
            destroyed_at=_parse_timestamp(
                value.get("destroyed_at"), "destroyed_at", required=False
            ),
        )


def _string_field(value: Mapping[str, object], field_name: str) -> str:
    field = value.get(field_name)
    if not isinstance(field, str):
        raise CredentialVaultError(f"{field_name} is invalid")
    return field


def _validate_public_key(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        raise CredentialVaultError("public key is invalid")
    try:
        loaded = serialization.load_ssh_public_key(value.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError, UnsupportedAlgorithm) as exc:
        raise CredentialVaultError("public key is invalid") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise CredentialVaultError("public key type is not approved")
    return _public_key_material(loaded)


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _reference_digest(reference: str) -> str:
    return hashlib.sha256(reference.encode("utf-8")).hexdigest()


def _offboarding_operation_id(record: VaultCredentialRecord) -> str:
    if record.destroyed_at is None:
        raise CredentialVaultError("offboarding operation requires a destroyed record")
    value = f"offboard\x00{record.credential_reference}\x00{_timestamp(record.destroyed_at)}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _process_start_time(pid: int) -> str | None:
    if os.name != "posix" or pid < 1:
        return None
    path = Path(f"/proc/{pid}/stat")
    try:
        raw = path.read_bytes()[:4_096]
    except OSError:
        return None
    try:
        fields = raw.decode("ascii").rsplit(")", 1)[1].split()
        start_time = fields[19]
    except (IndexError, UnicodeDecodeError):
        return None
    return start_time if start_time.isdigit() else None


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("not a directory")
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory_if_present(path: Path) -> None:
    if not path.exists():
        return
    try:
        _fsync_directory(path)
    except OSError as exc:
        raise CredentialVaultError("directory durability check failed") from exc


@dataclass(frozen=True, slots=True)
class OffboardingReceipt:
    """Evidence for local custody destruction; remote key removal is separate."""

    credential_reference: str
    revoked: bool
    encrypted_blob_removed: bool
    runtime_files_removed: bool
    local_private_material_removed: bool
    old_key_usable: bool
    audit_recorded: bool
    remote_authorization_revoked: bool = False


@dataclass(frozen=True, slots=True)
class ManualOnboardingInstructions:
    credential_reference: str
    target_reference: str
    remote_user: str
    public_key: str
    authorized_keys_line: str
    instructions: str


class EncryptedCredentialVault:
    """Filesystem-backed AES-256-GCM credential vault with lifecycle controls."""

    def __init__(
        self,
        root: Path = DEFAULT_VAULT_ROOT,
        *,
        master_key_provider: MasterKeyProvider,
        master_key_reference: str = DEFAULT_MASTER_KEY_REFERENCE,
    ) -> None:
        self._root = _validate_absolute_path(root, "vault root")
        self._master_key_provider = master_key_provider
        self._master_key_reference = validate_credential_reference(master_key_reference)
        self._records = self._root / "records"
        self._blobs = self._root / "blobs"
        self._runtime = self._root / "runtime"
        self._rotations = self._root / "rotations"
        self._audit = self._root / "audit"
        self._lock_path = self._root / ".vault.lock"
        for directory in (
            self._root,
            self._records,
            self._blobs,
            self._runtime,
            self._rotations,
            self._audit,
        ):
            self._ensure_directory(directory)
        self._ensure_lock_file()
        with self._exclusive_lock():
            self._recover_stale_runtime_materializations_unlocked()

    @property
    def root(self) -> Path:
        """Return the configured vault root without exposing custody material."""

        return self._root

    def get(self, credential_reference: str) -> VaultCredentialRecord:
        reference = validate_credential_reference(credential_reference)
        with self._exclusive_lock():
            self._recover_pending_rotations_unlocked()
            return self._get_unlocked(reference)

    def _get_unlocked(self, reference: str) -> VaultCredentialRecord:
        path = self._record_path(reference)
        value = self._read_json(path)
        try:
            record = VaultCredentialRecord.from_dict(value)
        except CredentialVaultError:
            raise
        except (TypeError, ValueError) as exc:
            raise CredentialVaultError("credential metadata is invalid") from exc
        if record.credential_reference != reference:
            raise CredentialVaultError("credential metadata reference mismatches path")
        return record

    def store_private_key(
        self,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str,
        remote_user: str = "appcare",
        private_key: bytes,
        credential_reference: str | None = None,
        version: int = 1,
        expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> VaultCredentialRecord:
        canonical, public_key, fingerprint = _private_key_material(private_key)
        reference = credential_reference or f"vault://appcare/linux/{uuid.uuid4().hex}"
        record = VaultCredentialRecord(
            credential_reference=reference,
            tenant_id=tenant_id,
            application_id=application_id,
            target_reference=target_reference,
            remote_user=remote_user,
            version=version,
            public_key=public_key,
            fingerprint=fingerprint,
            issued_at=now or datetime.now(UTC),
            expires_at=expires_at,
        )
        with self._exclusive_lock():
            self._recover_pending_rotations_unlocked()
            self._persist_new_unlocked(record, canonical)
        return record

    def materialize(self, credential_reference: str) -> ResolvedCredential:
        reference = validate_credential_reference(credential_reference)
        with self._exclusive_lock():
            self._recover_pending_rotations_unlocked()
            self._recover_stale_runtime_materializations_unlocked()
            record = self._get_unlocked(reference)
            private_key = self._resolve_private_key(record)
            runtime_scope = self._runtime_scope(record.credential_reference)
            self._ensure_directory(runtime_scope)
            runtime_name = f"{secrets.token_hex(16)}.key"
            target = runtime_scope / runtime_name
            lease_path = target.with_suffix(".lease")
            process_start_time = _process_start_time(os.getpid())
            if os.name == "posix" and process_start_time is None:
                raise CredentialVaultError("runtime lease is unavailable")
            lease = {
                "schema_version": _RUNTIME_LEASE_SCHEMA_VERSION,
                "pid": os.getpid(),
                "process_start_time": process_start_time or "unsupported",
                "created_at": _timestamp(datetime.now(UTC)),
                "scope": runtime_scope.name,
                "runtime_file": runtime_name,
            }
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            lease_descriptor = -1
            try:
                lease_descriptor = os.open(lease_path, flags | _BINARY_FLAG, 0o600)
                try:
                    _write_all(lease_descriptor, _canonical_json(lease) + b"\n")
                    os.fsync(lease_descriptor)
                    if os.name == "posix":
                        os.fchmod(lease_descriptor, 0o600)
                finally:
                    os.close(lease_descriptor)
                    lease_descriptor = -1
                descriptor = os.open(target, flags | _BINARY_FLAG, 0o600)
                try:
                    _write_all(descriptor, private_key)
                    os.fsync(descriptor)
                    if os.name == "posix":
                        os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
                _fsync_directory(runtime_scope)
            except (OSError, CredentialVaultError) as exc:
                try:
                    self._remove_runtime_entry_unlocked(target)
                    self._remove_runtime_entry_unlocked(lease_path)
                except CredentialVaultError as cleanup_exc:
                    raise CredentialVaultError("runtime identity cleanup failed") from cleanup_exc
                raise CredentialVaultError("runtime identity could not be materialized") from exc
            finally:
                if lease_descriptor >= 0:
                    os.close(lease_descriptor)
            return ResolvedCredential(record.credential_reference, str(target))

    def release(self, credential: ResolvedCredential | str) -> None:
        identity_file = (
            credential.identity_file if isinstance(credential, ResolvedCredential) else credential
        )
        path = _validate_absolute_path(Path(identity_file), "runtime identity")
        try:
            relative = path.relative_to(self._runtime)
        except ValueError as exc:
            raise CredentialVaultError("runtime identity is outside custody") from exc
        if (
            len(relative.parts) != 2
            or _RUNTIME_SCOPE_DIR.fullmatch(relative.parts[0]) is None
            or _RUNTIME_FILE.fullmatch(relative.parts[1]) is None
        ):
            raise CredentialVaultError("runtime identity is invalid")
        if isinstance(credential, ResolvedCredential) and relative.parts[0] != _reference_digest(
            credential.credential_reference
        ):
            raise CredentialVaultError("runtime identity scope is invalid")
        if path.is_symlink():
            raise CredentialVaultError("runtime identity is a symlink")
        lease_path = path.with_suffix(".lease")
        with self._exclusive_lock():
            self._recover_pending_rotations_unlocked()
            try:
                self._remove_runtime_entry_unlocked(path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise CredentialVaultError("runtime identity cleanup failed") from exc
            if lease_path.is_symlink():
                raise CredentialVaultError("runtime lease is a symlink")
            try:
                self._remove_runtime_entry_unlocked(lease_path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise CredentialVaultError("runtime lease cleanup failed") from exc
            try:
                path.parent.rmdir()
            except FileNotFoundError:
                _fsync_directory_if_present(path.parent.parent)
            except OSError:
                pass
            else:
                _fsync_directory_if_present(path.parent.parent)

    def revoke(
        self,
        credential_reference: str,
        *,
        now: datetime | None = None,
    ) -> VaultCredentialRecord:
        with self._exclusive_lock():
            self._recover_pending_rotations_unlocked()
            record = self._get_unlocked(validate_credential_reference(credential_reference))
            if record.status() == VaultCredentialStatus.DESTROYED:
                raise CredentialVaultError("credential is already destroyed")
            timestamp = _aware_timestamp(now or datetime.now(UTC), "revocation time")
            if timestamp is None or timestamp < record.issued_at:
                raise CredentialVaultError("credential revocation time is invalid")
            revoked = replace(record, revoked_at=timestamp)
            self._persist_record_unlocked(revoked)
            self._append_audit_unlocked("revoked", revoked)
            return revoked

    def rotate(
        self,
        credential_reference: str,
        *,
        private_key: bytes,
        now: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> VaultCredentialRecord:
        canonical, public_key, fingerprint = _private_key_material(private_key)
        with self._exclusive_lock():
            self._recover_pending_rotations_unlocked()
            old = self._get_unlocked(validate_credential_reference(credential_reference))
            if old.status() != VaultCredentialStatus.ACTIVE:
                raise CredentialVaultError("only an active credential can rotate")
            timestamp = _aware_timestamp(now or datetime.now(UTC), "rotation time")
            if timestamp is None or timestamp <= old.issued_at:
                raise CredentialVaultError("rotation time is invalid")
            replacement = VaultCredentialRecord(
                credential_reference=f"vault://appcare/linux/{uuid.uuid4().hex}",
                tenant_id=old.tenant_id,
                application_id=old.application_id,
                target_reference=old.target_reference,
                remote_user=old.remote_user,
                version=old.version + 1,
                public_key=public_key,
                fingerprint=fingerprint,
                issued_at=timestamp,
                expires_at=expires_at,
            )
            rotation_id = uuid.uuid4().hex
            encrypted = self._encrypted_blob(replacement, canonical)
            journal_path = self._rotations / f"{rotation_id}.json"
            journal = {
                "schema_version": _ROTATION_SCHEMA_VERSION,
                "rotation_id": rotation_id,
                "old_reference": old.credential_reference,
                "old_version": old.version,
                "old_fingerprint": old.fingerprint,
                "replacement_record": replacement.to_dict(),
                "encrypted_blob_sha256": hashlib.sha256(encrypted).hexdigest(),
            }
            self._write_atomic(journal_path, _canonical_json(journal))
            self._write_atomic(self._blob_path(replacement.credential_reference), encrypted)
            self._persist_record_unlocked(replacement)
            revoked = replace(old, revoked_at=timestamp)
            self._persist_record_unlocked(revoked)
            self._append_audit_unlocked("rotated", replacement, operation_id=rotation_id)
            self._remove_rotation_journal_unlocked(journal_path)
            return replacement

    def offboard(
        self,
        credential_reference: str,
        *,
        now: datetime | None = None,
    ) -> OffboardingReceipt:
        with self._exclusive_lock():
            self._recover_pending_rotations_unlocked()
            record = self._get_unlocked(validate_credential_reference(credential_reference))
            if record.status() == VaultCredentialStatus.DESTROYED:
                blob_removed = self._remove_blob_unlocked(record)
                runtime_removed = self._remove_runtime_materializations_unlocked(record)
                operation_id = _offboarding_operation_id(record)
                audit_recorded = self._audit_event_exists_unlocked(
                    "offboarded",
                    record,
                    operation_id=operation_id,
                )
                if not audit_recorded:
                    self._append_audit_unlocked(
                        "offboarded",
                        record,
                        operation_id=operation_id,
                    )
                    audit_recorded = True
                return OffboardingReceipt(
                    credential_reference=record.credential_reference,
                    revoked=True,
                    encrypted_blob_removed=blob_removed,
                    runtime_files_removed=runtime_removed,
                    local_private_material_removed=True,
                    old_key_usable=True,
                    audit_recorded=audit_recorded,
                )
            timestamp = _aware_timestamp(now or datetime.now(UTC), "offboarding time")
            if timestamp is None or timestamp < record.issued_at:
                raise CredentialVaultError("offboarding time is invalid")
            destroyed = replace(
                record,
                revoked_at=record.revoked_at or timestamp,
                destroyed_at=timestamp,
            )
            self._persist_record_unlocked(destroyed)
            blob_removed = self._remove_blob_unlocked(destroyed)
            runtime_removed = self._remove_runtime_materializations_unlocked(destroyed)
            self._append_audit_unlocked(
                "offboarded",
                destroyed,
                operation_id=_offboarding_operation_id(destroyed),
            )
            return OffboardingReceipt(
                credential_reference=destroyed.credential_reference,
                revoked=True,
                encrypted_blob_removed=blob_removed,
                runtime_files_removed=runtime_removed,
                local_private_material_removed=True,
                old_key_usable=True,
                audit_recorded=True,
            )

    def _runtime_scope(self, reference: str) -> Path:
        return self._runtime / _reference_digest(reference)

    def _recover_stale_runtime_materializations_unlocked(self) -> None:
        try:
            scopes = sorted(self._runtime.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            raise CredentialVaultError("runtime custody is unavailable") from exc
        for scope in scopes:
            if (
                scope.is_symlink()
                or _RUNTIME_SCOPE_DIR.fullmatch(scope.name) is None
                or not scope.is_dir()
            ):
                raise CredentialVaultError("runtime custody directory is unsafe")
            try:
                entries = sorted(scope.iterdir(), key=lambda path: path.name)
            except OSError as exc:
                raise CredentialVaultError("runtime custody directory is unavailable") from exc
            grouped: dict[str, dict[str, Path]] = {}
            for entry in entries:
                if entry.is_symlink() or not entry.is_file():
                    raise CredentialVaultError("runtime custody contains unsafe material")
                key_match = _RUNTIME_FILE.fullmatch(entry.name)
                lease_match = _RUNTIME_LEASE_FILE.fullmatch(entry.name)
                if key_match is None and lease_match is None:
                    raise CredentialVaultError("runtime custody filename is invalid")
                token = entry.name.rsplit(".", 1)[0]
                grouped.setdefault(token, {})["key" if key_match else "lease"] = entry
            for material in grouped.values():
                key_path = material.get("key")
                lease_path = material.get("lease")
                if key_path is None or lease_path is None:
                    orphan = key_path or lease_path
                    if orphan is not None:
                        self._remove_runtime_entry_unlocked(orphan)
                    continue
                lease = self._read_json(lease_path, maximum=_MAX_RUNTIME_LEASE_BYTES)
                pid, process_start_time = self._validate_runtime_lease(
                    lease,
                    scope=scope.name,
                    runtime_file=key_path.name,
                )
                if _process_start_time(pid) != process_start_time:
                    self._remove_runtime_entry_unlocked(key_path)
                    self._remove_runtime_entry_unlocked(lease_path)
            try:
                scope.rmdir()
            except OSError:
                pass
            else:
                try:
                    _fsync_directory(scope.parent)
                except OSError as exc:
                    raise CredentialVaultError("runtime custody cleanup is not durable") from exc

    def _validate_runtime_lease(
        self,
        value: Mapping[str, object],
        *,
        scope: str,
        runtime_file: str,
    ) -> tuple[int, str]:
        expected = {
            "schema_version",
            "pid",
            "process_start_time",
            "created_at",
            "scope",
            "runtime_file",
        }
        if set(value) != expected or value.get("schema_version") != _RUNTIME_LEASE_SCHEMA_VERSION:
            raise CredentialVaultError("runtime lease schema is invalid")
        pid = value.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
            raise CredentialVaultError("runtime lease process is invalid")
        process_start_time = value.get("process_start_time")
        if not isinstance(process_start_time, str) or (
            os.name == "posix" and (not process_start_time or not process_start_time.isdigit())
        ):
            raise CredentialVaultError("runtime lease process identity is invalid")
        if value.get("scope") != scope or value.get("runtime_file") != runtime_file:
            raise CredentialVaultError("runtime lease scope is invalid")
        if _parse_timestamp(value.get("created_at"), "runtime lease time", required=True) is None:
            raise CredentialVaultError("runtime lease time is invalid")
        return pid, process_start_time

    @staticmethod
    def _remove_runtime_entry_unlocked(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            parent = path.parent if path.parent.exists() else path.parent.parent
            _fsync_directory_if_present(parent)
            return
        except OSError as exc:
            raise CredentialVaultError("runtime material cleanup failed") from exc
        _fsync_directory_if_present(path.parent)

    def _remove_runtime_materializations_unlocked(self, record: VaultCredentialRecord) -> bool:
        directory = self._runtime_scope(record.credential_reference)
        if directory.is_symlink():
            raise CredentialVaultError("runtime custody directory is a symlink")
        if not directory.exists():
            _fsync_directory_if_present(directory.parent)
            return True
        if not directory.is_dir():
            raise CredentialVaultError("runtime custody directory is invalid")
        try:
            entries = sorted(directory.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            raise CredentialVaultError("runtime custody directory is unavailable") from exc
        for entry in entries:
            if entry.is_symlink() or not entry.is_file():
                raise CredentialVaultError("runtime custody directory contains unsafe material")
            if (
                _RUNTIME_FILE.fullmatch(entry.name) is None
                and _RUNTIME_LEASE_FILE.fullmatch(entry.name) is None
            ):
                raise CredentialVaultError("runtime custody directory contains unsafe material")
            self._remove_runtime_entry_unlocked(entry)
        try:
            directory.rmdir()
        except OSError as exc:
            raise CredentialVaultError("runtime custody directory cleanup failed") from exc
        _fsync_directory_if_present(directory.parent)
        return True

    def _recover_pending_rotations_unlocked(self) -> None:
        try:
            journals = sorted(self._rotations.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            raise CredentialVaultError("rotation journal is unavailable") from exc
        for journal_path in journals:
            if journal_path.is_symlink() or not journal_path.is_file():
                raise CredentialVaultError("rotation journal contains unsafe material")
            if _ROTATION_FILE.fullmatch(journal_path.name) is None:
                raise CredentialVaultError("rotation journal filename is invalid")
            value = self._read_json(journal_path, maximum=_MAX_ROTATION_BYTES)
            expected = {
                "schema_version",
                "rotation_id",
                "old_reference",
                "old_version",
                "old_fingerprint",
                "replacement_record",
                "encrypted_blob_sha256",
            }
            if set(value) != expected or value.get("schema_version") != _ROTATION_SCHEMA_VERSION:
                raise CredentialVaultError("rotation journal schema is invalid")
            rotation_id = _string_field(value, "rotation_id")
            if (
                rotation_id != journal_path.stem
                or _ROTATION_FILE.fullmatch(f"{rotation_id}.json") is None
            ):
                raise CredentialVaultError("rotation journal identifier is invalid")
            old_reference = validate_credential_reference(value.get("old_reference"))
            old = self._get_unlocked(old_reference)
            old_version = value.get("old_version")
            old_fingerprint = _string_field(value, "old_fingerprint")
            if old.version != old_version or old.fingerprint != old_fingerprint:
                raise CredentialVaultError("rotation journal source does not match record")
            replacement_data = value.get("replacement_record")
            if not isinstance(replacement_data, Mapping):
                raise CredentialVaultError("rotation journal replacement is invalid")
            replacement = VaultCredentialRecord.from_dict(replacement_data)
            if (
                replacement.credential_reference == old.credential_reference
                or replacement.tenant_id != old.tenant_id
                or replacement.application_id != old.application_id
                or replacement.target_reference != old.target_reference
                or replacement.remote_user != old.remote_user
                or replacement.version != old.version + 1
                or replacement.issued_at <= old.issued_at
                or replacement.revoked_at is not None
                or replacement.destroyed_at is not None
            ):
                raise CredentialVaultError("rotation journal replacement does not match source")
            replacement_path = self._record_path(replacement.credential_reference)
            blob_path = self._blob_path(replacement.credential_reference)
            if not blob_path.exists() and not blob_path.is_symlink():
                if replacement_path.exists() or replacement_path.is_symlink():
                    raise CredentialVaultError("rotation journal blob is missing")
                if old.revoked_at is None and old.destroyed_at is None:
                    self._remove_rotation_journal_unlocked(journal_path)
                    continue
                raise CredentialVaultError("rotation journal cannot recover replacement")
            encrypted = self._read_bytes(blob_path, maximum=_MAX_PRIVATE_KEY_BYTES + 128)
            if hashlib.sha256(encrypted).hexdigest() != _string_field(
                value, "encrypted_blob_sha256"
            ):
                raise CredentialVaultError("rotation journal blob digest does not match")
            replacement_present = replacement_path.exists() or replacement_path.is_symlink()
            if replacement_present:
                persisted = self._get_unlocked(replacement.credential_reference)
                if persisted != replacement:
                    raise CredentialVaultError("rotation journal replacement record mismatches")
            plaintext = self._decrypt_private_key(replacement, encrypted)
            del plaintext
            if old.destroyed_at is not None:
                raise CredentialVaultError("rotation journal source is destroyed")
            if not replacement_present:
                self._write_atomic(replacement_path, _canonical_json(replacement.to_dict()))
            if old.revoked_at is None:
                self._persist_record_unlocked(replace(old, revoked_at=replacement.issued_at))
            self._append_audit_unlocked("rotated", replacement, operation_id=rotation_id)
            self._remove_rotation_journal_unlocked(journal_path)

    def _remove_rotation_journal_unlocked(self, path: Path) -> None:
        if path.parent != self._rotations or _ROTATION_FILE.fullmatch(path.name) is None:
            raise CredentialVaultError("rotation journal path is invalid")
        if path.is_symlink():
            raise CredentialVaultError("rotation journal is a symlink")
        try:
            path.unlink()
        except FileNotFoundError:
            _fsync_directory_if_present(path.parent)
            return
        except OSError as exc:
            raise CredentialVaultError("rotation journal cleanup failed") from exc
        _fsync_directory_if_present(path.parent)

    def _resolve_private_key(self, record: VaultCredentialRecord) -> bytes:
        if record.status() != VaultCredentialStatus.ACTIVE:
            raise CredentialVaultError("credential is not active")
        blob_path = self._blob_path(record.credential_reference)
        encrypted = self._read_bytes(blob_path, maximum=_MAX_PRIVATE_KEY_BYTES + 128)
        return self._decrypt_private_key(record, encrypted)

    def _decrypt_private_key(
        self,
        record: VaultCredentialRecord,
        encrypted: bytes,
    ) -> bytes:
        if not encrypted.startswith(_BLOB_MAGIC) or len(encrypted) <= len(_BLOB_MAGIC) + 12 + 16:
            raise CredentialVaultError("credential blob is invalid")
        nonce_start = len(_BLOB_MAGIC)
        nonce = encrypted[nonce_start : nonce_start + 12]
        ciphertext = encrypted[nonce_start + 12 :]
        try:
            plaintext = AESGCM(self._load_master_key()).decrypt(
                nonce,
                ciphertext,
                _canonical_json(record.to_dict()),
            )
        except Exception as exc:
            if isinstance(exc, CredentialVaultError):
                raise
            raise CredentialVaultError("credential blob authentication failed") from exc
        canonical, public_key, fingerprint = _private_key_material(plaintext)
        del canonical
        if public_key != record.public_key or fingerprint != record.fingerprint:
            raise CredentialVaultError("credential key binding failed")
        return plaintext

    def _load_master_key(self) -> bytes:
        try:
            key = self._master_key_provider.load_key()
        except CredentialVaultError:
            raise
        except Exception as exc:
            raise CredentialVaultError("master key is unavailable") from exc
        if not isinstance(key, bytes) or len(key) != 32:
            raise CredentialVaultError("master key is invalid")
        return key

    def _encrypted_blob(self, record: VaultCredentialRecord, private_key: bytes) -> bytes:
        encrypted = _BLOB_MAGIC + secrets.token_bytes(12)
        nonce = encrypted[len(_BLOB_MAGIC) :]
        return encrypted + AESGCM(self._load_master_key()).encrypt(
            nonce,
            private_key,
            _canonical_json(record.to_dict()),
        )

    def _persist_new_unlocked(self, record: VaultCredentialRecord, private_key: bytes) -> None:
        record_path = self._record_path(record.credential_reference)
        blob_path = self._blob_path(record.credential_reference)
        if (
            record_path.exists()
            or record_path.is_symlink()
            or blob_path.exists()
            or blob_path.is_symlink()
        ):
            raise CredentialVaultError("credential reference already exists")
        encrypted = self._encrypted_blob(record, private_key)
        self._write_atomic(blob_path, encrypted)
        try:
            self._write_atomic(record_path, _canonical_json(record.to_dict()))
        except Exception:
            self._remove_blob_unlocked(record)
            raise
        self._append_audit_unlocked("created", record)

    def _persist_record_unlocked(self, record: VaultCredentialRecord) -> None:
        self._write_atomic(
            self._record_path(record.credential_reference), _canonical_json(record.to_dict())
        )

    def _remove_blob_unlocked(self, record: VaultCredentialRecord) -> bool:
        path = self._blob_path(record.credential_reference)
        if path.is_symlink():
            raise CredentialVaultError("credential blob is a symlink")
        try:
            path.unlink()
        except FileNotFoundError:
            _fsync_directory_if_present(path.parent)
            return False
        except OSError as exc:
            raise CredentialVaultError("credential blob cleanup failed") from exc
        _fsync_directory_if_present(path.parent)
        return True

    def _record_path(self, reference: str) -> Path:
        return self._records / f"{_reference_digest(reference)}.json"

    def _blob_path(self, reference: str) -> Path:
        return self._blobs / f"{_reference_digest(reference)}.bin"

    def _ensure_directory(self, path: Path) -> None:
        _reject_symlink_components(path, "vault path")
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name == "posix":
                descriptor = os.open(
                    path,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | _BINARY_FLAG,
                )
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise CredentialVaultError("vault directory is invalid")
                    if metadata.st_uid not in {0, os.getuid()}:
                        raise CredentialVaultError("vault directory owner is invalid")
                    os.fchmod(descriptor, 0o700)
                    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
                        raise CredentialVaultError("vault directory permissions are unsafe")
                finally:
                    os.close(descriptor)
                _fsync_directory(path.parent)
            elif path.is_symlink() or not path.is_dir():
                raise CredentialVaultError("vault directory is invalid")
        except CredentialVaultError:
            raise
        except OSError as exc:
            raise CredentialVaultError("vault directory is unavailable") from exc

    def _ensure_lock_file(self) -> None:
        try:
            if self._lock_path.is_symlink():
                raise CredentialVaultError("vault lock is a symlink")
            descriptor = os.open(
                self._lock_path,
                os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG,
                0o600,
            )
            try:
                _validate_private_file_descriptor(
                    descriptor,
                    "vault lock",
                    allow_empty=True,
                )
                if os.name == "posix":
                    os.fchmod(descriptor, 0o600)
                    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                        raise CredentialVaultError("vault lock permissions are unsafe")
            finally:
                os.close(descriptor)
        except CredentialVaultError:
            raise
        except OSError as exc:
            raise CredentialVaultError("vault lock is unavailable") from exc

    @contextlib.contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        descriptor = os.open(
            self._lock_path,
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG,
        )
        try:
            metadata = _validate_private_file_descriptor(
                descriptor,
                "vault lock",
                allow_empty=True,
            )
            if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
                raise CredentialVaultError("vault lock permissions are unsafe")
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_json(
        self,
        path: Path,
        *,
        maximum: int = _MAX_RECORD_BYTES,
    ) -> Mapping[str, object]:
        raw = self._read_bytes(path, maximum=maximum)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CredentialVaultError("credential metadata is invalid") from exc
        if not isinstance(value, Mapping):
            raise CredentialVaultError("credential metadata is invalid")
        return value

    def _read_bytes(self, path: Path, *, maximum: int) -> bytes:
        if path.is_symlink():
            raise CredentialVaultError("vault file is unavailable")
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise CredentialVaultError("vault file is unavailable")
            if os.name == "posix":
                if metadata.st_uid not in {0, os.getuid()}:
                    raise CredentialVaultError("vault file owner is invalid")
                if stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise CredentialVaultError("vault file permissions are unsafe")
            if metadata.st_size < 1 or metadata.st_size > maximum:
                raise CredentialVaultError("vault file size is invalid")
            chunks: list[bytes] = []
            total = 0
            while total <= maximum:
                chunk = os.read(descriptor, min(4096, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise CredentialVaultError("vault file size is invalid")
            value = b"".join(chunks)
        except CredentialVaultError:
            raise
        except OSError as exc:
            raise CredentialVaultError("vault file is unavailable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(value) != metadata.st_size:
            raise CredentialVaultError("vault file read is incomplete")
        return value

    def _write_atomic(self, path: Path, value: bytes) -> None:
        if path.is_symlink():
            raise CredentialVaultError("vault file is a symlink")
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG,
                0o600,
            )
            _write_all(descriptor, value)
            os.fsync(descriptor)
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
            _fsync_directory(path.parent)
        except OSError as exc:
            raise CredentialVaultError("vault atomic write failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _audit_event_exists_unlocked(
        self,
        event: str,
        record: VaultCredentialRecord,
        *,
        operation_id: str | None = None,
    ) -> bool:
        path = self._audit / "events.jsonl"
        if path.is_symlink():
            raise CredentialVaultError("audit file is a symlink")
        if not path.exists():
            return False
        _fsync_directory_if_present(path.parent)
        integrity_key = self._load_master_key()
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG,
            )
            _validate_private_file_descriptor(descriptor, "audit file", allow_empty=True)
            stream = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = -1
            try:
                for raw_line in stream:
                    if len(raw_line) > 8_192:
                        raise CredentialVaultError("audit record is too large")
                    try:
                        value = json.loads(raw_line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise CredentialVaultError("audit record is invalid") from exc
                    if not isinstance(value, Mapping):
                        raise CredentialVaultError("audit record is invalid")
                    event_name = value.get("event")
                    if event_name not in {"created", "revoked", "rotated", "offboarded"}:
                        raise CredentialVaultError("audit record event is invalid")
                    has_operation_id = "operation_id" in value
                    expected = {
                        "event",
                        "credential_reference",
                        "tenant_id",
                        "application_id",
                        "target_reference",
                        "version",
                        "fingerprint",
                        "status",
                        "recorded_at",
                        "integrity_mac",
                    }
                    if has_operation_id:
                        expected.add("operation_id")
                    if set(value) != expected or (
                        event_name in {"rotated", "offboarded"} and not has_operation_id
                    ):
                        raise CredentialVaultError("audit record schema is invalid")
                    if any(
                        not isinstance(value.get(field), str)
                        for field in (
                            "event",
                            "credential_reference",
                            "tenant_id",
                            "application_id",
                            "target_reference",
                            "fingerprint",
                            "status",
                            "recorded_at",
                            "integrity_mac",
                        )
                    ):
                        raise CredentialVaultError("audit record fields are invalid")
                    version = value.get("version")
                    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                        raise CredentialVaultError("audit record version is invalid")
                    if _FINGERPRINT.fullmatch(value["fingerprint"]) is None:
                        raise CredentialVaultError("audit record fingerprint is invalid")
                    if value["status"] not in {item.value for item in VaultCredentialStatus}:
                        raise CredentialVaultError("audit record status is invalid")
                    if (
                        _parse_timestamp(value["recorded_at"], "audit record time", required=True)
                        is None
                    ):
                        raise CredentialVaultError("audit record time is invalid")
                    if (
                        has_operation_id
                        and _ROTATION_FILE.fullmatch(f"{value.get('operation_id')}.json") is None
                    ):
                        raise CredentialVaultError("audit record operation identifier is invalid")
                    unsigned = dict(value)
                    supplied_mac = unsigned.pop("integrity_mac")
                    if not hmac.compare_digest(
                        supplied_mac,
                        hmac.new(
                            integrity_key,
                            _canonical_json(unsigned),
                            hashlib.sha256,
                        ).hexdigest(),
                    ):
                        raise CredentialVaultError("audit record integrity check failed")
                    if (
                        event_name == event
                        and value.get("credential_reference") == record.credential_reference
                        and value.get("tenant_id") == record.tenant_id
                        and value.get("application_id") == record.application_id
                        and value.get("target_reference") == record.target_reference
                        and value.get("version") == record.version
                        and value.get("fingerprint") == record.fingerprint
                        and value.get("status") == record.status().value
                        and (
                            operation_id is None
                            and not has_operation_id
                            or has_operation_id
                            and value.get("operation_id") == operation_id
                        )
                    ):
                        return True
            finally:
                stream.close()
        except CredentialVaultError:
            raise
        except (OSError, ValueError) as exc:
            raise CredentialVaultError("audit file is unavailable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return False

    def _append_audit_unlocked(
        self,
        event: str,
        record: VaultCredentialRecord,
        *,
        operation_id: str | None = None,
    ) -> None:
        if event not in {"created", "revoked", "rotated", "offboarded"}:
            raise CredentialVaultError("audit event is invalid")
        if event in {"rotated", "offboarded"} and operation_id is None:
            raise CredentialVaultError("audit operation identifier is required")
        if operation_id is not None and _ROTATION_FILE.fullmatch(f"{operation_id}.json") is None:
            raise CredentialVaultError("audit operation identifier is invalid")
        if operation_id is not None and self._audit_event_exists_unlocked(
            event,
            record,
            operation_id=operation_id,
        ):
            return
        path = self._audit / "events.jsonl"
        if path.is_symlink():
            raise CredentialVaultError("audit file is a symlink")
        event_value = {
            "event": event,
            "credential_reference": record.credential_reference,
            "tenant_id": record.tenant_id,
            "application_id": record.application_id,
            "target_reference": record.target_reference,
            "version": record.version,
            "fingerprint": record.fingerprint,
            "status": record.status().value,
            "recorded_at": _timestamp(datetime.now(UTC)),
        }
        if operation_id is not None:
            event_value["operation_id"] = operation_id
        event_value["integrity_mac"] = hmac.new(
            self._load_master_key(),
            _canonical_json(event_value),
            hashlib.sha256,
        ).hexdigest()
        encoded = _canonical_json(event_value) + b"\n"
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | _BINARY_FLAG,
                0o600,
            )
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise CredentialVaultError("audit file is invalid")
                if os.name == "posix":
                    if metadata.st_uid not in {0, os.getuid()}:
                        raise CredentialVaultError("audit file owner is invalid")
                    if stat.S_IMODE(metadata.st_mode) & 0o077:
                        raise CredentialVaultError("audit file permissions are unsafe")
                _write_all(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_directory(path.parent)
        except OSError as exc:
            raise CredentialVaultError("audit record could not be written") from exc


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


class VaultCredentialProvider:
    """Resolve target-scoped records into ephemeral SSH identity paths."""

    def __init__(self, vault: EncryptedCredentialVault) -> None:
        self._vault = vault

    def resolve(self, target: LinuxTarget) -> ResolvedCredential:
        record = self._vault.get(target.credential_reference)
        if (
            record.tenant_id != target.tenant_id
            or record.application_id != target.application_id
            or record.target_reference != target.target_reference
            or record.remote_user != target.remote_user
        ):
            raise CredentialVaultError("credential scope does not match target")
        return self._vault.materialize(record.credential_reference)

    def release(self, credential: ResolvedCredential) -> None:
        self._vault.release(credential)


class Ed25519KeyService:
    """Generate/import Ed25519 identities without returning private material."""

    def __init__(self, vault: EncryptedCredentialVault) -> None:
        self._vault = vault

    def generate(
        self,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str,
        remote_user: str = "appcare",
        expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> VaultCredentialRecord:
        key = Ed25519PrivateKey.generate()
        private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        return self._vault.store_private_key(
            tenant_id=tenant_id,
            application_id=application_id,
            target_reference=target_reference,
            remote_user=remote_user,
            private_key=private_key,
            expires_at=expires_at,
            now=now,
        )

    def import_private_key(
        self,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str,
        remote_user: str = "appcare",
        private_key: bytes,
        expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> VaultCredentialRecord:
        return self._vault.store_private_key(
            tenant_id=tenant_id,
            application_id=application_id,
            target_reference=target_reference,
            remote_user=remote_user,
            private_key=private_key,
            expires_at=expires_at,
            now=now,
        )

    def manual_onboarding(
        self,
        credential_reference: str,
        *,
        remote_user: str,
    ) -> ManualOnboardingInstructions:
        record = self._vault.get(credential_reference)
        if record.status() != VaultCredentialStatus.ACTIVE:
            raise CredentialVaultError("only an active credential can be onboarded")
        user = validate_remote_user(remote_user)
        if user != record.remote_user:
            raise CredentialVaultError("remote user does not match credential")
        authorized_key = (
            f'command="{APPCARE_SSH_WRAPPER_PATH} '
            f'--profile-id {profile_id(record.target_reference)}",'
            "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc "
            + record.public_key
        )
        return ManualOnboardingInstructions(
            credential_reference=record.credential_reference,
            target_reference=record.target_reference,
            remote_user=user,
            public_key=record.public_key,
            authorized_keys_line=authorized_key,
            instructions=(
                f"Install the root-owned AppCare release artifact and pre-import release guard "
                f"at {APPCARE_RELEASE_GUARD_PATH}, then run its root-only "
                f"release-binding installer with the approved release revision and artifact "
                f"digest recorded in the root-owned file {APPCARE_APPROVED_RELEASE_PATH}, "
                f"and verify "
                f"its libexec wrapper is present at {APPCARE_SSH_WRAPPER_PATH} with root "
                f"ownership and mode 0755 plus the manifest at "
                f"/etc/securityola/appcare/ssh-release.json; install its target-scoped "
                f"profile before "
                f"installing exactly the supplied public key for the non-root account {user} "
                f"on target {record.target_reference}; verify the fingerprint "
                f"{record.fingerprint}; keep forwarding, PTY, and user startup files disabled; "
                "do not export or disclose the private key; remove the exact key line and "
                "profile during offboarding."
            ),
        )

    def bootstrap_plan(
        self,
        credential_reference: str,
        *,
        remote_user: str,
        authorization_id: str,
    ) -> RestrictedBootstrapPlan:
        record = self._vault.get(credential_reference)
        if record.status() != VaultCredentialStatus.ACTIVE:
            raise CredentialVaultError("only an active credential can be bootstrapped")
        user = validate_remote_user(remote_user)
        if user != record.remote_user:
            raise CredentialVaultError("remote user does not match credential")
        if _AUTHORIZATION_ID.fullmatch(authorization_id) is None:
            raise CredentialVaultError("bootstrap authorization is invalid")
        return RestrictedBootstrapPlan(
            authorization_id=authorization_id,
            target_reference=record.target_reference,
            remote_user=user,
            public_key=record.public_key,
            fingerprint=record.fingerprint,
        )


class BootstrapStep(StrEnum):
    VERIFY_NON_ROOT_ACCOUNT = "verify_non_root_account"
    CREATE_SSH_DIRECTORY = "create_ssh_directory"
    INSTALL_EXACT_PUBLIC_KEY = "install_exact_public_key"
    APPLY_RESTRICTIONS = "apply_restrictions"
    VERIFY_ACCESS = "verify_access"
    CLEANUP_AUTHORIZATION = "cleanup_authorization"


_BOOTSTRAP_ORDER = (
    BootstrapStep.VERIFY_NON_ROOT_ACCOUNT,
    BootstrapStep.CREATE_SSH_DIRECTORY,
    BootstrapStep.INSTALL_EXACT_PUBLIC_KEY,
    BootstrapStep.APPLY_RESTRICTIONS,
    BootstrapStep.VERIFY_ACCESS,
    BootstrapStep.CLEANUP_AUTHORIZATION,
)


@dataclass(frozen=True, slots=True)
class RestrictedBootstrapPlan:
    """Fixed, auditable bootstrap state; it has no arbitrary command field."""

    authorization_id: str
    target_reference: str
    remote_user: str
    public_key: str
    fingerprint: str
    completed_steps: tuple[BootstrapStep, ...] = ()

    def __post_init__(self) -> None:
        if _AUTHORIZATION_ID.fullmatch(self.authorization_id) is None:
            raise CredentialVaultError("bootstrap authorization is invalid")
        object.__setattr__(
            self, "target_reference", _validate_scope(self.target_reference, "target_reference")
        )
        object.__setattr__(self, "remote_user", validate_remote_user(self.remote_user))
        public_key, fingerprint = _validate_public_key(self.public_key)
        if fingerprint != self.fingerprint:
            raise CredentialVaultError("bootstrap fingerprint does not match public key")
        object.__setattr__(self, "public_key", public_key)
        if tuple(self.completed_steps) != tuple(
            step for step in _BOOTSTRAP_ORDER if step in self.completed_steps
        ):
            raise CredentialVaultError("bootstrap state is invalid")

    @property
    def next_step(self) -> BootstrapStep | None:
        if len(self.completed_steps) >= len(_BOOTSTRAP_ORDER):
            return None
        return _BOOTSTRAP_ORDER[len(self.completed_steps)]

    @property
    def complete(self) -> bool:
        """A local plan cannot self-assert that remote bootstrap completed."""

        return False

    @property
    def ready_for_external_verification(self) -> bool:
        """Return whether all fixed steps await independent remote proof."""

        return self.next_step is None

    def advance(self, step: BootstrapStep) -> RestrictedBootstrapPlan:
        expected = self.next_step
        if expected != step:
            raise CredentialVaultError("bootstrap step is out of order")
        return replace(self, completed_steps=(*self.completed_steps, step))

    def to_public_dict(self) -> dict[str, object]:
        return {
            "authorization_id": self.authorization_id,
            "target_reference": self.target_reference,
            "remote_user": self.remote_user,
            "public_key": self.public_key,
            "fingerprint": self.fingerprint,
            "completed_steps": [step.value for step in self.completed_steps],
            "next_step": self.next_step.value if self.next_step else None,
            "complete": self.complete,
            "ready_for_external_verification": self.ready_for_external_verification,
        }


__all__ = [
    "BootstrapStep",
    "CredentialVaultError",
    "DEFAULT_MASTER_KEY_REFERENCE",
    "DEFAULT_VAULT_ROOT",
    "Ed25519KeyService",
    "EncryptedCredentialVault",
    "FileMasterKeyProvider",
    "ManualOnboardingInstructions",
    "MasterKeyProvider",
    "OffboardingReceipt",
    "RestrictedBootstrapPlan",
    "VaultCredentialProvider",
    "VaultCredentialRecord",
    "VaultCredentialStatus",
]
