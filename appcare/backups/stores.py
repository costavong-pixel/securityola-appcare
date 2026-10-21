"""Safe AppCare vault implementations and explicit cloud boundaries."""

from __future__ import annotations

import base64
import json
import os
import stat
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .contracts import (
    BackupBoundaryError,
    BackupDestination,
    BackupTarget,
    _safe_reference,
    utc,
    validate_backup_id,
    validate_path_segment,
)
from .models import (
    BackupArtifact,
    BackupManifest,
    ComponentDigest,
    EncryptedEnvelope,
    VaultReceipt,
)
from .paths import BackupFilesystemBoundary


class VaultError(RuntimeError):
    """A backup vault could not complete a requested operation."""


class RetentionLockedError(VaultError):
    """Deletion was attempted before the immutable retention deadline."""


class DuplicateArtifactError(VaultError):
    """An idempotency key or backup ID already represents another artifact."""


class VaultUnavailableError(VaultError):
    """The external vault is intentionally unavailable or not configured."""


def _now(value: datetime | None) -> datetime:
    return utc(value or datetime.now(UTC))


def _scope(
    backup_id: str,
    tenant_id: str,
    application_id: str,
    target_reference: str | None,
) -> tuple[str, str, str, str | None]:
    try:
        if target_reference is not None:
            _safe_reference(target_reference, field="vault target_reference")
        return (
            validate_path_segment(tenant_id, field="vault tenant_id"),
            validate_path_segment(application_id, field="vault application_id"),
            validate_backup_id(backup_id),
            target_reference,
        )
    except BackupBoundaryError as exc:
        raise VaultError(str(exc)) from exc


@contextmanager
def _directory_descriptor(
    root: int, parts: tuple[str, ...], *, create: bool = False, ancestry: bool = False
) -> Iterator[int]:
    """Walk from an already trusted descriptor, never resolving a symlink."""
    descriptor = os.dup(root)
    try:
        root_info = os.fstat(descriptor)
        if not ancestry and (root_info.st_uid != os.geteuid() or root_info.st_mode & 0o077):
            raise VaultError("vault root requires private owner permissions")
        for part in parts:
            if part in {"", ".", ".."} or "/" in part:
                raise VaultError("invalid vault directory segment")
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if ancestry:
                # Root-owned sticky temporary ancestors are safe for private test roots.
                trusted = info.st_uid in {0, os.geteuid()}
                writable = info.st_mode & 0o022
                sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                if not trusted or (writable and not sticky):
                    raise VaultError("untrusted vault ancestry")
            elif info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise VaultError("vault directories require private owner permissions")
        yield descriptor
    except OSError as exc:
        raise VaultError("unsafe or unavailable vault directory") from exc
    finally:
        os.close(descriptor)


class _DescriptorPath:
    """Small internal path interface whose IO is relative to the pinned vault root."""

    def __init__(self, root: int, parts: tuple[str, ...]) -> None:
        self.root = root
        self.parts = parts

    @property
    def parent(self) -> _DescriptorPath:
        return _DescriptorPath(self.root, self.parts[:-1])

    def mkdir(self, *, parents: bool, exist_ok: bool, mode: int) -> None:
        del parents, exist_ok, mode
        with _directory_descriptor(self.root, self.parts, create=True):
            pass

    def _stat(self) -> os.stat_result | None:
        with _directory_descriptor(self.root, self.parts[:-1]) as parent:
            try:
                info = os.stat(self.parts[-1], dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return None
            if stat.S_ISLNK(info.st_mode):
                raise VaultError("vault entry is a symlink")
            return info

    def exists(self) -> bool:
        # Missing parents also mean absence; unsafe parents must still fail closed.
        try:
            return self._stat() is not None
        except VaultError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                return False
            raise

    def is_dir(self) -> bool:
        info = self._stat()
        return info is not None and stat.S_ISDIR(info.st_mode)

    def is_file(self) -> bool:
        info = self._stat()
        return info is not None and stat.S_ISREG(info.st_mode)

    def read_bytes(self) -> bytes:
        with _directory_descriptor(self.root, self.parts[:-1]) as parent:
            descriptor = os.open(
                self.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_nlink != 1
                ):
                    raise VaultError("unsafe vault artifact file")
                return stream.read()

    def read_text(self, *, encoding: str) -> str:
        return self.read_bytes().decode(encoding)

    def write_private(self, payload: bytes) -> None:
        with _directory_descriptor(self.root, self.parts[:-1]) as parent:
            descriptor = os.open(
                self.parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)

    def unlink(self) -> None:
        with _directory_descriptor(self.root, self.parts[:-1]) as parent:
            os.unlink(self.parts[-1], dir_fd=parent)

    def rmdir(self) -> None:
        with _directory_descriptor(self.root, self.parts[:-1]) as parent:
            os.rmdir(self.parts[-1], dir_fd=parent)


def _write_private(path: Path | _DescriptorPath, payload: bytes) -> None:
    """Create one sensitive artifact file without following an existing path."""

    if isinstance(path, _DescriptorPath):
        try:
            path.write_private(payload)
        except OSError as exc:
            raise VaultError("backup artifact file cannot be created") from exc
        return
    file_path = os.fspath(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(file_path, flags, 0o600)
    except FileExistsError as exc:
        raise VaultError("backup artifact file already exists") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


class InMemoryImmutableVault:
    """Deterministic, non-external vault used only by controlled tests."""

    def __init__(self, destination: BackupDestination) -> None:
        if destination.provider != "isolated-test-vault":
            raise ValueError("in-memory vault is only for the isolated test provider")
        self.destination = destination
        self._artifacts: dict[tuple[str, str, str, str | None], BackupArtifact] = {}
        self._idempotency: dict[str, tuple[str, str, str, str | None]] = {}

    def put(self, artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt:
        scope = _scope(
            artifact.manifest.backup_id,
            artifact.manifest.target.tenant_id,
            artifact.manifest.target.application_id,
            artifact.manifest.target.target_reference,
        )
        existing_scope = self._idempotency.get(idempotency_key)
        if existing_scope is not None and existing_scope != scope:
            raise DuplicateArtifactError("idempotency key already belongs to another backup")
        existing = self._artifacts.get(scope)
        if existing is not None:
            if (
                existing.manifest.target.target_reference
                != artifact.manifest.target.target_reference
            ):
                raise DuplicateArtifactError("backup ID already belongs to another target")
            if existing.artifact_digest != artifact.artifact_digest:
                raise DuplicateArtifactError("backup ID already belongs to another artifact")
            return VaultReceipt(
                artifact.manifest.backup_id,
                self.destination.provider,
                f"memory://{self.destination.namespace}/{artifact.manifest.backup_id}",
                existing.artifact_digest,
                existing.manifest.destination.retention_until,
                idempotent=True,
            )
        self._artifacts[scope] = artifact
        self._idempotency[idempotency_key] = scope
        return VaultReceipt(
            artifact.manifest.backup_id,
            self.destination.provider,
            f"memory://{self.destination.namespace}/{artifact.manifest.backup_id}",
            artifact.artifact_digest,
            artifact.manifest.destination.retention_until,
        )

    def get(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str | None,
    ) -> BackupArtifact:
        scope = _scope(backup_id, tenant_id, application_id, target_reference)
        try:
            artifact = self._artifacts[scope]
        except KeyError as exc:
            raise VaultError("backup artifact not found in tenant scope") from exc
        if artifact.manifest.target.target_reference != target_reference:
            raise VaultError("backup artifact target scope mismatch")
        return artifact

    def delete(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str | None,
        now: datetime,
    ) -> None:
        scope = _scope(backup_id, tenant_id, application_id, target_reference)
        artifact = self.get(
            backup_id,
            tenant_id=tenant_id,
            application_id=application_id,
            target_reference=target_reference,
        )
        if _now(now) < _now(artifact.manifest.destination.retention_until):
            raise RetentionLockedError("backup retention is still locked")
        del self._artifacts[scope]


class UnavailableCloudVault:
    """Fail-closed placeholder for B2/Glacier until credentials are authorized."""

    def __init__(self, destination: BackupDestination, *, failure_code: str) -> None:
        if not destination.external:
            raise ValueError("unavailable cloud vault requires an external destination")
        if failure_code not in {
            "credentials_missing",
            "credentials_revoked",
            "provider_unavailable",
        }:
            raise ValueError("unsupported cloud vault failure code")
        self.destination = destination
        self.failure_code = failure_code

    def put(self, _artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt:
        del idempotency_key
        raise VaultUnavailableError(self.failure_code)

    def get(
        self,
        _backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str | None,
    ) -> BackupArtifact:
        del tenant_id, application_id, target_reference
        raise VaultUnavailableError(self.failure_code)

    def delete(
        self,
        _backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str | None,
        now: datetime,
    ) -> None:
        del tenant_id, application_id, target_reference, now
        raise VaultUnavailableError(self.failure_code)


class FilesystemImmutableVault:
    """Immutable test-vault persistence inside an explicit AppCare boundary.

    This class is intentionally limited to the isolated test provider. It
    models local retention and tenant paths without claiming local disk is
    authoritative off-site storage.
    """

    _SNAPSHOT_FILES = frozenset({"envelope.json", "artifact.sha256"})

    def __init__(
        self,
        filesystem: BackupFilesystemBoundary,
        destination: BackupDestination,
    ) -> None:
        if destination.provider != "isolated-test-vault":
            raise ValueError("filesystem vault is only for the isolated test provider")
        self.destination = destination
        self.filesystem = filesystem
        self._root_descriptor: int | None = None
        if os.name == "posix":
            anchor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with _directory_descriptor(
                    anchor, filesystem.backup_root.parts[1:], create=True, ancestry=True
                ) as root:
                    info = os.fstat(root)
                    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                        raise VaultError("vault root requires private owner permissions")
                    self._root_descriptor = os.dup(root)
            finally:
                os.close(anchor)
            weakref.finalize(self, os.close, self._root_descriptor)
            for name in (
                "staging",
                "snapshots",
                "manifests",
                "restore-rehearsal",
                "jobs",
                "failed",
            ):
                with _directory_descriptor(self._root_descriptor, (name,), create=True):
                    pass
        else:
            self.filesystem.ensure_data_dirs()
        self._memory = InMemoryImmutableVault(destination)

    def _vault_path(self, path: Path) -> Path | _DescriptorPath:
        if self._root_descriptor is None:
            return path
        return _DescriptorPath(
            self._root_descriptor, path.relative_to(self.filesystem.backup_root).parts
        )

    @staticmethod
    def _require_target_reference(target_reference: str | None) -> str:
        if target_reference is None:
            raise VaultError("filesystem vault requires target_reference")
        return target_reference

    def _artifact_dir(
        self,
        backup_id: str,
        tenant_id: str,
        application_id: str,
        target_reference: str,
    ) -> Path | _DescriptorPath:
        try:
            return self._vault_path(
                self.filesystem.snapshot_path(
                    tenant_id,
                    application_id,
                    backup_id,
                    target_reference=target_reference,
                )
            )
        except BackupBoundaryError as exc:
            raise VaultError(str(exc)) from exc

    def _artifact_file(
        self,
        backup_id: str,
        tenant_id: str,
        application_id: str,
        filename: str,
        target_reference: str,
    ) -> Path | _DescriptorPath:
        if filename not in self._SNAPSHOT_FILES:
            raise VaultError("unsupported backup artifact filename")
        try:
            return self._vault_path(
                self.filesystem.snapshot_file(
                    tenant_id,
                    application_id,
                    backup_id,
                    filename,
                    target_reference=target_reference,
                )
            )
        except BackupBoundaryError as exc:
            raise VaultError(str(exc)) from exc

    def _manifest_path(
        self,
        backup_id: str,
        tenant_id: str,
        application_id: str,
        target_reference: str,
    ) -> Path | _DescriptorPath:
        try:
            return self._vault_path(
                self.filesystem.manifest_path(
                    tenant_id,
                    application_id,
                    backup_id,
                    target_reference=target_reference,
                )
            )
        except BackupBoundaryError as exc:
            raise VaultError(str(exc)) from exc

    def _read_artifact(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str | None,
    ) -> BackupArtifact:
        required_target_reference = self._require_target_reference(target_reference)
        scope = _scope(backup_id, tenant_id, application_id, required_target_reference)
        backup_id, tenant_id, application_id = scope[2], scope[0], scope[1]
        target_reference = self._require_target_reference(scope[3])
        directory = self._artifact_dir(backup_id, tenant_id, application_id, target_reference)
        manifest_path = self._manifest_path(backup_id, tenant_id, application_id, target_reference)
        envelope_path = self._artifact_file(
            backup_id,
            tenant_id,
            application_id,
            "envelope.json",
            target_reference,
        )
        digest_path = self._artifact_file(
            backup_id,
            tenant_id,
            application_id,
            "artifact.sha256",
            target_reference,
        )
        if not directory.is_dir() or not manifest_path.is_file():
            raise VaultError("backup artifact not found")
        try:
            manifest_bytes = manifest_path.read_bytes()
            manifest_data = json.loads(manifest_bytes.decode("utf-8"))
            target_data = manifest_data["target"]
            destination_data = manifest_data["destination"]
            target = BackupTarget(
                target_data["tenant_id"],
                target_data["application_id"],
                target_data["environment"],
                target_data["source_reference"],
                target_data.get("target_reference"),
            )
            if target.tenant_id != tenant_id or target.application_id != application_id:
                raise VaultError("backup artifact tenant scope mismatch")
            if target.target_reference != target_reference:
                raise VaultError("backup artifact target scope mismatch")
            destination = BackupDestination(
                destination_data["provider"],
                destination_data["namespace"],
                destination_data["region"],
                datetime.fromisoformat(destination_data["retention_until"]),
                destination_data["immutable"],
                destination_data.get("credential_reference"),
            )
            components = tuple(
                ComponentDigest(
                    component["name"],
                    component["kind"],
                    component["source_reference"],
                    component["size_bytes"],
                    component["sha256"],
                )
                for component in manifest_data["components"]
            )
            manifest = BackupManifest(
                manifest_data["backup_id"],
                target,
                destination,
                components,
                manifest_data["key_reference"],
                manifest_data["encryption_algorithm"],
                datetime.fromisoformat(manifest_data["created_at"]),
                datetime.fromisoformat(manifest_data["source_captured_at"]),
                manifest_data["rpo_target_seconds"],
                manifest_data["rto_target_seconds"],
            )
            envelope_data = json.loads(envelope_path.read_text(encoding="utf-8"))
            envelope = EncryptedEnvelope(
                envelope_data["algorithm"],
                envelope_data["key_reference"],
                base64.b64decode(envelope_data["nonce"], validate=True),
                base64.b64decode(envelope_data["ciphertext"], validate=True),
            )
            artifact_digest = digest_path.read_text(encoding="ascii").strip()
            return BackupArtifact(manifest, manifest_bytes, envelope, artifact_digest)
        except VaultError:
            raise
        except (
            AttributeError,
            BackupBoundaryError,
            KeyError,
            TypeError,
            ValueError,
            OSError,
        ) as exc:
            raise VaultError("persisted backup artifact is malformed") from exc

    def put(self, artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt:
        tenant_id, application_id, backup_id, target_reference = _scope(
            artifact.manifest.backup_id,
            artifact.manifest.target.tenant_id,
            artifact.manifest.target.application_id,
            artifact.manifest.target.target_reference,
        )
        target_reference = self._require_target_reference(target_reference)
        path = self._artifact_dir(backup_id, tenant_id, application_id, target_reference)
        manifest_path = self._manifest_path(backup_id, tenant_id, application_id, target_reference)
        if path.exists() or manifest_path.exists():
            existing = self._read_artifact(
                backup_id,
                tenant_id=tenant_id,
                application_id=application_id,
                target_reference=target_reference,
            )
            if existing.artifact_digest != artifact.artifact_digest:
                raise DuplicateArtifactError("backup ID already belongs to another artifact")
            return VaultReceipt(
                backup_id,
                self.destination.provider,
                f"filesystem://{self.destination.namespace}/{tenant_id}/"
                f"{application_id}/{target_reference}/{backup_id}",
                existing.artifact_digest,
                existing.manifest.destination.retention_until,
                idempotent=True,
            )
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self._artifact_dir(backup_id, tenant_id, application_id, target_reference)
        manifest_path = self._manifest_path(backup_id, tenant_id, application_id, target_reference)
        receipt = self._memory.put(artifact, idempotency_key=idempotency_key)
        _write_private(manifest_path, artifact.manifest_bytes)
        _write_private(
            self._artifact_file(
                backup_id,
                tenant_id,
                application_id,
                "envelope.json",
                target_reference,
            ),
            artifact.envelope.canonical_bytes(),
        )
        _write_private(
            self._artifact_file(
                backup_id,
                tenant_id,
                application_id,
                "artifact.sha256",
                target_reference,
            ),
            artifact.artifact_digest.encode("ascii"),
        )
        return receipt

    def get(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str | None,
    ) -> BackupArtifact:
        return self._read_artifact(
            backup_id,
            tenant_id=tenant_id,
            application_id=application_id,
            target_reference=target_reference,
        )

    def delete(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str | None,
        now: datetime,
    ) -> None:
        tenant_id, application_id, backup_id, target_reference = _scope(
            backup_id, tenant_id, application_id, target_reference
        )
        target_reference = self._require_target_reference(target_reference)
        artifact = self._read_artifact(
            backup_id,
            tenant_id=tenant_id,
            application_id=application_id,
            target_reference=target_reference,
        )
        if _now(now) < _now(artifact.manifest.destination.retention_until):
            raise RetentionLockedError("backup retention is still locked")
        path = self._artifact_dir(backup_id, tenant_id, application_id, target_reference)
        for name in self._SNAPSHOT_FILES:
            child = self._artifact_file(
                backup_id,
                tenant_id,
                application_id,
                name,
                target_reference,
            )
            if child.exists():
                child.unlink()
        manifest_path = self._manifest_path(backup_id, tenant_id, application_id, target_reference)
        if manifest_path.exists():
            manifest_path.unlink()
        try:
            path.rmdir()
        except OSError as exc:
            raise VaultError("backup artifact directory is not empty") from exc
