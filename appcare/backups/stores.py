"""Safe AppCare vault implementations and explicit cloud boundaries."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .contracts import (
    BackupBoundaryError,
    BackupDestination,
    BackupTarget,
    validate_backup_id,
    validate_path_segment,
    utc,
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


def _scope(backup_id: str, tenant_id: str, application_id: str) -> tuple[str, str, str]:
    try:
        return (
            validate_path_segment(tenant_id, field="vault tenant_id"),
            validate_path_segment(application_id, field="vault application_id"),
            validate_backup_id(backup_id),
        )
    except BackupBoundaryError as exc:
        raise VaultError(str(exc)) from exc


def _write_private(path: Path, payload: bytes) -> None:
    """Create one sensitive artifact file without following an existing path."""

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
        self._artifacts: dict[tuple[str, str, str], BackupArtifact] = {}
        self._idempotency: dict[str, tuple[str, str, str]] = {}

    def put(self, artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt:
        scope = _scope(
            artifact.manifest.backup_id,
            artifact.manifest.target.tenant_id,
            artifact.manifest.target.application_id,
        )
        existing_scope = self._idempotency.get(idempotency_key)
        if existing_scope is not None and existing_scope != scope:
            raise DuplicateArtifactError("idempotency key already belongs to another backup")
        existing = self._artifacts.get(scope)
        if existing is not None:
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
    ) -> BackupArtifact:
        scope = _scope(backup_id, tenant_id, application_id)
        try:
            return self._artifacts[scope]
        except KeyError as exc:
            raise VaultError("backup artifact not found in tenant scope") from exc

    def delete(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        now: datetime,
    ) -> None:
        scope = _scope(backup_id, tenant_id, application_id)
        artifact = self.get(
            backup_id,
            tenant_id=tenant_id,
            application_id=application_id,
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
    ) -> BackupArtifact:
        del tenant_id, application_id
        raise VaultUnavailableError(self.failure_code)

    def delete(
        self,
        _backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        now: datetime,
    ) -> None:
        del tenant_id, application_id, now
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
        self.filesystem.ensure_data_dirs()
        self._memory = InMemoryImmutableVault(destination)

    def _artifact_dir(self, backup_id: str, tenant_id: str, application_id: str) -> Path:
        try:
            return self.filesystem.snapshot_path(tenant_id, application_id, backup_id)
        except BackupBoundaryError as exc:
            raise VaultError(str(exc)) from exc

    def _artifact_file(
        self,
        backup_id: str,
        tenant_id: str,
        application_id: str,
        filename: str,
    ) -> Path:
        if filename not in self._SNAPSHOT_FILES:
            raise VaultError("unsupported backup artifact filename")
        try:
            return self.filesystem.snapshot_file(
                tenant_id,
                application_id,
                backup_id,
                filename,
            )
        except BackupBoundaryError as exc:
            raise VaultError(str(exc)) from exc

    def _manifest_path(self, backup_id: str, tenant_id: str, application_id: str) -> Path:
        try:
            return self.filesystem.manifest_path(tenant_id, application_id, backup_id)
        except BackupBoundaryError as exc:
            raise VaultError(str(exc)) from exc

    def _read_artifact(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
    ) -> BackupArtifact:
        scope = _scope(backup_id, tenant_id, application_id)
        backup_id, tenant_id, application_id = scope[2], scope[0], scope[1]
        directory = self._artifact_dir(backup_id, tenant_id, application_id)
        manifest_path = self._manifest_path(backup_id, tenant_id, application_id)
        envelope_path = self._artifact_file(
            backup_id,
            tenant_id,
            application_id,
            "envelope.json",
        )
        digest_path = self._artifact_file(
            backup_id,
            tenant_id,
            application_id,
            "artifact.sha256",
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
            )
            if target.tenant_id != tenant_id or target.application_id != application_id:
                raise VaultError("backup artifact tenant scope mismatch")
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
        backup_id, tenant_id, application_id = _scope(
            artifact.manifest.backup_id,
            artifact.manifest.target.tenant_id,
            artifact.manifest.target.application_id,
        )
        path = self._artifact_dir(backup_id, tenant_id, application_id)
        manifest_path = self._manifest_path(backup_id, tenant_id, application_id)
        if path.exists() or manifest_path.exists():
            existing = self._read_artifact(
                backup_id,
                tenant_id=tenant_id,
                application_id=application_id,
            )
            if existing.artifact_digest != artifact.artifact_digest:
                raise DuplicateArtifactError("backup ID already belongs to another artifact")
            return VaultReceipt(
                backup_id,
                self.destination.provider,
                f"filesystem://{self.destination.namespace}/{backup_id}",
                existing.artifact_digest,
                existing.manifest.destination.retention_until,
                idempotent=True,
            )
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self._artifact_dir(backup_id, tenant_id, application_id)
        manifest_path = self._manifest_path(backup_id, tenant_id, application_id)
        receipt = self._memory.put(artifact, idempotency_key=idempotency_key)
        _write_private(manifest_path, artifact.manifest_bytes)
        _write_private(
            self._artifact_file(backup_id, tenant_id, application_id, "envelope.json"),
            artifact.envelope.canonical_bytes(),
        )
        _write_private(
            self._artifact_file(backup_id, tenant_id, application_id, "artifact.sha256"),
            artifact.artifact_digest.encode("ascii"),
        )
        return receipt

    def get(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
    ) -> BackupArtifact:
        return self._read_artifact(
            backup_id,
            tenant_id=tenant_id,
            application_id=application_id,
        )

    def delete(
        self,
        backup_id: str,
        *,
        tenant_id: str,
        application_id: str,
        now: datetime,
    ) -> None:
        backup_id, tenant_id, application_id = _scope(backup_id, tenant_id, application_id)
        artifact = self._read_artifact(
            backup_id,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        if _now(now) < _now(artifact.manifest.destination.retention_until):
            raise RetentionLockedError("backup retention is still locked")
        path = self._artifact_dir(backup_id, tenant_id, application_id)
        for name in self._SNAPSHOT_FILES:
            child = self._artifact_file(backup_id, tenant_id, application_id, name)
            if child.exists():
                child.unlink()
        manifest_path = self._manifest_path(backup_id, tenant_id, application_id)
        if manifest_path.exists():
            manifest_path.unlink()
        try:
            path.rmdir()
        except OSError as exc:
            raise VaultError("backup artifact directory is not empty") from exc
