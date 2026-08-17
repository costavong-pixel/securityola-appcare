"""Safe test-vault implementations and explicit unavailable cloud boundary."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

from .contracts import (
    BackupBoundaryError,
    BackupDestination,
    BackupTarget,
    utc,
    validate_backup_id,
    validate_isolated_root,
)
from .models import (
    BackupArtifact,
    BackupManifest,
    ComponentDigest,
    EncryptedEnvelope,
    VaultReceipt,
)


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


class InMemoryImmutableVault:
    """Deterministic, non-external vault used only by controlled tests."""

    def __init__(self, destination: BackupDestination) -> None:
        if destination.provider != "isolated-test-vault":
            raise ValueError("in-memory vault is only for the isolated test provider")
        self.destination = destination
        self._artifacts: dict[str, BackupArtifact] = {}
        self._idempotency: dict[str, str] = {}

    def put(self, artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt:
        backup_id = validate_backup_id(artifact.manifest.backup_id)
        existing_id = self._idempotency.get(idempotency_key)
        if existing_id is not None and existing_id != backup_id:
            raise DuplicateArtifactError("idempotency key already belongs to another backup")
        existing = self._artifacts.get(backup_id)
        if existing is not None:
            if existing.artifact_digest != artifact.artifact_digest:
                raise DuplicateArtifactError("backup ID already belongs to another artifact")
            return VaultReceipt(
                backup_id,
                self.destination.provider,
                f"memory://{self.destination.namespace}/{backup_id}",
                existing.artifact_digest,
                existing.manifest.destination.retention_until,
                idempotent=True,
            )
        self._artifacts[backup_id] = artifact
        self._idempotency[idempotency_key] = backup_id
        return VaultReceipt(
            backup_id,
            self.destination.provider,
            f"memory://{self.destination.namespace}/{backup_id}",
            artifact.artifact_digest,
            artifact.manifest.destination.retention_until,
        )

    def get(self, backup_id: str) -> BackupArtifact:
        backup_id = validate_backup_id(backup_id)
        try:
            return self._artifacts[backup_id]
        except KeyError as exc:
            raise VaultError("backup artifact not found") from exc

    def delete(self, backup_id: str, *, now: datetime) -> None:
        backup_id = validate_backup_id(backup_id)
        artifact = self.get(backup_id)
        if _now(now) < _now(artifact.manifest.destination.retention_until):
            raise RetentionLockedError("backup retention is still locked")
        del self._artifacts[backup_id]


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

    def get(self, _backup_id: str) -> BackupArtifact:
        raise VaultUnavailableError(self.failure_code)

    def delete(self, _backup_id: str, *, now: datetime) -> None:
        del now
        raise VaultUnavailableError(self.failure_code)


class FilesystemImmutableVault:
    """Isolated test vault that persists opaque artifact bytes outside the repo.

    This class is intentionally limited to the test provider. It models the
    retention and path boundary without pretending local disk is off-site.
    """

    def __init__(self, root: Path, destination: BackupDestination) -> None:
        if destination.provider != "isolated-test-vault":
            raise ValueError("filesystem vault is only for the isolated test provider")
        self.destination = destination
        try:
            self.root = validate_isolated_root(root, field="filesystem vault root")
        except BackupBoundaryError as exc:
            raise ValueError(str(exc)) from exc
        self.root.mkdir(parents=True, exist_ok=True)
        self._memory = InMemoryImmutableVault(destination)

    def _artifact_dir(self, backup_id: str) -> Path:
        backup_id = validate_backup_id(backup_id)
        path = self.root / backup_id
        if path.is_symlink():
            raise VaultError("backup artifact path is a symlink")
        try:
            resolved = path.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise VaultError("backup artifact path cannot be resolved") from exc
        if resolved.parent != self.root:
            raise VaultError("backup artifact path crossed the vault boundary")
        return path

    def _artifact_file(self, directory: Path, name: str) -> Path:
        path = directory / name
        if path.is_symlink():
            raise VaultError("backup artifact file is a symlink")
        try:
            resolved = path.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise VaultError("backup artifact file cannot be resolved") from exc
        if resolved.parent != directory.resolve(strict=False):
            raise VaultError("backup artifact file crossed the vault boundary")
        return path

    def _read_artifact(self, backup_id: str) -> BackupArtifact:
        directory = self._artifact_dir(backup_id)
        if not directory.is_dir():
            raise VaultError("backup artifact not found")
        try:
            manifest_path = self._artifact_file(directory, "manifest.json")
            envelope_path = self._artifact_file(directory, "envelope.json")
            digest_path = self._artifact_file(directory, "artifact.sha256")
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
        backup_id = validate_backup_id(artifact.manifest.backup_id)
        path = self._artifact_dir(backup_id)
        if path.exists():
            existing = self._read_artifact(backup_id)
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
        receipt = self._memory.put(artifact, idempotency_key=idempotency_key)
        path.mkdir(parents=True, exist_ok=True)
        (path / "manifest.json").write_bytes(artifact.manifest_bytes)
        (path / "envelope.json").write_bytes(artifact.envelope.canonical_bytes())
        (path / "artifact.sha256").write_text(artifact.artifact_digest, encoding="ascii")
        return receipt

    def get(self, backup_id: str) -> BackupArtifact:
        return self._read_artifact(backup_id)

    def delete(self, backup_id: str, *, now: datetime) -> None:
        backup_id = validate_backup_id(backup_id)
        artifact = self._read_artifact(backup_id)
        if _now(now) < _now(artifact.manifest.destination.retention_until):
            raise RetentionLockedError("backup retention is still locked")
        path = self._artifact_dir(backup_id)
        for name in ("manifest.json", "envelope.json", "artifact.sha256"):
            child = self._artifact_file(path, name)
            if child.exists():
                child.unlink()
        try:
            path.rmdir()
        except OSError as exc:
            raise VaultError("backup artifact directory is not empty") from exc
