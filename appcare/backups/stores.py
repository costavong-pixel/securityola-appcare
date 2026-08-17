"""Safe test-vault implementations and explicit unavailable cloud boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .contracts import BackupDestination, utc
from .models import BackupArtifact, VaultReceipt


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
        backup_id = artifact.manifest.backup_id
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
        try:
            return self._artifacts[backup_id]
        except KeyError as exc:
            raise VaultError("backup artifact not found") from exc

    def delete(self, backup_id: str, *, now: datetime) -> None:
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
        if not root.is_absolute():
            raise ValueError("filesystem vault root must be absolute")
        normalized = str(root).casefold().replace("\\", "/")
        if any(marker in normalized for marker in ("wordpress", "/var/www", "api.securityola.com")):
            raise ValueError("filesystem vault root is outside the AppCare boundary")
        self.destination = destination
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._memory = InMemoryImmutableVault(destination)

    def put(self, artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt:
        receipt = self._memory.put(artifact, idempotency_key=idempotency_key)
        path = self.root / artifact.manifest.backup_id
        path.mkdir(parents=True, exist_ok=True)
        (path / "manifest.json").write_bytes(artifact.manifest_bytes)
        (path / "envelope.json").write_bytes(artifact.envelope.canonical_bytes())
        (path / "artifact.sha256").write_text(artifact.artifact_digest, encoding="ascii")
        return receipt

    def get(self, backup_id: str) -> BackupArtifact:
        return self._memory.get(backup_id)

    def delete(self, backup_id: str, *, now: datetime) -> None:
        self._memory.delete(backup_id, now=now)
        path = self.root / backup_id
        if path.exists():
            for child in path.iterdir():
                child.unlink()
            path.rmdir()
