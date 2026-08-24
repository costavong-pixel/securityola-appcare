"""Controlled synthetic AppCare backup, restore, and failure rehearsals."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from appcare.backups import (
    AesGcmEnvelopeEncryptor,
    BackupComponent,
    BackupCoordinator,
    BackupDestination,
    BackupRequest,
    BackupTarget,
    BackupFilesystemBoundary,
    FilesystemImmutableVault,
    InMemoryImmutableVault,
    RestoreTarget,
    UnavailableCloudVault,
)
from appcare.backups.models import BackupArtifact, EncryptedEnvelope, VaultReceipt
from appcare.backups.stores import RetentionLockedError, VaultError

NOW = datetime(2026, 8, 17, 10, 0, tzinfo=UTC)


class SyntheticAppSource:
    def __init__(self, *, large_database: bool = False) -> None:
        database = b"synthetic database fixture\n" * (40_000 if large_database else 2)
        self.components = (
            BackupComponent("config", "config", "synthetic://appcare/config", b"mode=test"),
            BackupComponent("database", "database", "synthetic://appcare/database", database),
            BackupComponent("git", "source", "synthetic://appcare/git", b"revision=fixture"),
            BackupComponent("storage", "storage", "synthetic://appcare/storage", b"asset=fixture"),
        )
        self.calls = 0

    def snapshot(self, target: BackupTarget) -> tuple[BackupComponent, ...]:
        assert target.application_id == "appcare-test-app"
        self.calls += 1
        return self.components


def _target() -> BackupTarget:
    return BackupTarget(
        "tenant-appcare-1", "appcare-test-app", "test", "synthetic://appcare/test-app"
    )


def _destination(retention_until: datetime | None = None) -> BackupDestination:
    return BackupDestination(
        "isolated-test-vault",
        "appcare-test-vault",
        "local-test",
        retention_until or NOW + timedelta(days=7),
    )


def _request(
    *,
    backup_id: str = "backup-beta04-1",
    idempotency_key: str = "job-beta04-1",
    destination: BackupDestination | None = None,
) -> BackupRequest:
    return BackupRequest(
        _target(),
        destination or _destination(),
        backup_id,
        idempotency_key,
        NOW - timedelta(hours=1),
    )


def _encryptor() -> AesGcmEnvelopeEncryptor:
    return AesGcmEnvelopeEncryptor(b"c" * 32, key_reference="vault://appcare-test-key")


def _restore_target(
    tmp_path: Path, isolation_id: str
) -> tuple[RestoreTarget, BackupFilesystemBoundary]:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / f"boundary-{isolation_id}")
    root = filesystem.restore_rehearsal_path(
        "tenant-appcare-1",
        "appcare-test-app",
        isolation_id,
    )
    return (
        RestoreTarget(
            "tenant-appcare-1",
            "appcare-test-app",
            "test",
            root,
            isolation_id,
            filesystem=filesystem,
        ),
        filesystem,
    )


def test_complete_controlled_test_app_backup_and_isolated_restore(tmp_path: Path) -> None:
    source = SyntheticAppSource()
    destination = _destination()
    vault = InMemoryImmutableVault(destination)
    coordinator = BackupCoordinator()
    outcome = coordinator.create_backup(
        _request(destination=destination),
        source=source,
        vault=vault,
        encryptor=_encryptor(),
        now=NOW,
    )

    assert outcome.healthy is True
    assert outcome.status == "verified"
    assert outcome.evidence is not None
    assert outcome.evidence.controlled_test_only is True
    assert outcome.receipt is not None
    assert outcome.receipt.object_reference.startswith("memory://")

    restore_target, _ = _restore_target(tmp_path, "rehearsal-1")
    restore_root = restore_target.root
    evidence = coordinator.restore_backup(
        backup_id="backup-beta04-1",
        vault=vault,
        encryptor=_encryptor(),
        target=restore_target,
        now=NOW + timedelta(minutes=2),
    )

    assert evidence.status == "restore_verified"
    assert set(evidence.restored_component_names) == {"config", "database", "git", "storage"}
    assert evidence.rpo_observed_seconds == 3_720
    assert evidence.rto_observed_seconds is not None
    assert (
        restore_root / "restored" / "backup-beta04-1" / "components" / "database.bin"
    ).read_bytes() == source.components[1].payload
    assert not (restore_root / "restore-staging" / "backup-beta04-1").exists()


def test_failed_upload_is_unhealthy_and_not_a_verified_backup() -> None:
    class InterruptedVault(InMemoryImmutableVault):
        def put(self, artifact: BackupArtifact, *, idempotency_key: str) -> VaultReceipt:
            del artifact, idempotency_key
            raise TimeoutError("synthetic interruption")

    destination = _destination()
    outcome = BackupCoordinator().create_backup(
        _request(destination=destination),
        source=SyntheticAppSource(),
        vault=InterruptedVault(destination),
        encryptor=_encryptor(),
        now=NOW,
    )

    assert outcome.healthy is False
    assert outcome.status == "failed"
    assert outcome.failure_code == "upload_interrupted"


def test_revoked_cloud_credentials_are_explicitly_unhealthy() -> None:
    destination = BackupDestination(
        "backblaze-b2",
        "appcare-b2-vault",
        "us-west-001",
        NOW + timedelta(days=30),
        credential_reference="vault://appcare-b2-custody",
    )
    outcome = BackupCoordinator().create_backup(
        _request(destination=destination),
        source=SyntheticAppSource(),
        vault=UnavailableCloudVault(destination, failure_code="credentials_revoked"),
        encryptor=_encryptor(),
        now=NOW,
    )

    assert outcome.healthy is False
    assert outcome.failure_code == "credentials_revoked"


def test_duplicate_job_does_not_run_source_twice() -> None:
    source = SyntheticAppSource()
    destination = _destination()
    coordinator = BackupCoordinator()
    first = coordinator.create_backup(
        _request(destination=destination),
        source=source,
        vault=InMemoryImmutableVault(destination),
        encryptor=_encryptor(),
        now=NOW,
    )
    second = coordinator.create_backup(
        _request(destination=destination),
        source=source,
        vault=InMemoryImmutableVault(destination),
        encryptor=_encryptor(),
        now=NOW,
    )

    assert first.healthy is True
    assert second.healthy is False
    assert second.failure_code == "duplicate_job"
    assert source.calls == 1


def test_large_database_component_is_verified() -> None:
    source = SyntheticAppSource(large_database=True)
    destination = _destination()
    outcome = BackupCoordinator().create_backup(
        _request(destination=destination),
        source=source,
        vault=InMemoryImmutableVault(destination),
        encryptor=_encryptor(),
        now=NOW,
    )

    assert outcome.healthy is True
    assert outcome.evidence is not None
    assert "database" in outcome.evidence.component_names


def test_retention_lock_rejects_delete_until_expiry() -> None:
    destination = _destination(NOW + timedelta(days=1))
    vault = InMemoryImmutableVault(destination)
    outcome = BackupCoordinator().create_backup(
        _request(destination=destination),
        source=SyntheticAppSource(),
        vault=vault,
        encryptor=_encryptor(),
        now=NOW,
    )
    assert outcome.healthy is True

    with pytest.raises(RetentionLockedError):
        vault.delete(
            "backup-beta04-1",
            tenant_id="tenant-appcare-1",
            application_id="appcare-test-app",
            now=NOW + timedelta(hours=1),
        )
    vault.delete(
        "backup-beta04-1",
        tenant_id="tenant-appcare-1",
        application_id="appcare-test-app",
        now=NOW + timedelta(days=2),
    )
    with pytest.raises(VaultError):
        vault.get(
            "backup-beta04-1",
            tenant_id="tenant-appcare-1",
            application_id="appcare-test-app",
        )


def test_restore_integrity_failure_never_promotes_partial_content(tmp_path: Path) -> None:
    destination = _destination()
    vault = InMemoryImmutableVault(destination)
    coordinator = BackupCoordinator()
    outcome = coordinator.create_backup(
        _request(destination=destination),
        source=SyntheticAppSource(),
        vault=vault,
        encryptor=_encryptor(),
        now=NOW,
    )
    assert outcome.healthy is True
    original = vault.get(
        "backup-beta04-1",
        tenant_id="tenant-appcare-1",
        application_id="appcare-test-app",
    )
    corrupted = EncryptedEnvelope(
        original.envelope.algorithm,
        original.envelope.key_reference,
        original.envelope.nonce,
        bytes([original.envelope.ciphertext[0] ^ 1]) + original.envelope.ciphertext[1:],
    )
    vault._artifacts[("tenant-appcare-1", "appcare-test-app", "backup-beta04-1")] = BackupArtifact(
        original.manifest,
        original.manifest_bytes,
        corrupted,
        original.artifact_digest,
    )

    restore_target, _ = _restore_target(tmp_path, "rehearsal-2")
    evidence = coordinator.restore_backup(
        backup_id="backup-beta04-1",
        vault=vault,
        encryptor=_encryptor(),
        target=restore_target,
        now=NOW + timedelta(minutes=2),
    )

    assert evidence.status == "restore_failed"
    assert evidence.failure_code == "checksum_mismatch"
    assert not (restore_target.root / "restored" / "backup-beta04-1").exists()


def test_restore_rejects_path_traversal_before_vault_access(tmp_path: Path) -> None:
    destination = _destination()
    vault = InMemoryImmutableVault(destination)
    restore_target, _ = _restore_target(tmp_path, "rehearsal-path")
    evidence = BackupCoordinator().restore_backup(
        backup_id="../outside",
        vault=vault,
        encryptor=_encryptor(),
        target=restore_target,
        now=NOW,
    )

    assert evidence.status == "restore_failed"
    assert evidence.failure_code == "boundary_error"
    assert not (tmp_path / "outside").exists()


def test_filesystem_vault_reads_persisted_artifact_after_reopen(tmp_path: Path) -> None:
    destination = _destination()
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "filesystem-boundary")
    first_vault = FilesystemImmutableVault(filesystem, destination)
    outcome = BackupCoordinator().create_backup(
        _request(destination=destination),
        source=SyntheticAppSource(),
        vault=first_vault,
        encryptor=_encryptor(),
        now=NOW,
    )
    assert outcome.healthy is True
    assert outcome.evidence is not None

    reopened_vault = FilesystemImmutableVault(filesystem, destination)
    restored = reopened_vault.get(
        "backup-beta04-1",
        tenant_id="tenant-appcare-1",
        application_id="appcare-test-app",
    )
    assert filesystem.snapshot_path(
        "tenant-appcare-1", "appcare-test-app", "backup-beta04-1"
    ).is_dir()
    assert filesystem.manifest_path(
        "tenant-appcare-1", "appcare-test-app", "backup-beta04-1"
    ).is_file()
    assert restored.artifact_digest == outcome.evidence.artifact_digest
    assert restored.manifest_bytes == restored.manifest.canonical_bytes()


def test_filesystem_vault_rejects_foreign_tenant_scope(tmp_path: Path) -> None:
    destination = _destination()
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "tenant-boundary")
    vault = FilesystemImmutableVault(filesystem, destination)
    outcome = BackupCoordinator().create_backup(
        _request(destination=destination),
        source=SyntheticAppSource(),
        vault=vault,
        encryptor=_encryptor(),
        now=NOW,
    )
    assert outcome.healthy is True

    with pytest.raises(VaultError):
        vault.get(
            "backup-beta04-1",
            tenant_id="tenant-foreign",
            application_id="appcare-test-app",
        )
    with pytest.raises(VaultError):
        vault.get(
            "backup-beta04-1",
            tenant_id="tenant-appcare-1",
            application_id="foreign-app",
        )


def test_restore_does_not_delete_preexisting_staging_on_mkdir_failure(tmp_path: Path) -> None:
    destination = _destination()
    vault = InMemoryImmutableVault(destination)
    coordinator = BackupCoordinator()
    outcome = coordinator.create_backup(
        _request(destination=destination),
        source=SyntheticAppSource(),
        vault=vault,
        encryptor=_encryptor(),
        now=NOW,
    )
    assert outcome.healthy is True
    restore_target, _ = _restore_target(tmp_path, "rehearsal-existing")
    restore_root = restore_target.root
    staging = restore_root / "restore-staging" / "backup-beta04-1"
    staging.mkdir(parents=True)
    marker = staging / "must-survive.txt"
    marker.write_text("pre-existing", encoding="utf-8")

    evidence = coordinator.restore_backup(
        backup_id="backup-beta04-1",
        vault=vault,
        encryptor=_encryptor(),
        target=restore_target,
        now=NOW,
    )

    assert evidence.status == "restore_failed"
    assert marker.read_text(encoding="utf-8") == "pre-existing"
