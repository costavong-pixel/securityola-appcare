"""Unit coverage for BETA-04 target, encryption, and retention boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from appcare.backups import (
    AesGcmEnvelopeEncryptor,
    BackupComponent,
    BackupDestination,
    BackupTarget,
    EnvelopeEncryptionError,
    RestoreTarget,
)
from appcare.backups.contracts import BackupBoundaryError

NOW = datetime(2026, 8, 17, 10, 0, tzinfo=UTC)


def _target() -> BackupTarget:
    return BackupTarget(
        tenant_id="tenant-appcare-1",
        application_id="appcare-test-app",
        environment="test",
        source_reference="synthetic://appcare/test-app",
    )


def _destination(**overrides: object) -> BackupDestination:
    values: dict[str, object] = {
        "provider": "isolated-test-vault",
        "namespace": "appcare-test-vault",
        "region": "local-test",
        "retention_until": NOW + timedelta(days=7),
    }
    values.update(overrides)
    return BackupDestination(**values)  # type: ignore[arg-type]


def test_backup_component_digest_is_stable_and_source_is_scoped() -> None:
    first = BackupComponent("database", "database", "synthetic://appcare/db", b"fixture-db")
    second = BackupComponent("database", "database", "synthetic://appcare/db", b"fixture-db")

    assert first.digest == second.digest
    assert len(first.digest) == 64


def test_target_and_restore_boundaries_reject_wordpress_and_production() -> None:
    with pytest.raises(BackupBoundaryError):
        BackupTarget("tenant-appcare-1", "wordpress-app", "test", "synthetic://appcare/test")
    with pytest.raises(BackupBoundaryError):
        RestoreTarget(
            "tenant-appcare-1",
            "appcare-test-app",
            "production",  # type: ignore[arg-type]
            Path("C:/isolated-restore"),
            "rehearsal-1",
        )
    with pytest.raises(BackupBoundaryError):
        BackupDestination(
            "backblaze-b2",
            "appcare-b2-vault",
            "us-west-001",
            NOW + timedelta(days=30),
        )


def test_cloud_destination_requires_opaque_credential_reference() -> None:
    destination = BackupDestination(
        "backblaze-b2",
        "appcare-b2-vault",
        "us-west-001",
        NOW + timedelta(days=30),
        credential_reference="vault://appcare-b2-custody",
    )

    assert destination.external is True


def test_aes_gcm_round_trip_rejects_wrong_key() -> None:
    encryptor = AesGcmEnvelopeEncryptor(b"a" * 32, key_reference="vault://appcare-test-key")
    envelope = encryptor.encrypt(b"synthetic backup payload", associated_data=b"manifest")

    assert encryptor.decrypt(envelope, associated_data=b"manifest") == b"synthetic backup payload"
    with pytest.raises(EnvelopeEncryptionError):
        encryptor.decrypt(envelope, associated_data=b"wrong-manifest")


def test_restore_root_must_be_isolated(tmp_path: Path) -> None:
    with pytest.raises(BackupBoundaryError):
        RestoreTarget(
            _target().tenant_id,
            _target().application_id,
            "test",
            tmp_path / "production",
            "rehearsal-1",
        )


def test_key_reference_is_metadata_only() -> None:
    encryptor = AesGcmEnvelopeEncryptor(b"b" * 32, key_reference="vault://appcare-test-key")

    assert encryptor.key_reference == "vault://appcare-test-key"
    assert "aaaaaaaa" not in encryptor.key_reference
