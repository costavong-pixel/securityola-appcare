"""Unit coverage for the canonical AppCare backup filesystem boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from appcare.backups import (
    BACKUP_CONFIG_ROOT,
    BACKUP_LOG_ROOT,
    BACKUP_ROOT,
    BACKUP_TMP_ROOT,
    B2_BACKUP_PREFIX,
    GLACIER_ARCHIVE_PREFIX,
    BackupFilesystemBoundary,
    RestoreTarget,
    validate_read_only_source,
)
from appcare.backups.contracts import BackupBoundaryError


def test_canonical_boundary_constants_are_exact() -> None:
    boundary = BackupFilesystemBoundary.canonical()

    assert boundary.backup_root == BACKUP_ROOT
    assert boundary.log_root == BACKUP_LOG_ROOT
    assert boundary.config_root == BACKUP_CONFIG_ROOT
    assert boundary.tmp_root == BACKUP_TMP_ROOT


def test_required_paths_are_scoped_and_provider_prefixes_are_stable(tmp_path: Path) -> None:
    boundary = BackupFilesystemBoundary.for_test(tmp_path / "boundary")

    snapshot = boundary.snapshot_path("tenant-a", "app-a", "backup-a")
    manifest = boundary.manifest_path("tenant-a", "app-a", "backup-a")
    restore = boundary.restore_rehearsal_path("tenant-a", "app-a", "restore-a")
    job = boundary.job_path("job-a")
    failed = boundary.failed_path("job-a")

    assert snapshot == boundary.backup_root / "snapshots" / "tenant-a" / "app-a" / "backup-a"
    assert manifest == boundary.backup_root / "manifests" / "tenant-a" / "app-a" / "backup-a.json"
    assert restore == boundary.backup_root / "restore-rehearsal" / "tenant-a" / "app-a" / "restore-a"
    assert job == boundary.backup_root / "jobs" / "job-a"
    assert failed == boundary.backup_root / "failed" / "job-a"
    assert boundary.b2_prefix("tenant-a", "app-a", "backup-a") == (
        f"{B2_BACKUP_PREFIX}/tenant-a/app-a/backup-a/"
    )
    assert boundary.glacier_prefix("tenant-a", "app-a", "backup-a") == (
        f"{GLACIER_ARCHIVE_PREFIX}/tenant-a/app-a/backup-a/"
    )


@pytest.mark.parametrize(
    "value",
    ["", ".", "..", "../outside", "/absolute", r"backup\outside", "backup:id", "has space"],
)
def test_user_controlled_path_segments_are_rejected(tmp_path: Path, value: str) -> None:
    boundary = BackupFilesystemBoundary.for_test(tmp_path / "boundary")

    with pytest.raises(BackupBoundaryError):
        boundary.snapshot_path(value, "app-a", "backup-a")
    with pytest.raises(BackupBoundaryError):
        boundary.job_path(value)


def test_tenant_and_application_paths_cannot_cross_each_other(tmp_path: Path) -> None:
    boundary = BackupFilesystemBoundary.for_test(tmp_path / "boundary")

    tenant_a = boundary.snapshot_path("tenant-a", "app-a", "backup-a")
    tenant_b = boundary.snapshot_path("tenant-b", "app-b", "backup-a")

    assert tenant_a != tenant_b
    assert tenant_a.parent.parent != tenant_b.parent.parent


def test_symlink_crossing_is_rejected(tmp_path: Path) -> None:
    boundary = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    boundary.backup_root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = boundary.backup_root / "snapshots"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable in this environment")

    with pytest.raises(BackupBoundaryError):
        boundary.snapshot_path("tenant-a", "app-a", "backup-a")


def test_restore_target_must_use_canonical_rehearsal_path(tmp_path: Path) -> None:
    boundary = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    expected = boundary.restore_rehearsal_path("tenant-a", "app-a", "restore-a")
    target = RestoreTarget(
        "tenant-a",
        "app-a",
        "test",
        expected,
        "restore-a",
        filesystem=boundary,
    )

    assert target.root == expected
    with pytest.raises(BackupBoundaryError):
        RestoreTarget(
            "tenant-a",
            "app-a",
            "test",
            tmp_path / "wrong-root",
            "restore-a",
            filesystem=boundary,
        )


@pytest.mark.parametrize(
    "path",
    [
        Path("/var/www/api.securityola.com"),
        Path("/root"),
        Path("/home/debian/apps/appcare-opencode"),
        Path("/srv/wordpress"),
    ],
)
def test_protected_source_paths_are_rejected(path: Path) -> None:
    with pytest.raises(BackupBoundaryError):
        validate_read_only_source(path)


def test_backup_boundary_cannot_be_created_inside_protected_projects() -> None:
    with pytest.raises(BackupBoundaryError):
        BackupFilesystemBoundary.for_test(Path("/home/debian/apps/appcare-opencode"))
    with pytest.raises(BackupBoundaryError):
        BackupFilesystemBoundary.for_test(Path("/var/www"))
