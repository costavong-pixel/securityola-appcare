"""Adversarial coverage for the bounded Linux filesystem backup source."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from appcare.backups import (
    BackupTarget,
    FilesystemEntryClass,
    FilesystemEntryType,
    FilesystemSourceError,
    FilesystemSourceLimits,
    LinuxFilesystemBackupSource,
)
from appcare.revision import (
    BaselineEntry,
    BaselinePolicy,
    CapturedApplicationRevision,
    FilesystemBaseline,
    FilesystemBaselineCapturer,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux/POSIX source is required")


def _target(root: Path) -> BackupTarget:
    return BackupTarget(
        tenant_id="tenant-appcare-1",
        application_id="appcare-test-app",
        environment="test",
        source_reference=root.as_posix(),
        target_reference="target-appcare-test",
    )


def _revision(root: Path) -> CapturedApplicationRevision:
    baseline = FilesystemBaselineCapturer().capture(root)
    return CapturedApplicationRevision.from_filesystem_baseline(
        baseline,
        tenant_id="tenant-appcare-1",
        application_id="appcare-test-app",
        target_reference="target-appcare-test",
        host_identity="slab-prompt-ola",
        captured_at=datetime(2026, 9, 3, 12, 0, tzinfo=UTC),
    )


def _source(
    root: Path, *, limits: FilesystemSourceLimits | None = None
) -> LinuxFilesystemBackupSource:
    return LinuxFilesystemBackupSource.for_fixture(_revision(root), limits=limits)


def _hardlink_revision(root: Path) -> CapturedApplicationRevision:
    entries: list[BaselineEntry] = []
    root_metadata = root.stat()
    entries.append(
        BaselineEntry(
            ".",
            "directory",
            root_metadata.st_size,
            root_metadata.st_mode & 0o7777,
            getattr(root_metadata, "st_uid", 0),
            getattr(root_metadata, "st_gid", 0),
        )
    )
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        metadata = path.stat()
        payload = path.read_bytes()
        entries.append(
            BaselineEntry(
                path.name,
                "file",
                metadata.st_size,
                metadata.st_mode & 0o7777,
                getattr(metadata, "st_uid", 0),
                getattr(metadata, "st_gid", 0),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    baseline = FilesystemBaseline(
        root=root.as_posix(),
        entries=tuple(entries),
        policy=BaselinePolicy(),
        root_identity=(root_metadata.st_dev, root_metadata.st_ino),
    )
    return CapturedApplicationRevision.from_filesystem_baseline(
        baseline,
        tenant_id="tenant-appcare-1",
        application_id="appcare-test-app",
        target_reference="target-appcare-test",
        host_identity="slab-prompt-ola",
        captured_at=datetime(2026, 9, 3, 12, 0, tzinfo=UTC),
    )


def test_capture_is_deterministic_and_excludes_secret_contents(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    (root / "index.php").write_text("<?php echo 'safe';", encoding="utf-8")
    (root / ".env").write_text("DATABASE_PASSWORD=not-evidence", encoding="utf-8")
    (root / "assets").mkdir()
    (root / "assets" / "logo.txt").write_text("fixture", encoding="utf-8")
    source = _source(root)

    first = source.capture(_target(root))
    second = source.capture(_target(root))

    assert first.manifest_digest == second.manifest_digest
    assert first.entries == second.entries
    secret = next(item for item in first.entries if item.relative_path == ".env")
    assert secret.classification is FilesystemEntryClass.SECRET_EXCLUDED
    assert secret.sha256 is None
    safe = next(item for item in first.entries if item.relative_path == "index.php")
    assert safe.classification is FilesystemEntryClass.SAFE_FILE
    assert safe.sha256 is not None
    directory = next(item for item in first.entries if item.relative_path == "assets")
    assert directory.classification is FilesystemEntryClass.SAFE_DIRECTORY
    assert "DATABASE_PASSWORD" not in str(first)


def test_streaming_file_chunks_are_bounded_and_identity_bound(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    payload = b"0123456789" * 100
    (root / "large.bin").write_bytes(payload)
    source = _source(root, limits=FilesystemSourceLimits(chunk_bytes=17, max_file_bytes=2_000))
    entry = next(
        item for item in source.iter_entries(_target(root)) if item.relative_path == "large.bin"
    )

    chunks = tuple(source.iter_file_chunks(_target(root), entry))

    assert b"".join(chunks) == payload
    assert all(len(chunk) <= 17 for chunk in chunks)
    assert source.read_file(_target(root), entry) == payload


def test_unsafe_entry_types_are_classified_without_following(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    (root / "safe.txt").write_text("safe", encoding="utf-8")
    (root / "safe-target").mkdir()
    link = root / "escape"
    try:
        link.symlink_to(root / "safe-target", target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    entries = tuple(_source(root).iter_entries(_target(root)))

    escaped = next(item for item in entries if item.relative_path == "escape")
    assert escaped.entry_type is FilesystemEntryType.SYMLINK
    assert escaped.classification is FilesystemEntryClass.SYMLINK_DENIED


def test_hardlinks_and_oversized_files_are_not_read(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    original = root / "original.txt"
    original.write_text("content", encoding="utf-8")
    hardlink_created = True
    try:
        os.link(original, root / "linked.txt")
    except OSError:
        hardlink_created = False
    (root / "too-large.txt").write_text("12345", encoding="utf-8")
    source = LinuxFilesystemBackupSource.for_fixture(
        _hardlink_revision(root),
        limits=FilesystemSourceLimits(max_file_bytes=4, max_total_bytes=100),
    )
    entries = tuple(source.iter_entries(_target(root)))

    oversized = next(item for item in entries if item.relative_path == "too-large.txt")
    assert oversized.classification is FilesystemEntryClass.OVERSIZED_DENIED
    if hardlink_created and os.name == "posix":
        linked = next(item for item in entries if item.relative_path == "linked.txt")
        assert linked.classification is FilesystemEntryClass.HARDLINK_DENIED


def test_snapshot_requires_at_least_one_safe_file_and_binds_target(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    (root / "safe.txt").write_text("safe", encoding="utf-8")
    source = _source(root)

    components = source.snapshot(_target(root))

    assert components[0].kind == "filesystem-file"
    assert components[0].source_reference.startswith(
        "filesystem://tenant-appcare-1/appcare-test-app/"
    )
    with pytest.raises(FilesystemSourceError):
        source.snapshot(
            BackupTarget(
                "tenant-appcare-1",
                "appcare-test-app",
                "test",
                (root / "other").as_posix(),
                "target-appcare-test",
            )
        )


def test_revision_and_target_scope_are_required(tmp_path: Path) -> None:
    root_a = tmp_path / "tenant-a"
    root_b = tmp_path / "tenant-b"
    root_a.mkdir()
    root_b.mkdir()
    revision = _revision(root_a)

    with pytest.raises(FilesystemSourceError, match="live filesystem revision"):
        LinuxFilesystemBackupSource(revision)

    source = LinuxFilesystemBackupSource.for_fixture(revision)

    with pytest.raises(FilesystemSourceError):
        source.capture(_target(root_b))
    with pytest.raises(FilesystemSourceError):
        source.capture(
            BackupTarget(
                "tenant-appcare-1",
                "appcare-test-app",
                "test",
                root_a.as_posix(),
                "other-target",
            )
        )


def test_content_secret_is_excluded_even_when_filename_is_unremarkable(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    secret_file = root / "notes.txt"
    secret_file.write_text("password=fixture-secret-value", encoding="utf-8")
    source = _source(root)

    capture = source.capture(_target(root))

    entry = next(item for item in capture.entries if item.relative_path == "notes.txt")
    assert entry.classification is FilesystemEntryClass.SECRET_EXCLUDED
    assert entry.sha256 is None
    raw_entry = next(
        item for item in source.iter_entries(_target(root)) if item.relative_path == "notes.txt"
    )
    with pytest.raises(FilesystemSourceError):
        source.read_file(_target(root), raw_entry)


def test_structured_secret_is_excluded_even_when_filename_is_unremarkable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "site"
    root.mkdir()
    secret_file = root / "notes.txt"
    secret_file.write_text('{"database_url": "fixture-secret-value"}', encoding="utf-8")
    source = _source(root)

    capture = source.capture(_target(root))

    entry = next(item for item in capture.entries if item.relative_path == "notes.txt")
    assert entry.classification is FilesystemEntryClass.SECRET_EXCLUDED
    assert entry.sha256 is None


def test_same_size_in_place_mutation_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    source_file = root / "content.txt"
    source_file.write_text("AAAA", encoding="utf-8")
    source = _source(root)
    entry = next(
        item for item in source.iter_entries(_target(root)) if item.relative_path == "content.txt"
    )
    source_file.write_text("BBBB", encoding="utf-8")

    with pytest.raises(FilesystemSourceError):
        tuple(source.iter_file_chunks(_target(root), entry))


def test_root_rename_is_rejected_after_source_is_open(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    (root / "content.txt").write_text("safe", encoding="utf-8")
    source = _source(root)
    renamed = tmp_path / "site-renamed"
    root.rename(renamed)

    with pytest.raises(FilesystemSourceError):
        tuple(source.iter_entries(_target(root)))
