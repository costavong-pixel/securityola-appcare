"""Adversarial coverage for the bounded Linux filesystem backup source."""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

import appcare.backups.filesystem as filesystem
from appcare.backups import (
    BackupTarget,
    FilesystemEntryClass,
    FilesystemEntryType,
    FilesystemSourceError,
    FilesystemSourceLimits,
    LinuxFilesystemBackupSource,
    filesystem_source_reference,
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
        source_reference=filesystem_source_reference(
            root,
            tenant_id="tenant-appcare-1",
            application_id="appcare-test-app",
            target_reference="target-appcare-test",
        ),
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


def test_streaming_total_byte_limit_is_shared_across_files(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    (root / "first.txt").write_bytes(b"a" * 60)
    (root / "second.txt").write_bytes(b"b" * 60)
    source = _source(
        root,
        limits=FilesystemSourceLimits(max_file_bytes=100, max_total_bytes=100),
    )
    entries = {
        entry.relative_path: entry
        for entry in source.iter_entries(_target(root))
        if entry.classification is FilesystemEntryClass.SAFE_FILE
    }

    assert b"".join(source.iter_file_chunks(_target(root), entries["first.txt"])) == b"a" * 60
    with pytest.raises(FilesystemSourceError, match="total size limit"):
        tuple(source.iter_file_chunks(_target(root), entries["second.txt"]))

    # Restarting a file iterator on the same source cannot reset the budget.
    with pytest.raises(FilesystemSourceError, match="total size limit"):
        tuple(source.iter_file_chunks(_target(root), entries["first.txt"]))


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
                filesystem_source_reference(
                    root / "other",
                    tenant_id="tenant-appcare-1",
                    application_id="appcare-test-app",
                    target_reference="target-appcare-test",
                ),
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
                filesystem_source_reference(
                    root_a,
                    tenant_id="tenant-appcare-1",
                    application_id="appcare-test-app",
                    target_reference="other-target",
                ),
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


def test_long_php_define_secret_is_excluded_across_chunk_windows(
    tmp_path: Path,
) -> None:
    root = tmp_path / "site"
    root.mkdir()
    secret_file = root / "notes.txt"
    secret_file.write_bytes(
        b"<?php define(" + b" " * 5000 + b"'DB_PASSWORD', 'fixture-secret-value');"
    )
    source = _source(root, limits=FilesystemSourceLimits(chunk_bytes=257))

    capture = source.capture(_target(root))

    entry = next(item for item in capture.entries if item.relative_path == "notes.txt")
    assert entry.classification is FilesystemEntryClass.SECRET_EXCLUDED
    assert entry.sha256 is None

    raw_entry = next(
        item for item in source.iter_entries(_target(root)) if item.relative_path == "notes.txt"
    )
    with pytest.raises(FilesystemSourceError, match="excluded secret"):
        source.read_file(_target(root), raw_entry)
    with pytest.raises(FilesystemSourceError, match="excluded secret"):
        tuple(source.iter_file_chunks(_target(root), raw_entry))


def test_secret_classification_reads_count_toward_capture_limit(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    secret_file = root / "notes.txt"
    secret_file.write_bytes(b"x" * 64 + b" password=fixture-secret-value")
    (root / "public.txt").write_bytes(b"public" * 10)
    (root / "other.txt").write_bytes(b"public" * 20)
    source = _source(
        root,
        limits=FilesystemSourceLimits(
            max_file_bytes=256,
            max_total_bytes=256,
            chunk_bytes=17,
        ),
    )

    # Each file is individually below the cap; classification I/O, including
    # excluded content, must consume the shared aggregate budget.
    with pytest.raises(FilesystemSourceError, match="total size limit"):
        source.capture(_target(root))


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


@pytest.mark.parametrize("operation", ["read", "stream", "snapshot", "capture"])
def test_all_content_paths_enforce_baseline_digest_with_fresh_metadata(
    tmp_path: Path, operation: str
) -> None:
    root = tmp_path / "site"
    root.mkdir()
    path = root / "public.txt"
    path.write_bytes(b"AAAA")
    with _source(root) as source:
        path.write_bytes(b"BBBB")
        # Get a new entry after mutation, so stale timestamps cannot be the
        # reason for rejection. Size, permissions and identity still match.
        entries = tuple(source.iter_entries(_target(root)))
        entry = next(item for item in entries if item.relative_path == path.name)
        with pytest.raises(FilesystemSourceError, match="content differs from captured revision"):
            if operation == "read":
                source.read_file(_target(root), entry)
            elif operation == "stream":
                next(source.iter_file_chunks(_target(root), entry))
            elif operation == "snapshot":
                source.snapshot(_target(root))
            else:
                source.capture(_target(root))


def test_baseline_secret_exclusion_is_monotonic_even_for_unremarkable_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "site"
    root.mkdir()
    (root / "notes.txt").write_bytes(b"private fixture")
    (root / "public.txt").write_bytes(b"public fixture")
    baseline = FilesystemBaselineCapturer().capture(root)
    baseline = replace(
        baseline,
        entries=tuple(
            replace(entry, classification="excluded-secret", sha256=None)
            if entry.relative_path == "notes.txt"
            else entry
            for entry in baseline.entries
        ),
    )
    revision = CapturedApplicationRevision.from_filesystem_baseline(
        baseline,
        tenant_id="tenant-appcare-1",
        application_id="appcare-test-app",
        target_reference="target-appcare-test",
        host_identity="slab-prompt-ola",
        captured_at=datetime(2026, 9, 3, 12, 0, tzinfo=UTC),
    )
    real_open = filesystem._open_relative_regular_file
    opened: list[str] = []

    def track_open(root_fd: int, relative_path: str) -> int:
        opened.append(relative_path)
        assert relative_path != "notes.txt"
        return real_open(root_fd, relative_path)

    monkeypatch.setattr(filesystem, "_open_relative_regular_file", track_open)
    with LinuxFilesystemBackupSource.for_fixture(revision) as source:
        entries = tuple(source.iter_entries(_target(root)))
        excluded = next(item for item in entries if item.relative_path == "notes.txt")
        assert excluded.classification is FilesystemEntryClass.SECRET_EXCLUDED
        capture = source.capture(_target(root))
        assert next(e for e in capture.entries if e.relative_path == "notes.txt") == excluded
        assert [component.payload for component in source.snapshot(_target(root))] == [
            b"public fixture"
        ]
        forged = replace(excluded, classification=FilesystemEntryClass.SAFE_FILE)
        with pytest.raises(FilesystemSourceError, match="excluded secret"):
            source.read_file(_target(root), forged)
        with pytest.raises(FilesystemSourceError, match="excluded secret"):
            next(source.iter_file_chunks(_target(root), forged))
    assert opened == ["public.txt", "public.txt"]


@pytest.mark.parametrize("mutation_point", ["rewind", "after-first-block"])
def test_stream_mutation_never_releases_unchecked_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation_point: str
) -> None:
    root = tmp_path / "site"
    root.mkdir()
    block_size = 64 * 1024
    original = b"A" * (block_size * 2)
    path = root / "public.txt"
    path.write_bytes(original)
    with _source(root, limits=FilesystemSourceLimits(chunk_bytes=block_size)) as source:
        entry = next(e for e in source.iter_entries(_target(root)) if e.relative_path == path.name)
        captured_stat = path.stat()
        real_fstat = os.fstat
        real_lseek = os.lseek

        def hide_timestamp_changes(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            return captured_stat if metadata.st_ino == captured_stat.st_ino else metadata

        def mutate() -> None:
            with path.open("r+b") as stream:
                if mutation_point == "after-first-block":
                    stream.seek(block_size)
                stream.write(b"password=fixture-value".ljust(block_size, b"B"))

        def rewind_and_mutate(descriptor: int, offset: int, whence: int) -> int:
            result = real_lseek(descriptor, offset, whence)
            if mutation_point == "rewind":
                mutate()
            return result

        monkeypatch.setattr(os, "fstat", hide_timestamp_changes)
        monkeypatch.setattr(os, "lseek", rewind_and_mutate)
        emitted: list[bytes] = []
        stream = source.iter_file_chunks(_target(root), entry)
        if mutation_point == "after-first-block":
            emitted.append(next(stream))
            mutate()
        with pytest.raises(FilesystemSourceError, match="content changed during streaming"):
            emitted.append(next(stream))
        assert emitted == ([] if mutation_point == "rewind" else [original[:block_size]])


def test_fifo_replacement_is_rejected_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "site"
    root.mkdir()
    path = root / "public.txt"
    path.write_bytes(b"public")
    with _source(root) as source:
        entry = next(e for e in source.iter_entries(_target(root)) if e.relative_path == path.name)
        real_open = os.open
        replaced = False

        def replace_with_fifo(
            name: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal replaced
            if name == path.name and dir_fd is not None and not replaced:
                # Assert before an unsafe open could hang CI.
                assert flags & getattr(os, "O_NONBLOCK")  # noqa: B009
                path.unlink()
                getattr(os, "mkfifo")(path)  # noqa: B009
                replaced = True
            return real_open(name, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(os, "open", replace_with_fifo)
        with pytest.raises(FilesystemSourceError, match="stable regular file"):
            source.read_file(_target(root), entry)
        assert replaced


def test_file_directory_and_dangling_symlinks_match_baseline(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    (root / "public.txt").write_bytes(b"public")
    (root / "assets").mkdir()
    for name, target in [
        ("file-link", "public.txt"),
        ("dir-link", "assets"),
        ("dangling", "absent"),
    ]:
        (root / name).symlink_to(target)
    with _source(root) as source:
        capture = source.capture(_target(root))
    symlinks = [e for e in capture.entries if e.entry_type is FilesystemEntryType.SYMLINK]
    assert {e.relative_path for e in symlinks} == {"file-link", "dir-link", "dangling"}
    assert all(e.classification is FilesystemEntryClass.SYMLINK_DENIED for e in symlinks)
    assert all(e.size_bytes == 0 and e.sha256 is None for e in symlinks)


def test_directory_entry_limit_is_global_across_subdirectories(tmp_path: Path) -> None:
    root = tmp_path / "site"
    root.mkdir()
    for name in ("one", "two"):
        (root / name).mkdir()
        (root / name / "public.txt").write_bytes(b"public")
    with _source(root, limits=FilesystemSourceLimits(max_entries=4)) as source:
        with pytest.raises(FilesystemSourceError, match="entry limit"):
            tuple(source.iter_entries(_target(root)))
