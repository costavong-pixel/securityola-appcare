from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import appcare.backups.filesystem as filesystem
from appcare.backups.contracts import BackupTarget
from appcare.backups.filesystem import _is_secret_path, _SecretContentScanner
from appcare.revision import BaselineEntry


def _scan_in_chunks(content: bytes, chunk_size: int = 257) -> bool:
    scanner = _SecretContentScanner()
    return any(
        scanner.feed(content[offset : offset + chunk_size])
        for offset in range(0, len(content), chunk_size)
    )


def test_define_secret_name_is_detected_past_fixed_overlap() -> None:
    content = b"<?php define(" + b" " * 5000 + b"'DB_PASSWORD', 'fixture-value');"

    assert _scan_in_chunks(content)


def test_define_secret_identifier_split_across_chunk_boundary() -> None:
    content = b"<?php define('DB_PASS" + b"WORD', 'fixture-value');"

    assert _scan_in_chunks(content, chunk_size=7)


def test_define_secret_name_with_comments_before_open_paren() -> None:
    block_comment = b"<?php define /*" + b"comment" * 40 + b"*/ ('DB_PASSWORD', 'fixture-value');"
    adjacent_comment = b"<?php define/* comment */('DB_PASSWORD', 'fixture-value');"
    line_comment = b"<?php define // comment\n ('DB_PASSWORD', 'fixture-value');"
    hash_comment = b"<?php define # comment\n ('DB_PASSWORD', 'fixture-value');"

    assert _scan_in_chunks(block_comment, chunk_size=11)
    assert _scan_in_chunks(adjacent_comment, chunk_size=5)
    assert _scan_in_chunks(line_comment, chunk_size=9)
    assert _scan_in_chunks(hash_comment, chunk_size=9)


def test_define_secret_name_with_comments_inside_call() -> None:
    samples = (
        b"<?php define(/* before */ 'DB_PASSWORD', 'fixture-value');",
        b"<?php define('DB_PASSWORD' /* between */, 'fixture-value');",
        b"<?php define('DB_PASSWORD', // between\n 'fixture-value');",
    )

    assert all(_scan_in_chunks(sample, chunk_size=7) for sample in samples)


def test_secret_path_classification_covers_nested_and_dynamic_env_names() -> None:
    assert _is_secret_path("config/.env.custom")
    assert _is_secret_path("nested/credentials.json")
    assert _is_secret_path("private.key")
    assert not _is_secret_path("public/index.php")


def test_non_secret_define_is_not_classified_by_define_scanner() -> None:
    content = b"<?php define('APP_ROOT', '/srv/app');"

    assert not _scan_in_chunks(content)


@pytest.mark.parametrize("chunk_size", [1, 7, 257, 4096])
@pytest.mark.parametrize(
    "content",
    [
        b"DB_PASSWORD" + b" " * 9000 + b"=fixture-value",
        b"'client_secret'" + b"\t" * 9000 + b"=> 'fixture-value'",
        b'"authorization' + b"\r\n " * 3000 + b'" : "fixture-value"',
        b"api-key =" + b"\v\f" * 4500 + b"fixture-value",
        b"token = '" + b" " * 9000 + b"fixture-value'",
    ],
    ids=["before-separator", "after-key-quote", "before-key-quote", "after-separator", "value"],
)
def test_assignment_whitespace_cannot_outgrow_chunk_overlap(
    content: bytes, chunk_size: int
) -> None:
    assert _scan_in_chunks(content, chunk_size)


@pytest.mark.parametrize(
    "content",
    [
        b'{"password": "fixture-value"}',
        b"DB_PASSWD=fixture-value",
        b"private_key => fixture-value",
        b"database-url: fixture-value",
        b"-----BEGIN RSA " + b"PRIVATE KEY-----",
        b"AKIA" + b"A" * 16 + b"\n",
        b"define /* ) ( */ ('CLIENT_SECRET', 'fixture-value');",
    ],
)
def test_secret_markers_detected_at_every_two_chunk_split(content: bytes) -> None:
    for split in range(len(content) + 1):
        scanner = _SecretContentScanner()
        assert scanner.feed(content[:split]) or scanner.feed(content[split:])


@pytest.mark.parametrize(
    "content",
    [
        b"passphrase=fixture-value",
        b"secret_key=fixture-value",
        b"connection_string=fixture-value",
        b"dsn=fixture-value",
        b"password=" + b'",fixture-value"',
        b"token=" + b"'}fixture-value'",
    ],
)
def test_canonical_credential_names_and_quoted_punctuation_detected_at_every_split(
    content: bytes,
) -> None:
    for split in range(len(content) + 1):
        scanner = _SecretContentScanner()
        assert scanner.feed(content[:split]) or scanner.feed(content[split:])


@pytest.mark.parametrize(
    "content",
    [
        b"const secret_name = 'public-label';",
        b"token" + b" " * 9000 + b"description",
        b"password = ''\npublic content",
        b"define('APP_ROOT', '/srv/app');",
        b"public content " * 9000,
    ],
    ids=["identifier-suffix", "no-separator", "empty-value", "public-define", "large-public"],
)
def test_assignment_scanner_keeps_legitimate_controls(content: bytes) -> None:
    assert not _scan_in_chunks(content, 17)


@pytest.mark.parametrize("chunk_size", [1, 7, 257])
def test_php_array_arrow_operator_does_not_make_empty_value_a_secret(chunk_size: int) -> None:
    assert not _scan_in_chunks(b"'token' => ''", chunk_size)
    assert _scan_in_chunks(b"'token' => 'fixture-value'", chunk_size)


def test_long_pending_assignment_retains_constant_state() -> None:
    scanner = _SecretContentScanner()
    assert not scanner.feed(b"authorization")
    for _ in range(256):
        assert not scanner.feed(b" " * 4096)
        assert len(scanner._tail) <= 4096
        assert len(scanner._assignment_tail) <= 12
    assert scanner.feed(b"=fixture-value")
    assert scanner.feed(b"public content")


def test_fstat_failure_closes_both_opened_descriptors(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[int] = []
    monkeypatch.setattr(os, "dup", lambda descriptor: 101)
    monkeypatch.setattr(os, "open", lambda *args, **kwargs: 102)

    def fail_stat(descriptor: int) -> os.stat_result:
        raise OSError("injected fstat failure")

    monkeypatch.setattr(os, "fstat", fail_stat)
    monkeypatch.setattr(os, "close", closed.append)

    with pytest.raises(filesystem.FilesystemSourceError, match="opened safely"):
        filesystem._open_relative_regular_file(100, "safe.txt")

    assert closed == [102, 101]


def test_directory_listing_stops_at_global_budget_before_materializing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = filesystem.LinuxFilesystemBackupSource.__new__(filesystem.LinuxFilesystemBackupSource)
    source.limits = filesystem.FilesystemSourceLimits(max_entries=3)
    source._root_fd = -1
    consumed: list[int] = []
    closed: list[int] = []

    class EndlessDirectory:
        def __enter__(self) -> EndlessDirectory:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def __iter__(self) -> Iterator[SimpleNamespace]:
            for number in range(1000):
                consumed.append(number)
                yield SimpleNamespace(name=f"file-{number}")

    monkeypatch.setattr(filesystem, "_open_relative_directory", lambda *args: 101)
    monkeypatch.setattr(os, "fstat", lambda descriptor: None)
    monkeypatch.setattr(os, "scandir", lambda descriptor: EndlessDirectory())
    monkeypatch.setattr(os, "close", closed.append)

    with pytest.raises(filesystem.FilesystemSourceError, match="entry limit"):
        tuple(source._iter_posix_entries())

    assert consumed == [0, 1, 2]
    assert closed == [101]


@dataclass
class _MemoryFile:
    content: bytes
    position: int = 0
    short_read: int = 4096
    replace_on_rewind: bytes | None = None
    closed: bool = False

    def read(self, descriptor: int, size: int) -> bytes:
        assert descriptor == 102
        result = self.content[self.position : self.position + min(size, self.short_read)]
        self.position += len(result)
        return result

    def rewind(self, descriptor: int, offset: int, whence: int) -> int:
        assert (descriptor, offset, whence) == (102, 0, os.SEEK_SET)
        self.position = 0
        if self.replace_on_rewind is not None:
            self.content = self.replace_on_rewind
        return 0


def _memory_source(
    monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> tuple[
    filesystem.LinuxFilesystemBackupSource, BackupTarget, filesystem.FilesystemEntry, _MemoryFile
]:
    """Exercise real content methods with deterministic descriptor I/O on any OS."""
    source = filesystem.LinuxFilesystemBackupSource.__new__(filesystem.LinuxFilesystemBackupSource)
    source._root_fd = -1
    source.limits = filesystem.FilesystemSourceLimits(chunk_bytes=257)
    source._stream_budget = filesystem._CaptureByteBudget(source.limits.max_total_bytes)
    baseline = BaselineEntry(
        "public.txt",
        "file",
        len(payload),
        0o644,
        0,
        0,
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    source._revision_entries = {baseline.relative_path: baseline}
    metadata = cast(
        os.stat_result,
        SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644,
            st_size=len(payload),
            st_dev=1,
            st_ino=1,
            st_nlink=1,
            st_uid=0,
            st_gid=0,
            st_mtime_ns=1,
            st_ctime_ns=1,
        ),
    )
    entry = filesystem._entry_from_stat(
        baseline.relative_path,
        metadata,
        entry_type=filesystem.FilesystemEntryType.FILE,
        classification=filesystem.FilesystemEntryClass.SAFE_FILE,
    )
    target = BackupTarget("tenant", "application", "test", "filesystem://fixture", "target")
    memory = _MemoryFile(payload)
    monkeypatch.setattr(source, "_validate_target", lambda target: None)
    monkeypatch.setattr(source, "_check_root_identity", lambda: None)
    monkeypatch.setattr(source, "iter_entries", lambda target: iter([entry]))
    monkeypatch.setattr(filesystem, "_open_relative_regular_file", lambda *args: 102)
    monkeypatch.setattr(os, "read", memory.read)
    monkeypatch.setattr(os, "lseek", memory.rewind)
    monkeypatch.setattr(os, "fstat", lambda descriptor: metadata)
    monkeypatch.setattr(os, "close", lambda descriptor: setattr(memory, "closed", True))
    return source, target, entry, memory


def test_stream_blocks_are_checked_before_first_release_on_any_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, target, entry, memory = _memory_source(monkeypatch, b"A" * 70000)
    memory.replace_on_rewind = b"password=fixture-value".ljust(70000, b"B")
    emitted: list[bytes] = []
    with pytest.raises(filesystem.FilesystemSourceError, match="content changed during streaming"):
        for chunk in source.iter_file_chunks(target, entry):
            emitted.append(chunk)
    assert emitted == []
    assert memory.closed


def test_stream_late_mutation_yields_only_already_verified_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, target, entry, memory = _memory_source(monkeypatch, b"A" * 131072)
    stream = source.iter_file_chunks(target, entry)
    emitted: list[bytes] = []
    # Consume the first verified block (including its final partial chunk).
    while sum(map(len, emitted)) < 65536:
        emitted.append(next(stream))
    memory.content = memory.content[:65536] + b"password=fixture-value".ljust(65536, b"B")
    with pytest.raises(filesystem.FilesystemSourceError, match="content changed during streaming"):
        emitted.append(next(stream))
    assert b"".join(emitted) == b"A" * 65536
    assert memory.closed


@pytest.mark.parametrize("operation", ["read", "stream", "snapshot", "capture"])
def test_content_methods_check_baseline_even_with_unchanged_stat(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    source, target, entry, memory = _memory_source(monkeypatch, b"AAAA")
    memory.content = b"BBBB"
    with pytest.raises(
        filesystem.FilesystemSourceError, match="content differs from captured revision"
    ):
        if operation == "read":
            source.read_file(target, entry)
        elif operation == "stream":
            next(source.iter_file_chunks(target, entry))
        elif operation == "snapshot":
            source.snapshot(target)
        else:
            source.capture(target)
    assert memory.closed


def test_stream_short_reads_preserve_bounded_chunks_and_legitimate_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"public content " * 10000
    source, target, entry, memory = _memory_source(monkeypatch, payload)
    memory.short_read = 113
    chunks = list(source.iter_file_chunks(target, entry))
    assert b"".join(chunks) == payload
    assert all(0 < len(chunk) <= 257 for chunk in chunks)
    assert memory.closed


def test_full_secret_preflight_finishes_before_stream_releases_any_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"A" * 65536 + b" password" + b" " * 9000 + b"=fixture-value"
    source, target, entry, memory = _memory_source(monkeypatch, payload)
    emitted: list[bytes] = []
    with pytest.raises(filesystem.FilesystemSourceError, match="excluded secret"):
        for chunk in source.iter_file_chunks(target, entry):
            emitted.append(chunk)
    assert emitted == []
    assert memory.closed


def test_shared_stream_budget_cannot_overcommit_concurrently() -> None:
    budget = filesystem._CaptureByteBudget(100)
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: _account_sixty_bytes(budget), range(2)))
    assert sorted(outcomes) == ["accepted", "rejected"]
    assert budget.consumed_bytes == 60


def test_streaming_same_file_again_does_not_reset_source_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, target, entry, memory = _memory_source(monkeypatch, b"A" * 60)
    source.limits = filesystem.FilesystemSourceLimits(max_file_bytes=100, max_total_bytes=100)
    source._stream_budget = filesystem._CaptureByteBudget(source.limits.max_total_bytes)
    assert b"".join(source.iter_file_chunks(target, entry)) == b"A" * 60
    memory.position = 0
    with pytest.raises(filesystem.FilesystemSourceError, match="total size limit"):
        tuple(source.iter_file_chunks(target, entry))


def _account_sixty_bytes(budget: filesystem._CaptureByteBudget) -> str:
    try:
        budget.account(60)
    except filesystem.FilesystemSourceError:
        return "rejected"
    return "accepted"


@pytest.mark.parametrize("operation", ["read", "stream", "snapshot", "capture"])
@pytest.mark.parametrize(
    "payload",
    [
        b"passphrase=fixture-value",
        b"secret_key=fixture-value",
        b"connection_string=fixture-value",
        b"dsn=fixture-value",
        b"password=" + b'",fixture-value"',
        b"token=" + b"'}fixture-value'",
    ],
)
def test_secret_content_never_enters_any_backup_content_path(
    monkeypatch: pytest.MonkeyPatch, operation: str, payload: bytes
) -> None:
    source, target, _, memory = _memory_source(monkeypatch, payload)
    entry = next(source.iter_entries(target))
    if operation == "read":
        with pytest.raises(filesystem.FilesystemSourceError, match="excluded secret"):
            source.read_file(target, entry)
    elif operation == "stream":
        with pytest.raises(filesystem.FilesystemSourceError, match="excluded secret"):
            next(source.iter_file_chunks(target, entry))
    elif operation == "snapshot":
        with pytest.raises(filesystem.FilesystemSourceError, match="no safe files"):
            source.snapshot(target)
    else:
        source.root = Path("/fixture")
        source._root_identity = (1, 1)
        capture = source.capture(target)
        assert capture.entries[0].classification is filesystem.FilesystemEntryClass.SECRET_EXCLUDED
        assert capture.entries[0].sha256 is None
    assert memory.closed


def test_baseline_exclusion_cannot_be_overridden_by_caller_supplied_safe_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, target, entry, memory = _memory_source(monkeypatch, b"private fixture")
    source._revision_entries[entry.relative_path] = replace(
        source._revision_entries[entry.relative_path], classification="excluded-secret", sha256=None
    )
    assert source._classify_metadata(entry.relative_path, os.fstat(102)).classification is (
        filesystem.FilesystemEntryClass.SECRET_EXCLUDED
    )
    with pytest.raises(filesystem.FilesystemSourceError, match="excluded secret"):
        source.read_file(target, entry)
    with pytest.raises(filesystem.FilesystemSourceError, match="excluded secret"):
        next(source.iter_file_chunks(target, entry))
    assert memory.position == 0


@pytest.mark.parametrize("operation", ["read", "snapshot", "capture"])
def test_bounded_content_methods_preserve_legitimate_control(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    payload = b"public fixture"
    source, target, entry, memory = _memory_source(monkeypatch, payload)
    if operation == "read":
        assert source.read_file(target, entry) == payload
    elif operation == "snapshot":
        assert source.snapshot(target)[0].payload == payload
    else:
        source.root = Path("/fixture")
        source._root_identity = (1, 1)
        assert source.capture(target).entries[0].sha256 == hashlib.sha256(payload).hexdigest()
    assert memory.closed
