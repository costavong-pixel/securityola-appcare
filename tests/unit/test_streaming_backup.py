"""Adversarial tests for the bounded encrypted filesystem artifact path."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from appcare.backups import (
    BackupTarget,
    ChunkedBackupLimits,
    ChunkedBackupReader,
    ChunkedBackupRequest,
    ChunkedBackupWriter,
    FilesystemCapture,
    FilesystemEntry,
    FilesystemEntryClass,
    FilesystemEntryType,
    StreamingBackupError,
)
from appcare.backups.paths import BackupFilesystemBoundary


class FixtureStreamingSource:
    def __init__(self, root: str, files: dict[str, bytes], *, chunk_bytes: int) -> None:
        self._root = root
        self._files = files
        self._chunk_bytes = chunk_bytes
        entries: list[FilesystemEntry] = [
            FilesystemEntry(
                ".",
                FilesystemEntryType.DIRECTORY,
                FilesystemEntryClass.SAFE_DIRECTORY,
                0,
                0o755,
                1,
                1,
                1,
            )
        ]
        for index, (path, payload) in enumerate(sorted(files.items()), start=2):
            entries.append(
                FilesystemEntry(
                    path,
                    FilesystemEntryType.FILE,
                    FilesystemEntryClass.SAFE_FILE,
                    len(payload),
                    0o640,
                    1,
                    index,
                    1,
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        entries.append(
            FilesystemEntry(
                ".env",
                FilesystemEntryType.FILE,
                FilesystemEntryClass.SECRET_EXCLUDED,
                10,
                0o640,
                1,
                999,
                1,
            )
        )
        self._entries = tuple(sorted(entries, key=lambda entry: entry.relative_path))
        manifest_bytes = "\n".join(
            json.dumps(entry.as_dict(), sort_keys=True, separators=(",", ":"))
            for entry in self._entries
        ).encode()
        self._capture = FilesystemCapture(
            root,
            1,
            1,
            self._entries,
            sum(len(payload) for payload in files.values()),
            hashlib.sha256(manifest_bytes).hexdigest(),
        )

    def capture(self, target: BackupTarget) -> FilesystemCapture:
        assert target.source_reference == self._root
        return self._capture

    def iter_file_chunks(self, target: BackupTarget, entry: FilesystemEntry) -> Iterator[bytes]:
        assert target.source_reference == self._root
        payload = self._files[entry.relative_path]
        for offset in range(0, len(payload), self._chunk_bytes):
            yield payload[offset : offset + self._chunk_bytes]


class FailingFixtureSource(FixtureStreamingSource):
    def iter_file_chunks(self, target: BackupTarget, entry: FilesystemEntry) -> Iterator[bytes]:
        iterator = super().iter_file_chunks(target, entry)
        first = next(iterator)
        yield first
        raise StreamingBackupError("fixture interruption")


def _request(*, application_id: str = "appcare-test-app") -> ChunkedBackupRequest:
    target = BackupTarget(
        "tenant-appcare-1",
        application_id,
        "test",
        "fixture://source",
        "target-test-1",
    )
    return ChunkedBackupRequest(
        "backup-stream-1",
        target,
        "baseline-1",
        "b" * 64,
        "vault://appcare-test-key",
        datetime(2026, 1, 1, tzinfo=UTC),
    )


def _source(*, chunk_bytes: int = 5) -> FixtureStreamingSource:
    return FixtureStreamingSource(
        "fixture://source",
        {"public/index.html": b"abcdef", "uploads/image.bin": b"12345"},
        chunk_bytes=chunk_bytes,
    )


def _writer(
    tmp_path: Path, *, chunk_bytes: int = 5
) -> tuple[BackupFilesystemBoundary, ChunkedBackupWriter]:
    boundary = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    return boundary, ChunkedBackupWriter(
        boundary,
        b"k" * 32,
        limits=ChunkedBackupLimits(chunk_bytes=chunk_bytes, max_chunks=20, max_total_bytes=100),
    )


def test_chunked_artifact_is_sealed_and_read_back_without_full_payload(tmp_path: Path) -> None:
    boundary, writer = _writer(tmp_path)
    request = _request()
    artifact = writer.write(request, source=_source())

    assert artifact.path.is_dir()
    assert (artifact.path / "seal.json").is_file()
    assert not tuple(boundary.staging_path("backup-stream-1").parent.glob("*tmp*"))

    reader = ChunkedBackupReader(boundary, b"k" * 32, limits=writer.limits)
    assert b"".join(reader.iter_file_chunks(artifact, request, "public/index.html")) == b"abcdef"
    assert b"".join(reader.iter_file_chunks(artifact, request, "uploads/image.bin")) == b"12345"
    with pytest.raises(StreamingBackupError):
        tuple(reader.iter_file_chunks(artifact, request, ".env"))

    manifest = json.loads((artifact.path / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["chunks"]) == 3
    assert all(record["plaintext_size"] <= 5 for record in manifest["chunks"])
    assert all(
        (artifact.path / "chunks" / record["filename"]).stat().st_size == record["ciphertext_size"]
        for record in manifest["chunks"]
    )


def test_chunk_boundary_plus_one_is_two_authenticated_chunks(tmp_path: Path) -> None:
    boundary, writer = _writer(tmp_path, chunk_bytes=5)
    artifact = writer.write(_request(), source=_source(chunk_bytes=5))
    manifest = json.loads((artifact.path / "manifest.json").read_text(encoding="utf-8"))
    public_chunks = [
        record for record in manifest["chunks"] if record["entry_path"] == "public/index.html"
    ]
    assert [record["sequence"] for record in public_chunks] == [0, 1]


def test_reader_rejects_scope_mismatch_and_wrong_key(tmp_path: Path) -> None:
    boundary, writer = _writer(tmp_path)
    request = _request()
    artifact = writer.write(request, source=_source())

    with pytest.raises(StreamingBackupError):
        ChunkedBackupReader(boundary, b"z" * 32, limits=writer.limits).iter_file_chunks(
            artifact, request, "public/index.html"
        ).__next__()
    with pytest.raises(StreamingBackupError):
        list(
            ChunkedBackupReader(boundary, b"k" * 32, limits=writer.limits).iter_file_chunks(
                artifact, _request(application_id="other-app"), "public/index.html"
            )
        )


def test_reader_rejects_tampered_or_missing_chunk(tmp_path: Path) -> None:
    boundary, writer = _writer(tmp_path)
    request = _request()
    artifact = writer.write(request, source=_source())
    manifest = json.loads((artifact.path / "manifest.json").read_text(encoding="utf-8"))
    first = artifact.path / "chunks" / manifest["chunks"][0]["filename"]
    first.write_bytes(first.read_bytes() + b"tamper")
    reader = ChunkedBackupReader(boundary, b"k" * 32, limits=writer.limits)
    with pytest.raises(StreamingBackupError):
        list(reader.iter_file_chunks(artifact, request, manifest["chunks"][0]["entry_path"]))

    first.unlink()
    with pytest.raises(StreamingBackupError):
        list(reader.iter_file_chunks(artifact, request, manifest["chunks"][1]["entry_path"]))


def test_reader_rejects_manifest_tampering_even_when_seal_files_are_rewritten(
    tmp_path: Path,
) -> None:
    boundary, writer = _writer(tmp_path)
    request = _request()
    artifact = writer.write(request, source=_source())
    manifest_path = artifact.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["total_plaintext_bytes"] += 1
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )

    reader = ChunkedBackupReader(boundary, b"k" * 32, limits=writer.limits)
    with pytest.raises(StreamingBackupError):
        list(reader.iter_file_chunks(artifact, request, "public/index.html"))


def test_writer_rejects_replay_and_cleans_interrupted_capture(tmp_path: Path) -> None:
    boundary, writer = _writer(tmp_path)
    request = _request()
    writer.write(request, source=_source())
    with pytest.raises(StreamingBackupError):
        writer.write(request, source=_source())

    interrupted_request = ChunkedBackupRequest(
        "backup-stream-2",
        request.target,
        request.source_revision,
        request.source_manifest_digest,
        request.key_reference,
        request.created_at,
    )
    with pytest.raises(StreamingBackupError):
        writer.write(
            interrupted_request,
            source=FailingFixtureSource("fixture://source", {"a": b"abc"}, chunk_bytes=5),
        )
    staging = boundary.staging_path("backup-stream-2")
    assert not staging.exists()
    assert not tuple(staging.parent.glob("backup-stream-2-tmp-*"))


def test_writer_does_not_replace_completed_artifact_and_requires_completion_marker(
    tmp_path: Path,
) -> None:
    boundary, writer = _writer(tmp_path)
    request = _request()
    artifact = writer.write(request, source=_source())
    manifest_before = (artifact.path / "manifest.json").read_bytes()

    with pytest.raises(StreamingBackupError):
        writer.write(request, source=_source())
    assert (artifact.path / "manifest.json").read_bytes() == manifest_before

    (artifact.path / "COMPLETE").unlink()
    reader = ChunkedBackupReader(boundary, b"k" * 32, limits=writer.limits)
    with pytest.raises(StreamingBackupError):
        list(reader.iter_file_chunks(artifact, request, "public/index.html"))


def test_writer_rejects_manifest_budget_before_chunk_staging(tmp_path: Path) -> None:
    boundary = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    writer = ChunkedBackupWriter(
        boundary,
        b"k" * 32,
        limits=ChunkedBackupLimits(
            chunk_bytes=5,
            max_chunks=20,
            max_total_bytes=100,
            max_manifest_bytes=512,
        ),
    )

    with pytest.raises(StreamingBackupError, match="manifest exceeds size limit"):
        writer.write(_request(), source=_source())
    assert not boundary.staging_path("backup-stream-1").exists()


def test_request_requires_a_bound_target_reference(tmp_path: Path) -> None:
    target = BackupTarget(
        "tenant-appcare-1",
        "appcare-test-app",
        "test",
        "fixture://source",
        None,
    )

    with pytest.raises(StreamingBackupError, match="target reference"):
        ChunkedBackupRequest(
            "backup-stream-unbound",
            target,
            "baseline-1",
            "b" * 64,
            "vault://appcare-test-key",
            datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_writer_rejects_inconsistent_capture_size_metadata(tmp_path: Path) -> None:
    boundary, writer = _writer(tmp_path)
    request = _request()
    source = _source()
    source._capture = FilesystemCapture(
        source._capture.root,
        source._capture.root_device,
        source._capture.root_inode,
        source._capture.entries,
        source._capture.included_bytes + 1,
        source._capture.manifest_digest,
    )

    with pytest.raises(StreamingBackupError, match="size metadata"):
        writer.write(request, source=source)
