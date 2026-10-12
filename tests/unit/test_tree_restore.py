"""P04 isolated streaming filesystem tree restore security coverage."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, cast

import pytest

from appcare.backups import (
    BackupFilesystemBoundary,
    FilesystemRestoreRequest,
    FilesystemTreeRestoreError,
    FilesystemTreeRestorer,
)


POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="P04 tree restore requires POSIX descriptor-relative APIs"
)


def _request(
    *, filesystem: BackupFilesystemBoundary, environment: str = "test"
) -> FilesystemRestoreRequest:
    target = SimpleNamespace(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
        source_reference="/srv/app-a",
        environment="staging",
    )
    streaming_request = SimpleNamespace(
        backup_id="backup-a",
        target=target,
        source_revision="baseline-a",
        source_manifest_digest="a" * 64,
        key_reference="vault://appcare/key-a",
    )
    return FilesystemRestoreRequest(
        streaming_request=streaming_request,
        restore_job_id="restore-a",
        environment=environment,  # type: ignore[arg-type]
        filesystem=filesystem,
    )


def _artifact(
    filesystem: BackupFilesystemBoundary,
    request: FilesystemRestoreRequest,
    *,
    entries: list[dict[str, object]] | None = None,
    chunks: list[dict[str, object]] | None = None,
) -> tuple[SimpleNamespace, dict[str, bytes]]:
    streaming_request = cast(Any, request.streaming_request)
    payloads = {"etc/app.txt": b"hello", "index.txt": b"world"}
    if entries is None:
        entries = [
            {
                "relative_path": ".",
                "entry_type": "directory",
                "classification": "safe_directory",
                "size_bytes": 4096,
                "mode": 0o755,
                "sha256": None,
            },
            {
                "relative_path": "etc",
                "entry_type": "directory",
                "classification": "safe_directory",
                "size_bytes": 4096,
                "mode": 0o750,
                "sha256": None,
            },
            {
                "relative_path": "etc/app.txt",
                "entry_type": "file",
                "classification": "safe_file",
                "size_bytes": 5,
                "mode": 0o640,
                "sha256": hashlib.sha256(payloads["etc/app.txt"]).hexdigest(),
            },
            {
                "relative_path": "index.txt",
                "entry_type": "file",
                "classification": "safe_file",
                "size_bytes": 5,
                "mode": 0o644,
                "sha256": hashlib.sha256(payloads["index.txt"]).hexdigest(),
            },
        ]
    manifest = {
        "schema_version": 1,
        "algorithm": "AES-256-GCM-CHUNKED",
        "backup_id": streaming_request.backup_id,
        "tenant_id": streaming_request.target.tenant_id,
        "application_id": streaming_request.target.application_id,
        "target_reference": streaming_request.target.target_reference,
        "source_reference": streaming_request.target.source_reference,
        "source_revision": streaming_request.source_revision,
        "source_manifest_digest": streaming_request.source_manifest_digest,
        "key_reference": streaming_request.key_reference,
        "entries": entries,
        "chunks": chunks or [],
        "total_plaintext_bytes": 10,
    }
    artifact_path = filesystem.staging_path(streaming_request.backup_id)
    artifact_path.mkdir(parents=True)
    manifest_bytes = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    (artifact_path / "manifest.json").write_bytes(manifest_bytes)
    artifact = SimpleNamespace(
        path=artifact_path,
        manifest_digest=hashlib.sha256(manifest_bytes).hexdigest(),
        artifact_digest="b" * 64,
        backup_id=streaming_request.backup_id,
    )
    return artifact, payloads


class _Reader:
    def __init__(self, payloads: dict[str, bytes], *, tamper: bool = False) -> None:
        self.payloads = payloads
        self.tamper = tamper

    def iter_file_chunks(
        self, artifact: object, request: object, entry_path: str
    ) -> Iterator[bytes]:
        del artifact, request
        payload = self.payloads[entry_path]
        if self.tamper and entry_path == "etc/app.txt":
            payload = b"tampered"
        yield payload


@POSIX_ONLY
def test_restore_reconciles_tree_restores_modes_and_returns_deterministic_digest(
    tmp_path: Path,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    request = _request(filesystem=filesystem)
    artifact, payloads = _artifact(filesystem, request)

    evidence = FilesystemTreeRestorer(_Reader(payloads)).restore(artifact, request)

    assert evidence.status == "restore_verified"
    assert evidence.failure_code is None
    assert evidence.tree_digest is not None
    root = filesystem.restore_rehearsal_path("tenant-a", "application-a", "restore-a")
    assert (root / "etc" / "app.txt").read_bytes() == b"hello"
    assert (root / "index.txt").read_bytes() == b"world"
    assert stat.S_IMODE((root / "etc" / "app.txt").stat().st_mode) == 0o640
    assert stat.S_IMODE((root / "etc").stat().st_mode) == 0o750


@POSIX_ONLY
def test_tampered_chunks_fail_closed_and_cleanup_partial_root(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    request = _request(filesystem=filesystem)
    artifact, payloads = _artifact(filesystem, request)

    evidence = FilesystemTreeRestorer(_Reader(payloads, tamper=True)).restore(artifact, request)

    assert evidence.status == "restore_failed"
    assert evidence.failure_code == "checksum_mismatch"
    assert evidence.tree_digest is None
    root = filesystem.restore_rehearsal_path("tenant-a", "application-a", "restore-a")
    assert not root.exists()
    assert evidence.cleanup_status == "cleaned"
    assert evidence.failure_evidence_reference is not None
    failure_dirs = list((filesystem.backup_root / "failed").iterdir())
    assert len(failure_dirs) == 1
    failure = json.loads((failure_dirs[0] / "failure.json").read_text(encoding="utf-8"))
    assert failure["failure_code"] == "checksum_mismatch"
    assert "tampered" not in json.dumps(failure)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("classification", "special_file_denied", "special_file_denied"),
        ("mode", 0o1000, "mode_denied"),
    ],
)
@POSIX_ONLY
def test_unsafe_manifest_metadata_is_rejected_before_restore(
    tmp_path: Path, field: str, value: object, code: str
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    request = _request(filesystem=filesystem)
    entries = [
        {
            "relative_path": ".",
            "entry_type": "directory",
            "classification": "safe_directory",
            "size_bytes": 0,
            "mode": 0o755,
            "sha256": None,
        },
        {
            "relative_path": "file.txt",
            "entry_type": "file",
            "classification": "safe_file",
            "size_bytes": 5,
            "mode": 0o644,
            "sha256": hashlib.sha256(b"hello").hexdigest(),
        },
    ]
    entries[1][field] = value
    artifact, payloads = _artifact(filesystem, request, entries=entries)

    evidence = FilesystemTreeRestorer(_Reader({"file.txt": payloads["etc/app.txt"]})).restore(
        artifact, request
    )

    assert evidence.status == "restore_failed"
    assert evidence.failure_code == code
    assert evidence.tree_digest is None


@POSIX_ONLY
def test_duplicate_manifest_paths_fail_closed(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    request = _request(filesystem=filesystem)
    artifact, payloads = _artifact(filesystem, request)
    manifest = json.loads((artifact.path / "manifest.json").read_text(encoding="utf-8"))
    manifest["entries"].append(dict(manifest["entries"][-1]))
    manifest_bytes = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    (artifact.path / "manifest.json").write_bytes(manifest_bytes)
    artifact.manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()

    duplicate = FilesystemTreeRestorer(_Reader(payloads)).restore(artifact, request)
    assert duplicate.status == "restore_failed"
    assert duplicate.failure_code == "duplicate_entry"


@POSIX_ONLY
def test_wrong_revision_binding_fails_closed(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    request = _request(filesystem=filesystem)
    artifact, payloads = _artifact(filesystem, request)
    streaming_request = cast(Any, request.streaming_request)
    wrong_streaming_request = SimpleNamespace(
        backup_id=streaming_request.backup_id,
        target=streaming_request.target,
        source_revision="other-baseline",
        source_manifest_digest=streaming_request.source_manifest_digest,
        key_reference=streaming_request.key_reference,
    )
    wrong_request = FilesystemRestoreRequest(
        wrong_streaming_request, "restore-a", filesystem=filesystem
    )

    evidence = FilesystemTreeRestorer(_Reader(payloads)).restore(artifact, wrong_request)

    assert evidence.status == "restore_failed"
    assert evidence.failure_code == "wrong_scope"


def test_production_restore_target_is_rejected() -> None:
    target = SimpleNamespace(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
        source_reference="/srv/app-a",
        environment="production",
    )
    streaming_request = SimpleNamespace(
        backup_id="backup-a",
        target=target,
        source_revision="baseline-a",
        source_manifest_digest="a" * 64,
        key_reference="vault://appcare/key-a",
    )
    with pytest.raises(FilesystemTreeRestoreError, match="production"):
        FilesystemRestoreRequest(streaming_request, "restore-a")


@POSIX_ONLY
def test_preexisting_symlink_is_not_overwritten(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    request = _request(filesystem=filesystem)
    artifact, payloads = _artifact(filesystem, request)
    filesystem.ensure_data_dirs()
    scope = filesystem.restore_rehearsal_path("tenant-a", "application-a", "restore-a")
    scope.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    scope.symlink_to(outside, target_is_directory=True)

    evidence = FilesystemTreeRestorer(_Reader(payloads)).restore(artifact, request)

    assert evidence.status == "restore_failed"
    assert evidence.failure_code == "restore_target_exists"
    assert scope.is_symlink()
    assert not (outside / "index.txt").exists()
