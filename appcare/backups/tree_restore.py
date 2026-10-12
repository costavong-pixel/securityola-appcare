"""Fail-closed isolated restore of a validated streaming filesystem artifact.

This module deliberately does not implement the streaming artifact writer.  It
consumes the artifact and reader contract from ``appcare.backups.streaming`` so
the streaming PR can be merged independently.  Restore is POSIX-only because
the safety boundary depends on descriptor-relative, no-follow operations.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

from ..services.security import contains_credential_like, is_safe_credential_reference
from .contracts import (
    BackupBoundaryError,
    _FORBIDDEN_MARKERS,
    validate_backup_id,
    validate_path_segment,
)
from .paths import BackupFilesystemBoundary


class FilesystemTreeRestoreError(BackupBoundaryError):
    """A filesystem tree restore failed closed."""

    def __init__(self, message: str, *, code: str = "restore_failed") -> None:
        super().__init__(message)
        self.code = code


_SAFE_FAILURE_CODES = frozenset(
    {
        "artifact_invalid",
        "checksum_mismatch",
        "chunk_invalid",
        "cleanup_failed",
        "duplicate_entry",
        "entry_type_mismatch",
        "extra_entry",
        "invalid_limits",
        "manifest_invalid",
        "missing_entry",
        "mode_denied",
        "path_race",
        "path_traversal",
        "production_target_denied",
        "reader_unavailable",
        "restore_failed",
        "restore_io_failure",
        "restore_target_exists",
        "size_limit",
        "special_file_denied",
        "symlink_denied",
        "unsupported_restore_platform",
        "wrong_revision",
        "wrong_scope",
    }
)


class ChunkedBackupReaderProtocol(Protocol):
    """The small reader surface required from the streaming artifact PR."""

    def iter_file_chunks(
        self, artifact: object, request: object, entry_path: str
    ) -> Iterator[bytes]:
        """Validate the sealed artifact and yield one file's plaintext chunks."""


@dataclass(frozen=True, slots=True)
class FilesystemRestoreLimits:
    """Restore caps; callers may lower them but may not raise them."""

    max_manifest_bytes: int = 32 * 1024 * 1024
    max_entries: int = 100_000
    max_file_bytes: int = 1 * 1024 * 1024 * 1024
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_chunk_bytes: int = 8 * 1024 * 1024
    max_chunks: int = 1_000_000

    def __post_init__(self) -> None:
        bounds = (
            ("max_manifest_bytes", self.max_manifest_bytes, 32 * 1024 * 1024),
            ("max_entries", self.max_entries, 100_000),
            ("max_file_bytes", self.max_file_bytes, 1 * 1024 * 1024 * 1024),
            ("max_total_bytes", self.max_total_bytes, 2 * 1024 * 1024 * 1024),
            ("max_chunk_bytes", self.max_chunk_bytes, 8 * 1024 * 1024),
            ("max_chunks", self.max_chunks, 1_000_000),
        )
        for name, value, maximum in bounds:
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise FilesystemTreeRestoreError(f"{name} is outside bounds", code="invalid_limits")
        if self.max_file_bytes > self.max_total_bytes:
            raise FilesystemTreeRestoreError(
                "max_file_bytes exceeds max_total_bytes", code="invalid_limits"
            )


@dataclass(frozen=True, slots=True)
class FilesystemRestoreRequest:
    """Restore binding around the streaming PR's ``ChunkedBackupRequest``.

    ``streaming_request`` is intentionally typed as ``object`` on this base
    branch.  Once the streaming artifact PR is merged, callers pass its real
    ``ChunkedBackupRequest`` unchanged; no second request or manifest format is
    introduced here.
    """

    streaming_request: object
    restore_job_id: str
    environment: Literal["development", "staging", "test"] = "test"
    filesystem: BackupFilesystemBoundary | None = None

    def __post_init__(self) -> None:
        _validated_scope(self.streaming_request)
        validate_path_segment(self.restore_job_id, field="restore_job_id")
        if self.environment not in {"development", "staging", "test"}:
            raise FilesystemTreeRestoreError(
                "filesystem restore cannot target production", code="production_target_denied"
            )
        if self.filesystem is None:
            object.__setattr__(self, "filesystem", BackupFilesystemBoundary.canonical())


@dataclass(frozen=True, slots=True)
class FilesystemTreeRestoreEvidence:
    """Sanitized component evidence; it never contains exception text."""

    backup_id: str
    status: Literal["restore_verified", "restore_failed"]
    tenant_id: str
    application_id: str
    target_reference: str
    restore_job_id: str
    source_revision: str
    source_manifest_digest: str
    tree_digest: str | None
    restored_entry_count: int
    restored_bytes: int
    controlled_test_only: bool
    failure_code: str | None = None
    cleanup_status: Literal["not_required", "cleaned", "cleanup_failed"] = "not_required"
    failure_evidence_reference: str | None = None

    def __post_init__(self) -> None:
        validate_backup_id(self.backup_id)
        validate_path_segment(self.tenant_id, field="evidence tenant_id")
        validate_path_segment(self.application_id, field="evidence application_id")
        validate_path_segment(self.target_reference, field="evidence target_reference")
        validate_path_segment(self.restore_job_id, field="evidence restore_job_id")
        if self.status == "restore_verified" and self.failure_code is not None:
            raise ValueError("verified restore cannot carry a failure")
        if self.status == "restore_verified" and self.tree_digest is None:
            raise ValueError("verified restore must carry a tree digest")
        if self.status == "restore_failed" and self.tree_digest is not None:
            raise ValueError("failed restore cannot carry a tree digest")
        if self.restored_entry_count < 0 or self.restored_bytes < 0:
            raise ValueError("restore evidence counters are invalid")


@dataclass(frozen=True, slots=True)
class _RestoreScope:
    backup_id: str
    tenant_id: str
    application_id: str
    target_reference: str
    source_reference: str
    source_revision: str
    source_manifest_digest: str
    key_reference: str


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _validated_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise FilesystemTreeRestoreError(f"{field} is invalid", code="manifest_invalid")
    normalized = value.casefold()
    if any(character not in "0123456789abcdef" for character in normalized):
        raise FilesystemTreeRestoreError(f"{field} is invalid", code="manifest_invalid")
    return normalized


def _validated_scope(request: object) -> _RestoreScope:
    target = getattr(request, "target", None)
    if target is None:
        raise FilesystemTreeRestoreError("streaming request target is missing", code="wrong_scope")
    backup_id = validate_backup_id(getattr(request, "backup_id", ""))
    tenant_id = validate_path_segment(getattr(target, "tenant_id", ""), field="tenant_id")
    application_id = validate_path_segment(
        getattr(target, "application_id", ""), field="application_id"
    )
    target_reference = validate_path_segment(
        getattr(target, "target_reference", ""), field="target_reference"
    )
    source_reference = _validated_source_reference(getattr(target, "source_reference", ""))
    source_revision = getattr(request, "source_revision", "")
    if (
        not isinstance(source_revision, str)
        or not source_revision
        or len(source_revision) > 200
        or ".." in source_revision
        or any(character.isspace() or ord(character) < 32 for character in source_revision)
    ):
        raise FilesystemTreeRestoreError("source revision is invalid", code="wrong_revision")
    source_manifest_digest = _validated_digest(
        getattr(request, "source_manifest_digest", ""), field="source manifest digest"
    )
    key_reference = getattr(request, "key_reference", "")
    if not is_safe_credential_reference(key_reference):
        raise FilesystemTreeRestoreError("streaming key reference is unsafe", code="wrong_scope")
    if getattr(target, "environment", None) == "production":
        raise FilesystemTreeRestoreError(
            "source target is production", code="production_target_denied"
        )
    return _RestoreScope(
        backup_id,
        tenant_id,
        application_id,
        target_reference,
        source_reference,
        source_revision,
        source_manifest_digest,
        key_reference,
    )


def _validated_source_reference(value: object) -> str:
    if not isinstance(value, str):
        raise FilesystemTreeRestoreError("source reference is unsafe", code="wrong_scope")
    normalized = value.strip()
    pattern = re.compile(r"^/?[A-Za-z0-9][A-Za-z0-9._:/-]{0,499}$")
    if (
        not normalized
        or pattern.fullmatch(normalized) is None
        or ".." in normalized
        or any(character.isspace() or ord(character) < 32 for character in normalized)
        or contains_credential_like(normalized)
        or any(marker in normalized.casefold() for marker in _FORBIDDEN_MARKERS)
    ):
        raise FilesystemTreeRestoreError("source reference is unsafe", code="wrong_scope")
    return normalized


def _relative_parts(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise FilesystemTreeRestoreError("manifest path is invalid", code="manifest_invalid")
    if value == ".":
        return ()
    if value.startswith("/") or len(value) > 4096:
        raise FilesystemTreeRestoreError("manifest path is invalid", code="manifest_invalid")
    parts = tuple(value.split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        raise FilesystemTreeRestoreError(
            "manifest path escapes restore root", code="path_traversal"
        )
    if any(any(ord(character) < 32 for character in part) for part in parts):
        raise FilesystemTreeRestoreError("manifest path is invalid", code="manifest_invalid")
    return parts


def _relative_key(parts: tuple[str, ...]) -> str:
    return "." if not parts else "/".join(parts)


def _read_bounded(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(path), flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise FilesystemTreeRestoreError(
                "artifact metadata exceeds its limit", code="artifact_invalid"
            )
        value = os.read(descriptor, maximum + 1)
    except FilesystemTreeRestoreError:
        raise
    except OSError as exc:
        raise FilesystemTreeRestoreError(
            "artifact metadata cannot be read", code="artifact_invalid"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value) > maximum:
        raise FilesystemTreeRestoreError(
            "artifact metadata exceeds its limit", code="artifact_invalid"
        )
    return value


def _open_directory(path: str | os.PathLike[str], *, dir_fd: int | None = None) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, dir_fd=dir_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise FilesystemTreeRestoreError("restore path is not a directory", code="path_race")
        return descriptor
    except FilesystemTreeRestoreError:
        raise
    except OSError as exc:
        raise FilesystemTreeRestoreError(
            "restore directory cannot be opened", code="path_race"
        ) from exc


def _open_relative_directory(root_fd: int, parts: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for part in parts:
            next_fd = _open_directory(part, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except Exception:
        os.close(current)
        raise


def _mkdir_child(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError as exc:
        raise FilesystemTreeRestoreError(
            "restore destination already contains an entry", code="restore_target_exists"
        ) from exc
    except OSError as exc:
        raise FilesystemTreeRestoreError(
            "restore directory cannot be created", code="restore_io_failure"
        ) from exc
    return _open_directory(name, dir_fd=parent_fd)


def _open_new_file(parent_fd: int, name: str) -> int:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(descriptor)
            raise FilesystemTreeRestoreError("restore file is not regular", code="path_race")
        return descriptor
    except FilesystemTreeRestoreError:
        raise
    except FileExistsError as exc:
        raise FilesystemTreeRestoreError(
            "restore destination already contains an entry", code="restore_target_exists"
        ) from exc
    except OSError as exc:
        raise FilesystemTreeRestoreError(
            "restore file cannot be created", code="restore_io_failure"
        ) from exc


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as exc:
            raise FilesystemTreeRestoreError(
                "restore file cannot be written", code="restore_io_failure"
            ) from exc
        if written <= 0:
            raise FilesystemTreeRestoreError(
                "restore file write made no progress", code="restore_io_failure"
            )
        offset += written


def _validate_mode(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value & ~0o777:
        raise FilesystemTreeRestoreError("manifest mode is not approved", code="mode_denied")
    return value


def _validated_int(value: object, *, field: str, code: str = "manifest_invalid") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FilesystemTreeRestoreError(f"{field} is invalid", code=code)
    return value


def _fchmod(descriptor: int, mode: int) -> None:
    function = getattr(os, "fchmod", None)
    if not callable(function):
        raise FilesystemTreeRestoreError(
            "descriptor mode restoration is unavailable", code="mode_denied"
        )
    cast(Callable[[int, int], None], function)(descriptor, mode)


def _load_manifest(
    artifact: object,
    scope: _RestoreScope,
    filesystem: BackupFilesystemBoundary,
    limits: FilesystemRestoreLimits,
) -> tuple[dict[str, object], bytes]:
    artifact_path = Path(getattr(artifact, "path", ""))
    expected_path = filesystem.staging_path(scope.backup_id)
    try:
        if (
            artifact_path != expected_path
            or artifact_path.is_symlink()
            or not artifact_path.is_dir()
        ):
            raise FilesystemTreeRestoreError(
                "artifact path is outside AppCare scope", code="wrong_scope"
            )
        if getattr(artifact, "backup_id", scope.backup_id) != scope.backup_id:
            raise FilesystemTreeRestoreError(
                "artifact backup binding is invalid", code="wrong_scope"
            )
        manifest_bytes = _read_bounded(artifact_path / "manifest.json", limits.max_manifest_bytes)
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except FilesystemTreeRestoreError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FilesystemTreeRestoreError(
            "artifact manifest is malformed", code="manifest_invalid"
        ) from exc
    if not isinstance(manifest, dict) or _canonical_json(manifest) != manifest_bytes:
        raise FilesystemTreeRestoreError(
            "artifact manifest is not canonical", code="manifest_invalid"
        )
    manifest_digest = _digest(manifest_bytes)
    if getattr(artifact, "manifest_digest", manifest_digest) != manifest_digest:
        raise FilesystemTreeRestoreError(
            "artifact manifest digest does not match", code="artifact_invalid"
        )
    if (
        manifest.get("backup_id") != scope.backup_id
        or manifest.get("tenant_id") != scope.tenant_id
        or manifest.get("application_id") != scope.application_id
        or manifest.get("target_reference") != scope.target_reference
        or manifest.get("source_reference") != scope.source_reference
        or manifest.get("source_revision") != scope.source_revision
        or manifest.get("source_manifest_digest") != scope.source_manifest_digest
        or manifest.get("key_reference") != scope.key_reference
    ):
        raise FilesystemTreeRestoreError(
            "artifact scope binding does not match", code="wrong_scope"
        )
    if not isinstance(manifest.get("entries"), list) or not isinstance(
        manifest.get("chunks"), list
    ):
        raise FilesystemTreeRestoreError(
            "artifact manifest records are malformed", code="manifest_invalid"
        )
    return manifest, manifest_bytes


def _validate_entries(
    manifest: Mapping[str, object], limits: FilesystemRestoreLimits
) -> tuple[dict[str, dict[str, object]], int]:
    raw_entries = manifest["entries"]
    if (
        not isinstance(raw_entries, list)
        or not raw_entries
        or len(raw_entries) > limits.max_entries
    ):
        raise FilesystemTreeRestoreError("artifact entry set is invalid", code="manifest_invalid")
    entries: dict[str, dict[str, object]] = {}
    ordered: list[str] = []
    folded: set[str] = set()
    total_bytes = 0
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise FilesystemTreeRestoreError("artifact entry is malformed", code="manifest_invalid")
        parts = _relative_parts(raw.get("relative_path"))
        path = _relative_key(parts)
        if path in entries or path.casefold() in folded:
            raise FilesystemTreeRestoreError(
                "artifact entries are duplicated", code="duplicate_entry"
            )
        folded.add(path.casefold())
        ordered.append(path)
        classification = raw.get("classification")
        entry_type = raw.get("entry_type")
        if classification == "safe_directory" and entry_type == "directory":
            if raw.get("sha256") not in {None, ""}:
                raise FilesystemTreeRestoreError(
                    "directory digest metadata is invalid", code="manifest_invalid"
                )
        elif classification == "safe_file" and entry_type == "file":
            size = raw.get("size_bytes")
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or not 0 <= size <= limits.max_file_bytes
            ):
                raise FilesystemTreeRestoreError("file size is outside bounds", code="size_limit")
            digest = _validated_digest(raw.get("sha256"), field="file digest")
            total_bytes += size
            if total_bytes > limits.max_total_bytes:
                raise FilesystemTreeRestoreError(
                    "restore exceeds total size limit", code="size_limit"
                )
            raw = dict(raw)
            raw["sha256"] = digest
        else:
            raise FilesystemTreeRestoreError(
                "artifact contains a non-restoreable file classification",
                code="special_file_denied",
            )
        raw = dict(raw)
        raw["mode"] = _validate_mode(raw.get("mode"))
        entries[path] = raw
    if ordered != sorted(ordered):
        raise FilesystemTreeRestoreError(
            "artifact entries are not ordered", code="manifest_invalid"
        )
    if "." not in entries or entries["."].get("classification") != "safe_directory":
        raise FilesystemTreeRestoreError("artifact tree is not rooted", code="missing_entry")
    directories = {
        path for path, entry in entries.items() if entry["classification"] == "safe_directory"
    }
    for path in entries:
        if path == ".":
            continue
        path_parts = path.split("/")
        for index in range(1, len(path_parts)):
            parent = "/".join(path_parts[:index])
            if parent not in directories:
                raise FilesystemTreeRestoreError(
                    "artifact tree has a missing directory", code="missing_entry"
                )
    if not any(entry["classification"] == "safe_file" for entry in entries.values()):
        raise FilesystemTreeRestoreError(
            "artifact has no authenticated file entry", code="missing_entry"
        )
    return entries, total_bytes


def _hash_file_at(parent_fd: int, name: str, expected_size: int, expected_digest: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise FilesystemTreeRestoreError("restored file is not regular", code="path_race")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            if size > expected_size:
                raise FilesystemTreeRestoreError(
                    "restored file exceeds manifest size", code="checksum_mismatch"
                )
        if size != expected_size or digest.hexdigest() != expected_digest:
            raise FilesystemTreeRestoreError(
                "restored file checksum mismatch", code="checksum_mismatch"
            )
    except FilesystemTreeRestoreError:
        raise
    except OSError as exc:
        raise FilesystemTreeRestoreError(
            "restored file cannot be read", code="restore_io_failure"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _tree_records(
    root: Path, expected: Mapping[str, Mapping[str, object]]
) -> tuple[dict[str, dict[str, object]], int]:
    actual: dict[str, dict[str, object]] = {".": {"classification": "safe_directory"}}
    total = 0
    fwalk = cast(
        Callable[..., Iterator[tuple[str, list[str], list[str], int]]],
        getattr(os, "fwalk"),
    )
    for directory, directories, files, directory_fd in fwalk(
        root, topdown=True, follow_symlinks=False
    ):
        directory_path = Path(directory)
        for name in list(directories):
            relative = (directory_path / name).relative_to(root).as_posix()
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise FilesystemTreeRestoreError(
                    "restored tree contains a symlink", code="symlink_denied"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise FilesystemTreeRestoreError(
                    "restored tree contains a special file", code="special_file_denied"
                )
            actual[relative] = {
                "classification": "safe_directory",
                "mode": stat.S_IMODE(metadata.st_mode),
            }
        for name in files:
            relative = (directory_path / name).relative_to(root).as_posix()
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise FilesystemTreeRestoreError(
                    "restored tree contains a symlink", code="symlink_denied"
                )
            if not stat.S_ISREG(metadata.st_mode):
                raise FilesystemTreeRestoreError(
                    "restored tree contains a special file", code="special_file_denied"
                )
            expected_entry = expected.get(relative)
            if expected_entry is None or expected_entry.get("classification") != "safe_file":
                raise FilesystemTreeRestoreError(
                    "restored tree contains an extra file", code="extra_entry"
                )
            _hash_file_at(
                directory_fd,
                name,
                _validated_int(expected_entry.get("size_bytes"), field="file size"),
                str(expected_entry["sha256"]),
            )
            actual[relative] = {
                "classification": "safe_file",
                "mode": stat.S_IMODE(metadata.st_mode),
                "size_bytes": metadata.st_size,
                "sha256": str(expected_entry["sha256"]),
            }
            total += metadata.st_size
    if set(actual) != set(expected):
        missing = set(expected) - set(actual)
        extra = set(actual) - set(expected)
        code = "missing_entry" if missing else "extra_entry"
        raise FilesystemTreeRestoreError(
            "restored tree does not reconcile with manifest", code=code
        )
    for manifest_path, expected_entry in expected.items():
        if actual[manifest_path].get("classification") != expected_entry.get("classification"):
            raise FilesystemTreeRestoreError(
                "restored tree entry type does not reconcile", code="entry_type_mismatch"
            )
    return actual, total


class FilesystemTreeRestorer:
    """Restore one sealed filesystem artifact below the canonical rehearsal root."""

    def __init__(
        self,
        reader: ChunkedBackupReaderProtocol,
        *,
        limits: FilesystemRestoreLimits | None = None,
    ) -> None:
        if not callable(getattr(reader, "iter_file_chunks", None)):
            raise FilesystemTreeRestoreError(
                "streaming reader contract is unavailable", code="reader_unavailable"
            )
        self.reader = reader
        self.limits = limits or FilesystemRestoreLimits()

    def restore(
        self,
        artifact: object,
        request: FilesystemRestoreRequest,
    ) -> FilesystemTreeRestoreEvidence:
        scope = _validated_scope(request.streaming_request)
        root: Path | None = None
        root_created = False
        root_fd = -1
        try:
            if (
                os.name != "posix"
                or not hasattr(os, "O_NOFOLLOW")
                or not hasattr(os, "O_DIRECTORY")
                or not hasattr(os, "fwalk")
            ):
                raise FilesystemTreeRestoreError(
                    "descriptor-relative restore requires POSIX",
                    code="unsupported_restore_platform",
                )
            filesystem = request.filesystem
            if filesystem is None:
                raise FilesystemTreeRestoreError(
                    "restore filesystem boundary is missing", code="wrong_scope"
                )
            manifest, _manifest_bytes = _load_manifest(artifact, scope, filesystem, self.limits)
            entries, total_bytes = _validate_entries(manifest, self.limits)
            root = filesystem.restore_rehearsal_path(
                scope.tenant_id, scope.application_id, request.restore_job_id
            )
            root_fd = self._create_root(filesystem, scope, request.restore_job_id)
            root_created = True
            directories = sorted(
                (
                    path
                    for path, entry in entries.items()
                    if entry["classification"] == "safe_directory"
                ),
                key=lambda path: (path.count("/"), path),
            )
            for path in directories:
                if path == ".":
                    continue
                parts = _relative_parts(path)
                parent_fd = _open_relative_directory(root_fd, parts[:-1])
                try:
                    child_fd = _mkdir_child(parent_fd, parts[-1])
                finally:
                    os.close(parent_fd)
                os.close(child_fd)
            for path in sorted(entries):
                entry = entries[path]
                if entry["classification"] != "safe_file":
                    continue
                parts = _relative_parts(path)
                parent_fd = _open_relative_directory(root_fd, parts[:-1])
                descriptor = -1
                try:
                    descriptor = _open_new_file(parent_fd, parts[-1])
                    digest = hashlib.sha256()
                    written = 0
                    chunk_count = 0
                    chunks = self.reader.iter_file_chunks(artifact, request.streaming_request, path)
                    for chunk in chunks:
                        chunk_count += 1
                        if chunk_count > self.limits.max_chunks:
                            raise FilesystemTreeRestoreError(
                                "streaming artifact exceeds chunk limit", code="size_limit"
                            )
                        if (
                            not isinstance(chunk, bytes)
                            or not chunk
                            or len(chunk) > self.limits.max_chunk_bytes
                        ):
                            raise FilesystemTreeRestoreError(
                                "streaming chunk is invalid", code="chunk_invalid"
                            )
                        written += len(chunk)
                        if written > _validated_int(entry.get("size_bytes"), field="file size"):
                            raise FilesystemTreeRestoreError(
                                "streaming file exceeds manifest size", code="checksum_mismatch"
                            )
                        digest.update(chunk)
                        _write_all(descriptor, chunk)
                    if written != _validated_int(
                        entry.get("size_bytes"), field="file size"
                    ) or digest.hexdigest() != str(entry["sha256"]):
                        raise FilesystemTreeRestoreError(
                            "restored file checksum mismatch", code="checksum_mismatch"
                        )
                    os.fsync(descriptor)
                    mode = _validated_int(entry.get("mode"), field="file mode")
                    _fchmod(descriptor, mode)
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or stat.S_IMODE(metadata.st_mode) != mode
                    ):
                        raise FilesystemTreeRestoreError(
                            "restored file metadata changed", code="path_race"
                        )
                except FilesystemTreeRestoreError:
                    raise
                except OSError as exc:
                    raise FilesystemTreeRestoreError(
                        "restore file operation failed", code="restore_io_failure"
                    ) from exc
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                    os.close(parent_fd)
            actual, actual_bytes = _tree_records(root, entries)
            if actual_bytes != total_bytes:
                raise FilesystemTreeRestoreError(
                    "restored byte count does not reconcile", code="checksum_mismatch"
                )
            tree_digest = self._apply_modes_and_digest(root_fd, root, entries, actual)
            self._verify_root_identity(root, root_fd)
            os.fsync(root_fd)
            return FilesystemTreeRestoreEvidence(
                backup_id=scope.backup_id,
                status="restore_verified",
                tenant_id=scope.tenant_id,
                application_id=scope.application_id,
                target_reference=scope.target_reference,
                restore_job_id=request.restore_job_id,
                source_revision=scope.source_revision,
                source_manifest_digest=scope.source_manifest_digest,
                tree_digest=tree_digest,
                restored_entry_count=len(entries),
                restored_bytes=actual_bytes,
                controlled_test_only=True,
            )
        except Exception as exc:
            code = (
                exc.code
                if isinstance(exc, FilesystemTreeRestoreError) and exc.code in _SAFE_FAILURE_CODES
                else "restore_failed"
            )
            if root_fd >= 0:
                os.close(root_fd)
                root_fd = -1
            cleanup_status: Literal["not_required", "cleaned", "cleanup_failed"] = "not_required"
            if root_created and root is not None:
                cleanup_status = "cleaned" if self._cleanup(root) else "cleanup_failed"
            reference = self._persist_failure(
                request=request,
                scope=scope,
                code=code,
                cleanup_status=cleanup_status,
            )
            return FilesystemTreeRestoreEvidence(
                backup_id=scope.backup_id,
                status="restore_failed",
                tenant_id=scope.tenant_id,
                application_id=scope.application_id,
                target_reference=scope.target_reference,
                restore_job_id=request.restore_job_id,
                source_revision=scope.source_revision,
                source_manifest_digest=scope.source_manifest_digest,
                tree_digest=None,
                restored_entry_count=0,
                restored_bytes=0,
                controlled_test_only=True,
                failure_code=code,
                cleanup_status=cleanup_status,
                failure_evidence_reference=reference,
            )
        finally:
            if root_fd >= 0:
                os.close(root_fd)

    @staticmethod
    def _create_root(
        filesystem: BackupFilesystemBoundary, scope: _RestoreScope, job_id: str
    ) -> int:
        filesystem.ensure_data_dirs()
        base = filesystem._static_subdirectory("restore-rehearsal")
        base_fd = _open_directory(base)
        tenant_fd = -1
        application_fd = -1
        try:
            tenant_fd = FilesystemTreeRestorer._open_or_create_scope_dir(base_fd, scope.tenant_id)
            application_fd = FilesystemTreeRestorer._open_or_create_scope_dir(
                tenant_fd, scope.application_id
            )
            return _mkdir_child(application_fd, job_id)
        finally:
            if application_fd >= 0:
                os.close(application_fd)
            if tenant_fd >= 0:
                os.close(tenant_fd)
            os.close(base_fd)

    @staticmethod
    def _open_or_create_scope_dir(parent_fd: int, name: str) -> int:
        try:
            return _open_directory(name, dir_fd=parent_fd)
        except FilesystemTreeRestoreError as exc:
            if exc.code != "path_race":
                raise
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                return _open_directory(name, dir_fd=parent_fd)
            except OSError as mkdir_exc:
                raise FilesystemTreeRestoreError(
                    "restore scope directory cannot be created", code="restore_io_failure"
                ) from mkdir_exc
            return _open_directory(name, dir_fd=parent_fd)

    @staticmethod
    def _verify_root_identity(root: Path, root_fd: int) -> None:
        try:
            path_metadata = root.lstat()
            fd_metadata = os.fstat(root_fd)
        except OSError as exc:
            raise FilesystemTreeRestoreError("restore root changed", code="path_race") from exc
        if (
            not stat.S_ISDIR(path_metadata.st_mode)
            or not stat.S_ISDIR(fd_metadata.st_mode)
            or (path_metadata.st_dev, path_metadata.st_ino)
            != (fd_metadata.st_dev, fd_metadata.st_ino)
        ):
            raise FilesystemTreeRestoreError("restore root changed", code="path_race")

    @staticmethod
    def _cleanup(root: Path) -> bool:
        try:
            if root.is_symlink() or not root.is_dir():
                return False
            shutil.rmtree(root)
            return not root.exists()
        except OSError:
            return False

    def _persist_failure(
        self,
        *,
        request: FilesystemRestoreRequest,
        scope: _RestoreScope,
        code: str,
        cleanup_status: str,
    ) -> str | None:
        filesystem = request.filesystem
        if filesystem is None:
            return None
        failure_id = (
            "restore-"
            + _digest(
                f"{scope.tenant_id}\0{scope.application_id}\0{request.restore_job_id}\0{time.monotonic_ns()}".encode()
            )[:32]
        )
        try:
            filesystem.ensure_data_dirs()
            directory = filesystem.failed_path(failure_id)
            directory.mkdir(parents=False, exist_ok=False, mode=0o700)
            payload = _canonical_json(
                {
                    "status": "restore_failed",
                    "backup_id": scope.backup_id,
                    "tenant_id": scope.tenant_id,
                    "application_id": scope.application_id,
                    "target_reference": scope.target_reference,
                    "restore_job_id": request.restore_job_id,
                    "source_revision": scope.source_revision,
                    "source_manifest_digest": scope.source_manifest_digest,
                    "failure_code": code,
                    "cleanup_status": cleanup_status,
                }
            )
            descriptor = os.open(
                directory / "failure.json",
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                _write_all(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return f"failed://{failure_id}"
        except (OSError, BackupBoundaryError, TypeError, ValueError):
            return None

    @staticmethod
    def _apply_modes_and_digest(
        root_fd: int,
        root: Path,
        entries: Mapping[str, Mapping[str, object]],
        actual: Mapping[str, Mapping[str, object]],
    ) -> str:
        for path in sorted(
            (
                path
                for path in entries
                if path != "." and entries[path]["classification"] == "safe_directory"
            ),
            key=lambda value: (value.count("/"), value),
            reverse=True,
        ):
            parts = _relative_parts(path)
            descriptor = _open_relative_directory(root_fd, parts)
            try:
                mode = _validated_int(entries[path].get("mode"), field="directory mode")
                _fchmod(descriptor, mode)
                if stat.S_IMODE(os.fstat(descriptor).st_mode) != mode:
                    raise FilesystemTreeRestoreError(
                        "directory mode was not restored", code="mode_denied"
                    )
            finally:
                os.close(descriptor)
        root_mode = _validated_int(entries["."].get("mode"), field="root mode")
        _fchmod(root_fd, root_mode)
        if stat.S_IMODE(os.fstat(root_fd).st_mode) != root_mode:
            raise FilesystemTreeRestoreError("root mode was not restored", code="mode_denied")
        records: list[bytes] = []
        total = 0
        for path in sorted(entries):
            entry = entries[path]
            observed = actual[path]
            record: dict[str, object] = {
                "path": path,
                "classification": entry["classification"],
                "mode": _validated_int(entry.get("mode"), field="tree mode"),
            }
            if entry["classification"] == "safe_file":
                record["size_bytes"] = _validated_int(observed.get("size_bytes"), field="tree size")
                record["sha256"] = observed["sha256"]
                total += _validated_int(observed.get("size_bytes"), field="tree size")
            records.append(_canonical_json(record))
        if total < 0 or not records:
            raise FilesystemTreeRestoreError("restored tree is empty", code="missing_entry")
        return _digest(b"\n".join(records))


__all__ = [
    "ChunkedBackupReaderProtocol",
    "FilesystemRestoreLimits",
    "FilesystemRestoreRequest",
    "FilesystemTreeRestoreEvidence",
    "FilesystemTreeRestoreError",
    "FilesystemTreeRestorer",
]
