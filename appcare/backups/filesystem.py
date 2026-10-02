"""Bounded, read-only Linux filesystem backup source.

The legacy :class:`~appcare.backups.contracts.BackupSource` interface returns
in-memory components and remains available for small controlled fixtures.  The
source in this module also exposes metadata and chunk iterators so a later
artifact writer can process a large application without loading the tree into
memory.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final, cast

from ..revision import CapturedApplicationRevision, EvidenceClass
from .contracts import BackupBoundaryError, BackupTarget
from .models import BackupComponent
from .paths import validate_read_only_source


class FilesystemSourceError(BackupBoundaryError):
    """A filesystem source could not be captured safely."""


class FilesystemEntryType(StrEnum):
    DIRECTORY = "directory"
    FILE = "file"
    SYMLINK = "symlink"
    SPECIAL = "special"


class FilesystemEntryClass(StrEnum):
    SAFE_DIRECTORY = "safe_directory"
    SAFE_FILE = "safe_file"
    SECRET_EXCLUDED = "secret_excluded"  # noqa: S105
    CONFIG_METADATA_ONLY = "config_metadata_only"
    SYMLINK_DENIED = "symlink_denied"
    SPECIAL_FILE_DENIED = "special_file_denied"
    HARDLINK_DENIED = "hardlink_denied"
    OVERSIZED_DENIED = "oversized_denied"


_MAX_ENTRIES: Final = 100_000
_MAX_FILE_BYTES: Final = 1 * 1024 * 1024 * 1024
_MAX_TOTAL_BYTES: Final = 2 * 1024 * 1024 * 1024
_MAX_CHUNK_BYTES: Final = 8 * 1024 * 1024
_MAX_SYMLINK_BYTES: Final = 4096
_SECRET_NAMES: Final = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        "authorized_keys",
        "credentials",
        "credentials.json",
        "id_ed25519",
        "id_rsa",
        "private.key",
        "secret",
        "secrets",
        "secrets.json",
        "settings.php",
        "config.php",
        "wp-config.php",
    }
)
_SECRET_SUFFIXES: Final = (".pem", ".p12", ".pfx", ".key")
_SECRET_DIRECTORY_NAMES: Final = frozenset({".ssh", "secrets", "credentials"})
_CONFIG_SUFFIXES: Final = (
    ".cfg",
    ".conf",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".xml",
    ".yaml",
    ".yml",
)
_SECRET_CONTENT_PATTERNS: Final = (
    re.compile(
        rb"(?i)(?:[a-z0-9_.-]*[_-])?(?:password|passwd|secret|token|"
        rb"api[_-]?key|private[_-]?key|client[_-]?secret|database[_-]?url|"
        rb"authorization)"
        rb"\s*['\"]?\s*(?:[:=]|=>)\s*['\"]?[^'\"\r\n,}\)]{1,4096}"
    ),
    re.compile(rb"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?i)\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        rb"(?is)\bdefine\s*\(\s*['\"][^'\"]*"
        rb"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
        rb"database[_-]?url)"
        rb"[^'\"]*['\"]\s*,"
    ),
)
_SECRET_SCAN_TAIL_BYTES: Final = 4096


@dataclass(frozen=True, slots=True)
class FilesystemSourceLimits:
    """Hard limits; callers may lower them but may not raise them."""

    max_entries: int = _MAX_ENTRIES
    max_file_bytes: int = _MAX_FILE_BYTES
    max_total_bytes: int = _MAX_TOTAL_BYTES
    chunk_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        for name, value, upper in (
            ("max_entries", self.max_entries, _MAX_ENTRIES),
            ("max_file_bytes", self.max_file_bytes, _MAX_FILE_BYTES),
            ("max_total_bytes", self.max_total_bytes, _MAX_TOTAL_BYTES),
            ("chunk_bytes", self.chunk_bytes, _MAX_CHUNK_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= upper:
                raise FilesystemSourceError(f"{name} is outside bounds")
        if self.max_file_bytes > self.max_total_bytes:
            raise FilesystemSourceError("max_file_bytes exceeds max_total_bytes")


@dataclass(frozen=True, slots=True)
class FilesystemEntry:
    """Sanitized metadata for one source-tree entry."""

    relative_path: str
    entry_type: FilesystemEntryType
    classification: FilesystemEntryClass
    size_bytes: int
    mode: int
    device: int
    inode: int
    nlink: int
    uid: int | None = None
    gid: int | None = None
    mtime_ns: int = 0
    ctime_ns: int = 0
    sha256: str | None = None
    symlink_target: str | None = None

    def __post_init__(self) -> None:
        _validate_relative_path(self.relative_path)
        if not isinstance(self.entry_type, FilesystemEntryType):
            object.__setattr__(self, "entry_type", FilesystemEntryType(self.entry_type))
        if not isinstance(self.classification, FilesystemEntryClass):
            object.__setattr__(self, "classification", FilesystemEntryClass(self.classification))
        for name in (
            "size_bytes",
            "mode",
            "device",
            "inode",
            "nlink",
            "mtime_ns",
            "ctime_ns",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise FilesystemSourceError(f"filesystem entry {name} is invalid")
        if self.sha256 is not None and (
            len(self.sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise FilesystemSourceError("filesystem entry digest is invalid")
        if self.symlink_target is not None:
            if len(self.symlink_target) > _MAX_SYMLINK_BYTES or any(
                ord(character) < 32 for character in self.symlink_target
            ):
                raise FilesystemSourceError("filesystem symlink metadata is invalid")

    @property
    def included(self) -> bool:
        return self.classification in {
            FilesystemEntryClass.SAFE_FILE,
            FilesystemEntryClass.SAFE_DIRECTORY,
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "entry_type": self.entry_type.value,
            "classification": self.classification.value,
            "size_bytes": self.size_bytes,
            "mode": self.mode,
            "device": self.device,
            "inode": self.inode,
            "nlink": self.nlink,
            "uid": self.uid,
            "gid": self.gid,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "sha256": self.sha256,
            "symlink_target": self.symlink_target,
        }


@dataclass(frozen=True, slots=True)
class FilesystemCapture:
    """Metadata-only capture result with a deterministic manifest digest."""

    root: str
    root_device: int
    root_inode: int
    entries: tuple[FilesystemEntry, ...]
    included_bytes: int
    manifest_digest: str


def _validate_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FilesystemSourceError("filesystem relative path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        if value != ".":
            raise FilesystemSourceError("filesystem relative path escapes source root")
    return value


def _relative(root: Path, path: str | Path) -> str:
    candidate = Path(path)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise FilesystemSourceError("filesystem entry escaped source root") from exc
    return relative.as_posix() if relative.parts else "."


def _is_secret_path(relative_path: str) -> bool:
    parts = PurePosixPath(relative_path).parts
    lowered = tuple(part.casefold() for part in parts)
    name = lowered[-1]
    return (
        name in _SECRET_NAMES
        or name.endswith(_SECRET_SUFFIXES)
        or any(part in _SECRET_DIRECTORY_NAMES for part in lowered[:-1])
    )


def _is_config_path(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name.casefold()
    return (
        name.startswith("config")
        or name.startswith("settings")
        or name.startswith("database")
        or any(name.endswith(suffix) for suffix in _CONFIG_SUFFIXES)
    )


def _entry_from_stat(
    relative_path: str,
    metadata: os.stat_result,
    *,
    entry_type: FilesystemEntryType,
    classification: FilesystemEntryClass,
    symlink_target: str | None = None,
) -> FilesystemEntry:
    return FilesystemEntry(
        relative_path=relative_path,
        entry_type=entry_type,
        classification=classification,
        size_bytes=0 if entry_type is FilesystemEntryType.SYMLINK else metadata.st_size,
        mode=stat.S_IMODE(metadata.st_mode),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        nlink=metadata.st_nlink,
        uid=getattr(metadata, "st_uid", None),
        gid=getattr(metadata, "st_gid", None),
        mtime_ns=getattr(metadata, "st_mtime_ns", 0),
        ctime_ns=getattr(metadata, "st_ctime_ns", 0),
        symlink_target=symlink_target,
    )


class LinuxFilesystemBackupSource:
    """Read one approved Linux/POSIX filesystem root without write access.

    This source is explicitly streaming-required. The snapshot method remains
    only as a bounded compatibility adapter for legacy fixture callers; the
    normal backup coordinator rejects this source until the chunked artifact
    writer is selected.
    """

    requires_streaming = True

    def __init__(
        self,
        revision: CapturedApplicationRevision,
        *,
        limits: FilesystemSourceLimits | None = None,
    ) -> None:
        if not isinstance(revision, CapturedApplicationRevision):
            raise FilesystemSourceError("captured application revision is required")
        if revision.evidence_class is not EvidenceClass.REAL_TARGET:
            raise FilesystemSourceError("live filesystem revision is required")
        self._initialize(revision, limits=limits)

    @classmethod
    def for_fixture(
        cls,
        revision: CapturedApplicationRevision,
        *,
        limits: FilesystemSourceLimits | None = None,
    ) -> LinuxFilesystemBackupSource:
        """Build an explicitly fixture-scoped source for repository tests only."""

        if not isinstance(revision, CapturedApplicationRevision):
            raise FilesystemSourceError("captured application revision is required")
        if revision.evidence_class is EvidenceClass.REAL_TARGET:
            raise FilesystemSourceError("fixture source cannot carry real-target evidence")
        instance = cls.__new__(cls)
        instance._initialize(revision, limits=limits)
        return instance

    def _initialize(
        self,
        revision: CapturedApplicationRevision,
        *,
        limits: FilesystemSourceLimits | None,
    ) -> None:
        if revision.source_type != "direct-filesystem":
            raise FilesystemSourceError("filesystem source requires a direct-filesystem revision")
        if revision.snapshot_semantics != "observed-tree-merkle-race-checked":
            raise FilesystemSourceError("filesystem revision is not race-checked")
        if revision._source_root_identity is None:
            raise FilesystemSourceError("filesystem revision lacks root identity")
        self.revision = revision
        self._revision_entries = {entry.relative_path: entry for entry in revision.manifest}
        if os.name != "posix" or not hasattr(os, "fwalk") or not hasattr(os, "O_NOFOLLOW"):
            raise FilesystemSourceError("Linux/POSIX descriptor-relative source is required")
        self.root = validate_read_only_source(Path(revision.approved_root))
        if self.root.is_symlink():
            raise FilesystemSourceError("filesystem source root cannot be a symlink")
        self.limits = limits or FilesystemSourceLimits()
        try:
            metadata = self.root.lstat()
        except OSError as exc:
            raise FilesystemSourceError("filesystem source root is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise FilesystemSourceError("filesystem source root is not a directory")
        self._root_identity = (metadata.st_dev, metadata.st_ino)
        if self._root_identity != revision._source_root_identity:
            raise FilesystemSourceError("filesystem root does not match the captured revision")
        try:
            self._root_fd = os.open(
                self.root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            held = os.fstat(self._root_fd)
        except OSError as exc:
            if hasattr(self, "_root_fd"):
                os.close(self._root_fd)
            raise FilesystemSourceError("filesystem source root cannot be held safely") from exc
        if not stat.S_ISDIR(held.st_mode) or (held.st_dev, held.st_ino) != self._root_identity:
            os.close(self._root_fd)
            raise FilesystemSourceError("filesystem source root identity is unstable")

    def close(self) -> None:
        descriptor = getattr(self, "_root_fd", -1)
        if descriptor >= 0:
            self._root_fd = -1
            os.close(descriptor)

    def __enter__(self) -> LinuxFilesystemBackupSource:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def _validate_target(self, target: BackupTarget) -> None:
        if not isinstance(target, BackupTarget):
            raise FilesystemSourceError("backup target is invalid")
        if (
            target.tenant_id != self.revision.tenant_id
            or target.application_id != self.revision.application_id
            or target.target_reference != self.revision.target_reference
            or target.source_reference != self.root.as_posix()
        ):
            raise FilesystemSourceError("backup target is not bound to the filesystem root")

    def _check_root_identity(self) -> None:
        try:
            metadata = self.root.lstat()
            held = os.fstat(self._root_fd)
        except OSError as exc:
            raise FilesystemSourceError("filesystem source root changed") from exc
        if (
            (metadata.st_dev, metadata.st_ino) != self._root_identity
            or (held.st_dev, held.st_ino) != self._root_identity
            or not stat.S_ISDIR(metadata.st_mode)
            or not stat.S_ISDIR(held.st_mode)
        ):
            raise FilesystemSourceError("filesystem source root identity changed")

    def iter_entries(self, target: BackupTarget) -> Iterator[FilesystemEntry]:
        """Yield deterministic metadata, including safe exclusion records."""

        self._validate_target(target)
        self._check_root_identity()
        yielded = 0
        root_metadata = self.root.lstat()
        root_entry = _entry_from_stat(
            ".",
            root_metadata,
            entry_type=FilesystemEntryType.DIRECTORY,
            classification=FilesystemEntryClass.SAFE_DIRECTORY,
        )
        self._validate_revision_entry(root_entry)
        seen_paths = {root_entry.relative_path}
        yield root_entry
        yielded += 1
        if hasattr(os, "fwalk") and os.name == "posix":
            iterator = self._iter_posix_entries()
        else:
            iterator = self._iter_portable_entries()
        for entry in iterator:
            self._validate_revision_entry(entry)
            seen_paths.add(entry.relative_path)
            yielded += 1
            if yielded > self.limits.max_entries:
                raise FilesystemSourceError("filesystem entry limit exceeded")
            yield entry
        self._check_root_identity()
        if seen_paths != set(self._revision_entries):
            raise FilesystemSourceError("filesystem tree differs from captured revision")

    def _validate_revision_entry(self, entry: FilesystemEntry) -> None:
        baseline = self._revision_entries.get(entry.relative_path)
        if baseline is None:
            raise FilesystemSourceError("filesystem entry is absent from captured revision")
        if (
            entry.entry_type.value != baseline.entry_type
            or entry.size_bytes != baseline.size_bytes
            or entry.mode != baseline.mode
            or entry.uid != baseline.uid
            or entry.gid != baseline.gid
            or entry.symlink_target != baseline.symlink_target
        ):
            raise FilesystemSourceError("filesystem metadata differs from captured revision")

    def _iter_posix_entries(self) -> Iterator[FilesystemEntry]:
        fwalk = cast(
            Callable[..., Iterator[tuple[str, list[str], list[str], int]]],
            getattr(os, "fwalk"),  # noqa: B009
        )
        for directory, directories, files, directory_fd in fwalk(
            ".",
            topdown=True,
            follow_symlinks=False,
            dir_fd=self._root_fd,
        ):
            directory_relative = (
                "" if directory in {"", "."} else PurePosixPath(directory).as_posix()
            )
            directories.sort()
            files.sort()
            for name in tuple(directories):
                relative_path = name if not directory_relative else f"{directory_relative}/{name}"
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    directories.remove(name)
                    yield _entry_from_stat(
                        relative_path,
                        metadata,
                        entry_type=FilesystemEntryType.SYMLINK,
                        classification=FilesystemEntryClass.SYMLINK_DENIED,
                        symlink_target=_readlink_at(directory_fd, name),
                    )
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    directories.remove(name)
                    yield _entry_from_stat(
                        relative_path,
                        metadata,
                        entry_type=FilesystemEntryType.SPECIAL,
                        classification=FilesystemEntryClass.SPECIAL_FILE_DENIED,
                    )
                elif _is_secret_path(relative_path):
                    directories.remove(name)
                    yield _entry_from_stat(
                        relative_path,
                        metadata,
                        entry_type=FilesystemEntryType.DIRECTORY,
                        classification=FilesystemEntryClass.SECRET_EXCLUDED,
                    )
                else:
                    yield _entry_from_stat(
                        relative_path,
                        metadata,
                        entry_type=FilesystemEntryType.DIRECTORY,
                        classification=FilesystemEntryClass.SAFE_DIRECTORY,
                    )
            for name in files:
                relative_path = name if not directory_relative else f"{directory_relative}/{name}"
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                yield self._classify_metadata(relative_path, metadata, directory_fd, name)

    def _iter_portable_entries(self) -> Iterator[FilesystemEntry]:
        pending = [self.root]
        while pending:
            directory = pending.pop()
            children = sorted(os.scandir(directory), key=lambda item: item.name)
            for child in children:
                relative_path = _relative(self.root, child.path)
                metadata = child.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                    if _is_secret_path(relative_path):
                        yield _entry_from_stat(
                            relative_path,
                            metadata,
                            entry_type=FilesystemEntryType.DIRECTORY,
                            classification=FilesystemEntryClass.SECRET_EXCLUDED,
                        )
                        continue
                    pending.append(Path(child.path))
                    yield _entry_from_stat(
                        relative_path,
                        metadata,
                        entry_type=FilesystemEntryType.DIRECTORY,
                        classification=FilesystemEntryClass.SAFE_DIRECTORY,
                    )
                elif stat.S_ISLNK(metadata.st_mode):
                    yield _entry_from_stat(
                        relative_path,
                        metadata,
                        entry_type=FilesystemEntryType.SYMLINK,
                        classification=FilesystemEntryClass.SYMLINK_DENIED,
                        symlink_target=os.readlink(child.path),
                    )
                else:
                    yield self._classify_metadata(
                        relative_path, metadata, None, child.name, directory
                    )

    def _classify_metadata(
        self,
        relative_path: str,
        metadata: os.stat_result,
        directory_fd: int | None,
        name: str,
        directory: Path | None = None,
    ) -> FilesystemEntry:
        if not stat.S_ISREG(metadata.st_mode):
            return _entry_from_stat(
                relative_path,
                metadata,
                entry_type=FilesystemEntryType.SPECIAL,
                classification=FilesystemEntryClass.SPECIAL_FILE_DENIED,
            )
        if os.name == "posix" and metadata.st_nlink > 1:
            classification = FilesystemEntryClass.HARDLINK_DENIED
        elif _is_secret_path(relative_path):
            classification = FilesystemEntryClass.SECRET_EXCLUDED
        elif _is_config_path(relative_path):
            classification = FilesystemEntryClass.CONFIG_METADATA_ONLY
        elif metadata.st_size > self.limits.max_file_bytes:
            classification = FilesystemEntryClass.OVERSIZED_DENIED
        else:
            classification = FilesystemEntryClass.SAFE_FILE
        return _entry_from_stat(
            relative_path,
            metadata,
            entry_type=FilesystemEntryType.FILE,
            classification=classification,
        )

    def _contains_secret(self, target: BackupTarget, entry: FilesystemEntry) -> bool:
        self._validate_target(target)
        if entry.classification is not FilesystemEntryClass.SAFE_FILE:
            return False
        descriptor = _open_relative_regular_file(self._root_fd, entry.relative_path)
        try:
            before = os.fstat(descriptor)
            _validate_file_identity(entry, before)
            tail = b""
            while True:
                chunk = os.read(descriptor, self.limits.chunk_bytes)
                if not chunk:
                    break
                window = tail + chunk
                if any(pattern.search(window) for pattern in _SECRET_CONTENT_PATTERNS):
                    return True
                tail = window[-_SECRET_SCAN_TAIL_BYTES:]
            after = os.fstat(descriptor)
            _validate_file_identity(entry, after)
            return False
        finally:
            os.close(descriptor)

    def read_file(self, target: BackupTarget, entry: FilesystemEntry) -> bytes:
        """Read one safe file with a bounded allocation and identity check."""

        self._validate_target(target)
        if entry.classification is not FilesystemEntryClass.SAFE_FILE:
            raise FilesystemSourceError("filesystem entry is not readable")
        if self._contains_secret(target, entry):
            raise FilesystemSourceError("filesystem file contains excluded secret material")
        descriptor = _open_relative_regular_file(self._root_fd, entry.relative_path)
        try:
            before = os.fstat(descriptor)
            _validate_file_identity(entry, before)
            if before.st_size > self.limits.max_file_bytes:
                raise FilesystemSourceError("filesystem file exceeds size limit")
            content = bytearray()
            while True:
                chunk = os.read(
                    descriptor, min(self.limits.chunk_bytes, self.limits.max_file_bytes + 1)
                )
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > self.limits.max_file_bytes:
                    raise FilesystemSourceError("filesystem file exceeds size limit")
            after = os.fstat(descriptor)
            _validate_file_identity(entry, after)
            if len(content) != before.st_size:
                raise FilesystemSourceError("filesystem file changed during capture")
            return bytes(content)
        finally:
            os.close(descriptor)

    def iter_file_chunks(self, target: BackupTarget, entry: FilesystemEntry) -> Iterator[bytes]:
        """Stream one safe file with fixed-size chunks and no full-file buffer."""

        self._validate_target(target)
        if entry.classification is not FilesystemEntryClass.SAFE_FILE:
            raise FilesystemSourceError("filesystem entry is not readable")
        if self._contains_secret(target, entry):
            raise FilesystemSourceError("filesystem file contains excluded secret material")
        descriptor = _open_relative_regular_file(self._root_fd, entry.relative_path)
        total = 0
        try:
            before = os.fstat(descriptor)
            _validate_file_identity(entry, before)
            if before.st_size > self.limits.max_file_bytes:
                raise FilesystemSourceError("filesystem file exceeds size limit")
            while True:
                chunk = os.read(descriptor, self.limits.chunk_bytes)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.limits.max_file_bytes:
                    raise FilesystemSourceError("filesystem file exceeds size limit")
                yield chunk
            after = os.fstat(descriptor)
            _validate_file_identity(entry, after)
            if total != before.st_size:
                raise FilesystemSourceError("filesystem file changed during capture")
        finally:
            os.close(descriptor)

    def capture(self, target: BackupTarget) -> FilesystemCapture:
        """Capture a deterministic metadata manifest and per-file digests."""

        entries: list[FilesystemEntry] = []
        included_bytes = 0
        for entry in self.iter_entries(target):
            if entry.classification is FilesystemEntryClass.SAFE_FILE:
                if self._contains_secret(target, entry):
                    entries.append(
                        replace(entry, classification=FilesystemEntryClass.SECRET_EXCLUDED)
                    )
                    continue
                digest = hashlib.sha256()
                size = 0
                for chunk in self.iter_file_chunks(target, entry):
                    digest.update(chunk)
                    size += len(chunk)
                entry = replace(entry, size_bytes=size, sha256=digest.hexdigest())
                baseline = self._revision_entries[entry.relative_path]
                if baseline.sha256 is not None and entry.sha256 != baseline.sha256:
                    raise FilesystemSourceError("filesystem content differs from captured revision")
                included_bytes += size
                if included_bytes > self.limits.max_total_bytes:
                    raise FilesystemSourceError("filesystem capture exceeds total size limit")
            entries.append(entry)
        payload = "\n".join(
            _canonical_entry_bytes(entry).decode("utf-8") for entry in entries
        ).encode("utf-8")
        return FilesystemCapture(
            root=self.root.as_posix(),
            root_device=self._root_identity[0],
            root_inode=self._root_identity[1],
            entries=tuple(entries),
            included_bytes=included_bytes,
            manifest_digest=hashlib.sha256(payload).hexdigest(),
        )

    def snapshot(self, target: BackupTarget) -> tuple[BackupComponent, ...]:
        """Compatibility snapshot for small fixtures; never use for large sites."""

        components: list[BackupComponent] = []
        total = 0
        index = 0
        for entry in self.iter_entries(target):
            if entry.classification is not FilesystemEntryClass.SAFE_FILE:
                continue
            if self._contains_secret(target, entry):
                continue
            payload = self.read_file(target, entry)
            total += len(payload)
            if total > self.limits.max_total_bytes:
                raise FilesystemSourceError("filesystem snapshot exceeds total size limit")
            components.append(
                BackupComponent(
                    name=f"file-{index:06d}",
                    kind="filesystem-file",
                    source_reference=(
                        f"filesystem://{target.tenant_id}/{target.application_id}/"
                        f"{entry.relative_path}"
                    ),
                    payload=payload,
                )
            )
            index += 1
        if not components:
            raise FilesystemSourceError("filesystem source contains no safe files")
        return tuple(components)


def _readlink_at(directory_fd: int, name: str) -> str:
    target = os.readlink(name, dir_fd=directory_fd)
    if len(target) > _MAX_SYMLINK_BYTES or any(ord(character) < 32 for character in target):
        raise FilesystemSourceError("filesystem symlink metadata is unsafe")
    return target


def _open_relative_regular_file(root_fd: int, relative_path: str) -> int:
    _validate_relative_path(relative_path)
    parts = PurePosixPath(relative_path).parts
    if not parts or parts == (".",):
        raise FilesystemSourceError("filesystem file path is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child_fd = os.open(
                part,
                flags | getattr(os, "O_DIRECTORY", 0),
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = child_fd
        descriptor = os.open(parts[-1], flags, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise FilesystemSourceError("filesystem file cannot be opened safely") from exc
    finally:
        os.close(parent_fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(descriptor)
        raise FilesystemSourceError("filesystem file is not a stable regular file")
    return descriptor


def _validate_file_identity(entry: FilesystemEntry, metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (entry.device > 0 and metadata.st_dev != entry.device)
        or (entry.inode > 0 and metadata.st_ino != entry.inode)
        or (entry.nlink > 0 and metadata.st_nlink != entry.nlink)
        or (entry.size_bytes != metadata.st_size)
        or (entry.mtime_ns > 0 and metadata.st_mtime_ns != entry.mtime_ns)
        or (entry.ctime_ns > 0 and metadata.st_ctime_ns != entry.ctime_ns)
    ):
        raise FilesystemSourceError("filesystem file identity changed during capture")


def _canonical_entry_bytes(entry: FilesystemEntry) -> bytes:
    import json

    return json.dumps(
        entry.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


__all__ = [
    "FilesystemCapture",
    "FilesystemEntry",
    "FilesystemEntryClass",
    "FilesystemEntryType",
    "FilesystemSourceError",
    "FilesystemSourceLimits",
    "LinuxFilesystemBackupSource",
]
