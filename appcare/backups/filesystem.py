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
from _thread import LockType
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import Final

from ..revision import CapturedApplicationRevision, EvidenceClass, is_secret_path_name
from ..services.security import SECRET_IDENTIFIER_PATTERN_BYTES, SECRET_PROVIDER_TOKEN_PATTERN_BYTES
from .contracts import BackupBoundaryError, BackupTarget, validate_path_segment
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
    re.compile(rb"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?i)\bAKIA[0-9A-Z]{16}\b"),
    re.compile(SECRET_PROVIDER_TOKEN_PATTERN_BYTES),
)
_SECRET_SCAN_TAIL_BYTES: Final = 4096
_DEFINE_SECRET_IDENTIFIER_PATTERN: Final = re.compile(
    rb"(?i)(?:" + SECRET_IDENTIFIER_PATTERN_BYTES + rb"|passwd|authorization)"
)
_DEFINE_SECRET_TAIL_BYTES: Final = 128
_IDENTIFIER_BYTES: Final = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)
_WHITESPACE_BYTES: Final = frozenset(b" \t\r\n\f\v")
_WHITESPACE_PATTERN: Final = re.compile(rb"\s*")
_VALUE_TERMINATORS: Final = frozenset(b"'\"\r\n,})")
_STREAM_VALIDATION_BYTES: Final = 64 * 1024


class _SecretContentScanner:
    """Scan bounded chunks, including long PHP ``define`` expressions.

    Assignments and PHP define calls retain constant parser state, including
    across arbitrarily long whitespace. Fixed-width markers use an overlap.
    """

    def __init__(self) -> None:
        self._tail = b""
        self._identifier = bytearray()
        self._identifier_overflow = False
        self._waiting_for_open = False
        self._pending_comment_slash = False
        self._line_comment = False
        self._block_comment = False
        self._block_comment_star = False
        self._in_define_call = False
        self._define_depth = 0
        self._quote: int | None = None
        self._escaped = False
        self._call_tail = b""
        self._found = False
        self._assignment_tail = b""
        self._assignment_state = 0
        self._assignment_arrow_possible = False
        self._assignment_quote: int | None = None
        self._assignment_key_quote: int | None = None
        self._assignment_comment = 0
        self._assignment_comment_star = False

    def feed(self, chunk: bytes) -> bool:
        """Consume one bounded chunk and report whether it contains a secret."""

        if self._found:
            return True
        window = self._tail + chunk
        if any(pattern.search(window) for pattern in _SECRET_CONTENT_PATTERNS):
            self._found = True
            return True
        self._found = self._scan_assignments(chunk) or self._scan_define_calls(chunk)
        self._tail = window[-_SECRET_SCAN_TAIL_BYTES:]
        return self._found

    def _scan_assignments(self, chunk: bytes) -> bool:
        window = self._assignment_tail + chunk
        self._assignment_tail = b""
        index = 0
        while index < len(window):
            if self._assignment_state == 0:
                match = _DEFINE_SECRET_IDENTIFIER_PATTERN.search(window, index)
                if match is None:
                    self._assignment_tail = window[-_DEFINE_SECRET_TAIL_BYTES:]
                    return False
                if match.end() == len(window):
                    # A shorter credential name may be the prefix of a longer
                    # one split at this chunk boundary (for example secret_key).
                    token_start = match.start()
                    while token_start and window[token_start - 1] in _IDENTIFIER_BYTES:
                        token_start -= 1
                    if token_start and window[token_start - 1] in (ord("'"), ord('"')):
                        token_start -= 1
                    self._assignment_tail = window[
                        max(token_start, len(window) - _DEFINE_SECRET_TAIL_BYTES) :
                    ]
                    return False
                self._assignment_key_quote = (
                    window[match.start() - 1]
                    if match.start() and window[match.start() - 1] in (ord("'"), ord('"'))
                    else None
                )
                index = match.end()
                self._assignment_state = 1
            if self._assignment_state == 1 and self._assignment_key_quote is not None:
                if window[index] in _WHITESPACE_BYTES:
                    index += 1
                    continue
                if window[index] != self._assignment_key_quote:
                    self._assignment_state = 0
                    self._assignment_key_quote = None
                    continue
                self._assignment_state = 2
                self._assignment_key_quote = None
                index += 1
                continue
            if self._assignment_comment:
                byte = window[index]
                if self._assignment_comment == 1:
                    if byte == ord("*"):
                        self._assignment_comment = 3
                    elif byte == ord("/"):
                        self._assignment_comment = 2
                    else:
                        self._assignment_state = 0
                        self._assignment_comment = 0
                        continue
                elif self._assignment_comment == 2:
                    if byte in (ord("\r"), ord("\n")):
                        self._assignment_comment = 0
                elif self._assignment_comment_star and byte == ord("/"):
                    self._assignment_comment = 0
                    self._assignment_comment_star = False
                else:
                    self._assignment_comment_star = byte == ord("*")
                index += 1
                continue
            whitespace = _WHITESPACE_PATTERN.match(window, index)
            assert whitespace is not None
            index = whitespace.end()
            if index == len(window):
                return False
            byte = window[index]
            if self._assignment_state in (1, 2) and byte == ord("/"):
                self._assignment_comment = 1
                index += 1
                continue
            if self._assignment_state in (1, 2) and byte == ord("#"):
                self._assignment_comment = 2
                index += 1
                continue
            if self._assignment_state == 1 and byte in (ord("'"), ord('"')):
                self._assignment_state = 2
            elif self._assignment_state in (1, 2) and byte in (ord(":"), ord("=")):
                self._assignment_state = 3
                self._assignment_arrow_possible = byte == ord("=")
            elif (
                self._assignment_state == 3 and byte == ord(">") and self._assignment_arrow_possible
            ):
                self._assignment_arrow_possible = False
            elif self._assignment_state == 3 and byte in (ord("'"), ord('"')):
                self._assignment_state = 4
                self._assignment_quote = byte
                self._assignment_arrow_possible = False
            elif self._assignment_state == 4 and byte != self._assignment_quote:
                return True
            elif self._assignment_state == 3 and byte not in _VALUE_TERMINATORS:
                return True
            else:
                self._assignment_state = 0
                self._assignment_arrow_possible = False
                self._assignment_quote = None
                self._assignment_key_quote = None
                continue
            index += 1
        return False

    def _scan_define_calls(self, chunk: bytes) -> bool:
        segment_start = 0
        index = 0
        while index < len(chunk):
            byte = chunk[index]
            if self._in_define_call:
                if self._quote is not None:
                    if self._escaped:
                        self._escaped = False
                    elif byte == ord("\\"):
                        self._escaped = True
                    elif byte == self._quote:
                        self._quote = None
                elif self._consume_comment(byte):
                    pass
                elif byte in (ord("'"), ord('"')):
                    self._quote = byte
                elif byte == ord("("):
                    self._define_depth += 1
                elif byte == ord(")"):
                    self._define_depth -= 1
                    if self._define_depth == 0:
                        call_window = self._call_tail + chunk[segment_start:index]
                        if _DEFINE_SECRET_IDENTIFIER_PATTERN.search(call_window):
                            return True
                        self._in_define_call = False
                        self._quote = None
                        self._escaped = False
                        self._call_tail = b""
                        index += 1
                        segment_start = index
                        continue
                index += 1
                continue

            if self._waiting_for_open:
                if self._consume_comment(byte):
                    index += 1
                    continue
                if byte in _WHITESPACE_BYTES:
                    index += 1
                    continue
                if byte == ord("("):
                    self._waiting_for_open = False
                    self._in_define_call = True
                    self._define_depth = 1
                    self._quote = None
                    self._escaped = False
                    self._call_tail = b""
                    index += 1
                    segment_start = index
                    continue
                self._waiting_for_open = False

            if byte in _IDENTIFIER_BYTES:
                if len(self._identifier) < len(b"define"):
                    self._identifier.append(byte + 0x20 if ord("A") <= byte <= ord("Z") else byte)
                else:
                    self._identifier_overflow = True
                index += 1
                continue

            is_define = not self._identifier_overflow and self._identifier == b"define"
            self._identifier.clear()
            self._identifier_overflow = False
            if is_define:
                if byte == ord("("):
                    self._in_define_call = True
                    self._define_depth = 1
                    self._quote = None
                    self._escaped = False
                    self._call_tail = b""
                    index += 1
                    segment_start = index
                    continue
                if byte in _WHITESPACE_BYTES:
                    self._waiting_for_open = True
                elif byte == ord("/"):
                    self._waiting_for_open = True
                    self._pending_comment_slash = True
                elif byte == ord("#"):
                    self._waiting_for_open = True
                    self._line_comment = True
            index += 1

        if self._in_define_call:
            call_window = self._call_tail + chunk[segment_start:]
            if _DEFINE_SECRET_IDENTIFIER_PATTERN.search(call_window):
                return True
            self._call_tail = call_window[-_DEFINE_SECRET_TAIL_BYTES:]
        return False

    def _consume_comment(self, byte: int) -> bool:
        """Ignore comment punctuation for call structure, retaining chunk state."""

        if self._line_comment:
            if byte in (ord("\r"), ord("\n")):
                self._line_comment = False
            return True
        if self._block_comment:
            if self._block_comment_star and byte == ord("/"):
                self._block_comment = False
                self._block_comment_star = False
            else:
                self._block_comment_star = byte == ord("*")
            return True
        if self._pending_comment_slash:
            self._pending_comment_slash = False
            if byte == ord("/"):
                self._line_comment = True
                return True
            if byte == ord("*"):
                self._block_comment = True
                self._block_comment_star = False
                return True
        if byte == ord("/"):
            self._pending_comment_slash = True
            return True
        if byte == ord("#"):
            self._line_comment = True
            return True
        return False


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


@dataclass(slots=True)
class _CaptureByteBudget:
    """Account every byte read while one capture classifies and digests files."""

    max_bytes: int
    consumed_bytes: int = 0
    _lock: LockType = dataclass_field(default_factory=Lock, repr=False)

    def account(self, amount: int) -> None:
        with self._lock:
            if amount < 0 or amount > self.max_bytes - self.consumed_bytes:
                raise FilesystemSourceError("filesystem capture exceeds total size limit")
            self.consumed_bytes += amount


def _validate_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FilesystemSourceError("filesystem relative path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        if value != ".":
            raise FilesystemSourceError("filesystem relative path escapes source root")
    return value


def filesystem_source_reference(
    root: Path,
    *,
    tenant_id: str,
    application_id: str,
    target_reference: str,
) -> str:
    """Return a safe opaque reference bound to one approved source root.

    ``BackupTarget.source_reference`` is deliberately not a raw filesystem
    path: its contract rejects absolute paths and credential-like material.
    The source root remains bound by the captured revision and root identity;
    this reference adds a deterministic, non-disclosing path binding for the
    target contract without putting the path itself into a serialized target.
    """

    for value, field in (
        (tenant_id, "filesystem source tenant_id"),
        (application_id, "filesystem source application_id"),
        (target_reference, "filesystem source target_reference"),
    ):
        validate_path_segment(value, field=field)
    canonical_root = validate_read_only_source(root)
    root_digest = hashlib.sha256(canonical_root.as_posix().encode("utf-8")).hexdigest()[:32]
    return f"filesystem://{tenant_id}/{application_id}/{target_reference}/{root_digest}"


def _is_secret_path(relative_path: str) -> bool:
    parts = PurePosixPath(relative_path).parts
    lowered = tuple(part.casefold() for part in parts)
    return any(is_secret_path_name(part) for part in lowered) or any(
        part in _SECRET_DIRECTORY_NAMES for part in lowered[:-1]
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
        if os.name != "posix" or not all(
            hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
        ):
            raise FilesystemSourceError("Linux/POSIX descriptor-relative source is required")
        self.root = validate_read_only_source(Path(revision.approved_root))
        if self.root.is_symlink():
            raise FilesystemSourceError("filesystem source root cannot be a symlink")
        self.limits = limits or FilesystemSourceLimits()
        # One source instance represents one streaming operation. Per-file budgets
        # would allow a multi-file tree to exceed the aggregate capture limit.
        self._stream_budget = _CaptureByteBudget(self.limits.max_total_bytes)
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
                self.close()
            raise FilesystemSourceError("filesystem source root cannot be held safely") from exc
        if not stat.S_ISDIR(held.st_mode) or (held.st_dev, held.st_ino) != self._root_identity:
            self.close()
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
        expected_source_reference = filesystem_source_reference(
            self.root,
            tenant_id=self.revision.tenant_id,
            application_id=self.revision.application_id,
            target_reference=self.revision.target_reference,
        )
        if (
            target.tenant_id != self.revision.tenant_id
            or target.application_id != self.revision.application_id
            or target.target_reference != self.revision.target_reference
            or target.source_reference != expected_source_reference
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
        for entry in self._iter_posix_entries():
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
        # Reserve the global entry budget as names arrive, before sorting or
        # materializing a directory. fwalk/scandir sorting alone is unbounded.
        pending: list[tuple[str, FilesystemEntry | None]] = [(".", None)]
        discovered = 1
        while pending:
            directory, expected = pending.pop()
            directory_fd = _open_relative_directory(self._root_fd, directory)
            try:
                before = os.fstat(directory_fd)
                if (
                    expected is not None
                    and _entry_from_stat(
                        directory,
                        before,
                        entry_type=FilesystemEntryType.DIRECTORY,
                        classification=FilesystemEntryClass.SAFE_DIRECTORY,
                    )
                    != expected
                ):
                    raise FilesystemSourceError("filesystem directory changed during capture")
                names: list[str] = []
                with os.scandir(directory_fd) as children:
                    for child in children:
                        if discovered >= self.limits.max_entries:
                            raise FilesystemSourceError("filesystem entry limit exceeded")
                        discovered += 1
                        names.append(child.name)
                names.sort(key=os.fsencode)
                for name in names:
                    relative_path = name if directory == "." else f"{directory}/{name}"
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        yield _entry_from_stat(
                            relative_path,
                            metadata,
                            entry_type=FilesystemEntryType.SYMLINK,
                            classification=FilesystemEntryClass.SYMLINK_DENIED,
                            symlink_target=_readlink_at(directory_fd, name),
                        )
                    elif stat.S_ISDIR(metadata.st_mode):
                        excluded = _is_secret_path(relative_path) or self._baseline_excludes_secret(
                            relative_path
                        )
                        entry = _entry_from_stat(
                            relative_path,
                            metadata,
                            entry_type=FilesystemEntryType.DIRECTORY,
                            classification=(
                                FilesystemEntryClass.SECRET_EXCLUDED
                                if excluded
                                else FilesystemEntryClass.SAFE_DIRECTORY
                            ),
                        )
                        if not excluded:
                            pending.append((relative_path, entry))
                        yield entry
                    else:
                        yield self._classify_metadata(relative_path, metadata)
                if _stat_identity(before) != _stat_identity(os.fstat(directory_fd)):
                    raise FilesystemSourceError("filesystem directory changed during capture")
            except OSError as exc:
                raise FilesystemSourceError("filesystem directory cannot be read safely") from exc
            finally:
                os.close(directory_fd)

    def _baseline_excludes_secret(self, relative_path: str) -> bool:
        baseline = self._revision_entries.get(relative_path)
        return baseline is not None and baseline.classification in {
            "excluded-secret",
            "excluded-secret-tree",
        }

    def _classify_metadata(
        self,
        relative_path: str,
        metadata: os.stat_result,
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
        elif _is_secret_path(relative_path) or self._baseline_excludes_secret(relative_path):
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

    def _validate_readable_entry(self, target: BackupTarget, entry: FilesystemEntry) -> None:
        self._validate_target(target)
        self._check_root_identity()
        self._validate_revision_entry(entry)
        if self._baseline_excludes_secret(entry.relative_path):
            raise FilesystemSourceError("filesystem file contains excluded secret material")
        baseline = self._revision_entries[entry.relative_path]
        if (
            entry.entry_type is not FilesystemEntryType.FILE
            or entry.classification is not FilesystemEntryClass.SAFE_FILE
            or baseline.classification != "included"
            or baseline.sha256 is None
        ):
            raise FilesystemSourceError("filesystem entry is not readable")
        if entry.sha256 is not None and entry.sha256 != baseline.sha256:
            raise FilesystemSourceError("filesystem digest differs from captured revision")

    def _scan_open_file(
        self,
        descriptor: int,
        entry: FilesystemEntry,
        budget: _CaptureByteBudget,
        *,
        consume: Callable[[bytes], object] | None = None,
        block_bytes: int | None = None,
    ) -> tuple[bool, int, str]:
        """Check exactly the bytes hashed, scanned, and optionally buffered."""

        before = os.fstat(descriptor)
        _validate_file_identity(entry, before)
        if before.st_size > self.limits.max_file_bytes:
            raise FilesystemSourceError("filesystem file exceeds size limit")
        digest = hashlib.sha256()
        total = 0
        scanner = _SecretContentScanner()
        contains_secret = False
        while chunk := _read_block(
            descriptor, block_bytes or self.limits.chunk_bytes, self.limits.chunk_bytes
        ):
            budget.account(len(chunk))
            total += len(chunk)
            if total > self.limits.max_file_bytes:
                raise FilesystemSourceError("filesystem file exceeds size limit")
            digest.update(chunk)
            contains_secret = scanner.feed(chunk) or contains_secret
            if consume is not None:
                consume(chunk)
        _validate_file_identity(entry, os.fstat(descriptor))
        self._check_root_identity()
        if total != before.st_size:
            raise FilesystemSourceError("filesystem file changed during capture")
        hexdigest = digest.hexdigest()
        if hexdigest != self._revision_entries[entry.relative_path].sha256:
            raise FilesystemSourceError("filesystem content differs from captured revision")
        return contains_secret, total, hexdigest

    def _read_file_once(
        self,
        target: BackupTarget,
        entry: FilesystemEntry,
        budget: _CaptureByteBudget,
    ) -> tuple[bytes, bool]:
        """Read one bounded file while classifying its content in one pass."""

        self._validate_readable_entry(target, entry)
        descriptor = _open_relative_regular_file(self._root_fd, entry.relative_path)
        try:
            content = bytearray()
            contains_secret, _, _ = self._scan_open_file(
                descriptor, entry, budget, consume=content.extend
            )
            return bytes(content), contains_secret
        finally:
            os.close(descriptor)

    def _capture_file(
        self,
        target: BackupTarget,
        entry: FilesystemEntry,
        budget: _CaptureByteBudget,
    ) -> tuple[bool, int, str]:
        """Classify and digest one file in one bounded read pass."""

        self._validate_readable_entry(target, entry)
        descriptor = _open_relative_regular_file(self._root_fd, entry.relative_path)
        try:
            return self._scan_open_file(descriptor, entry, budget)
        finally:
            os.close(descriptor)

    def read_file(self, target: BackupTarget, entry: FilesystemEntry) -> bytes:
        """Read one safe file with a bounded allocation and identity check."""

        self._validate_target(target)
        if entry.classification is not FilesystemEntryClass.SAFE_FILE:
            raise FilesystemSourceError("filesystem entry is not readable")
        content, contains_secret = self._read_file_once(
            target,
            entry,
            _CaptureByteBudget(self.limits.max_total_bytes),
        )
        if contains_secret:
            raise FilesystemSourceError("filesystem file contains excluded secret material")
        return content

    def iter_file_chunks(self, target: BackupTarget, entry: FilesystemEntry) -> Iterator[bytes]:
        """Yield only blocks verified against a complete baseline-bound scan.

        Hold one descriptor across both passes. Store only SHA-256 block hashes
        (at most 512 KiB at the file cap), then verify each bounded reread before
        releasing any of it. A late mutation can never leak unchecked bytes.
        """

        self._validate_readable_entry(target, entry)
        descriptor = _open_relative_regular_file(self._root_fd, entry.relative_path)
        try:
            block_digests = bytearray()
            contains_secret, total, _ = self._scan_open_file(
                descriptor,
                entry,
                self._stream_budget,
                consume=lambda chunk: block_digests.extend(hashlib.sha256(chunk).digest()),
                block_bytes=_STREAM_VALIDATION_BYTES,
            )
            if contains_secret:
                raise FilesystemSourceError("filesystem file contains excluded secret material")
            os.lseek(descriptor, 0, os.SEEK_SET)
            remaining = total
            for offset in range(0, len(block_digests), 32):
                self._check_root_identity()
                _validate_file_identity(entry, os.fstat(descriptor))
                block = _read_block(
                    descriptor, min(remaining, _STREAM_VALIDATION_BYTES), self.limits.chunk_bytes
                )
                _validate_file_identity(entry, os.fstat(descriptor))
                if hashlib.sha256(block).digest() != block_digests[offset : offset + 32]:
                    raise FilesystemSourceError("filesystem content changed during streaming")
                remaining -= len(block)
                for start in range(0, len(block), self.limits.chunk_bytes):
                    yield block[start : start + self.limits.chunk_bytes]
            if remaining or os.read(descriptor, 1):
                raise FilesystemSourceError("filesystem file changed during capture")
            _validate_file_identity(entry, os.fstat(descriptor))
            self._check_root_identity()
        finally:
            os.close(descriptor)

    def capture(self, target: BackupTarget) -> FilesystemCapture:
        """Capture a deterministic metadata manifest and per-file digests."""

        entries: list[FilesystemEntry] = []
        included_bytes = 0
        budget = _CaptureByteBudget(self.limits.max_total_bytes)
        for entry in self.iter_entries(target):
            if entry.classification is FilesystemEntryClass.SAFE_FILE:
                contains_secret, size, digest = self._capture_file(target, entry, budget)
                if contains_secret:
                    entries.append(
                        replace(entry, classification=FilesystemEntryClass.SECRET_EXCLUDED)
                    )
                    continue
                entry = replace(entry, size_bytes=size, sha256=digest)
                baseline = self._revision_entries[entry.relative_path]
                if baseline.sha256 is not None and entry.sha256 != baseline.sha256:
                    raise FilesystemSourceError("filesystem content differs from captured revision")
                included_bytes += size
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
        index = 0
        budget = _CaptureByteBudget(self.limits.max_total_bytes)
        for entry in self.iter_entries(target):
            if entry.classification is not FilesystemEntryClass.SAFE_FILE:
                continue
            payload, contains_secret = self._read_file_once(target, entry, budget)
            if contains_secret:
                continue
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


def _read_block(descriptor: int, size: int, read_size: int) -> bytes:
    """Keep verification framing stable even when read() returns short reads."""

    block = bytearray()
    while len(block) < size:
        chunk = os.read(descriptor, min(read_size, size - len(block)))
        if not chunk:
            break
        block.extend(chunk)
    return bytes(block)


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_relative_directory(root_fd: int, relative_path: str) -> int:
    _validate_relative_path(relative_path)
    descriptor = os.dup(root_fd)
    try:
        for part in PurePosixPath(relative_path).parts:
            child_fd = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child_fd
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise FilesystemSourceError("filesystem directory cannot be opened safely") from exc


def _open_relative_regular_file(root_fd: int, relative_path: str) -> int:
    _validate_relative_path(relative_path)
    parts = PurePosixPath(relative_path).parts
    if not parts or parts == (".",):
        raise FilesystemSourceError("filesystem file path is invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    parent_fd = os.dup(root_fd)
    descriptor = -1
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
        if descriptor >= 0:
            os.close(descriptor)
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
    "filesystem_source_reference",
]
