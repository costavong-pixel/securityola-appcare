"""Bounded, race-checked filesystem capture for AppCare P03."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Final

from .contracts import (
    BaselineCaptureError,
    BaselineEntry,
    BaselinePolicy,
    CapturedApplicationRevision,
    EvidenceClass,
    FilesystemBaseline,
    LiveCaptureAuthorization,
    SourceType,
    is_secret_path_name,
)

_O_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY: Final[int] = getattr(os, "O_DIRECTORY", 0)
_O_BINARY: Final[int] = getattr(os, "O_BINARY", 0)
_MAX_GIT_HEAD_BYTES: Final[int] = 4096
_GIT_SHA_HEX: Final = frozenset("0123456789abcdef")


def detect_source_type(root: Path) -> SourceType:
    """Detect Git only from a local marker; never execute hooks or contact a remote."""

    marker = root / ".git"
    try:
        metadata = marker.lstat()
    except (FileNotFoundError, OSError):
        return "direct-filesystem"
    if stat.S_ISLNK(metadata.st_mode):
        return "direct-filesystem"
    return (
        "git"
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
        else "direct-filesystem"
    )


def read_git_revision(root: Path) -> str | None:
    """Read a Git HEAD/ref without invoking Git or following an external worktree."""

    if detect_source_type(root) != "git":
        return None
    marker = root / ".git"
    try:
        marker_metadata = marker.lstat()
        if stat.S_ISDIR(marker_metadata.st_mode):
            git_root = marker
        elif stat.S_ISREG(marker_metadata.st_mode):
            raw = marker.read_bytes()
            if len(raw) > _MAX_GIT_HEAD_BYTES:
                return None
            line = raw.decode("utf-8").strip()
            if not line.startswith("gitdir: "):
                return None
            candidate = Path(line[8:])
            if not candidate.is_absolute():
                candidate = marker.parent / candidate
            git_root = candidate.resolve(strict=True)
            if root.resolve(strict=True) not in git_root.parents:
                return None
        else:
            return None
        head = git_root / "HEAD"
        head_raw = head.read_bytes()
        if len(head_raw) > _MAX_GIT_HEAD_BYTES:
            return None
        head_value = head_raw.decode("ascii").strip()
        if _is_git_revision(head_value):
            return head_value
        if not head_value.startswith("ref: refs/"):
            return None
        reference = head_value[5:]
        ref_path = git_root / reference
        if ref_path.resolve(strict=False).parent != ref_path.parent.resolve(strict=False):
            return None
        try:
            ref_raw = ref_path.read_bytes()
            revision = ref_raw.decode("ascii").strip()
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            revision = ""
        if _is_git_revision(revision):
            return revision
        packed = git_root / "packed-refs"
        try:
            packed_raw = packed.read_bytes()
            if len(packed_raw) > 4 * 1024 * 1024:
                return None
            for line in packed_raw.decode("ascii").splitlines():
                if line and not line.startswith("#") and not line.startswith("^"):
                    candidate_revision, _, candidate_ref = line.partition(" ")
                    if candidate_ref == reference and _is_git_revision(candidate_revision):
                        return candidate_revision
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return None
    except (FileNotFoundError, OSError, RuntimeError, UnicodeDecodeError):
        return None
    return None


def _is_git_revision(value: str) -> bool:
    return 40 <= len(value) <= 64 and set(value.casefold()) <= _GIT_SHA_HEX


class FilesystemBaselineCapturer:
    """Capture an observed-tree Merkle manifest without retaining file contents."""

    def __init__(self, policy: BaselinePolicy | None = None) -> None:
        self.policy = policy or BaselinePolicy()

    def capture(self, root: Path) -> FilesystemBaseline:
        canonical_root = self._canonical_root(root)
        root_metadata = os.lstat(canonical_root)
        entries: list[BaselineEntry] = [self._directory_entry(".", root_metadata)]
        state = _CaptureState(self.policy)
        state.add_entry(entries[0])
        if os.name != "posix":
            raise BaselineCaptureError("secure baseline capture requires POSIX descriptor APIs")
        try:
            descriptor = os.open(canonical_root, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
        except OSError as exc:
            raise BaselineCaptureError("capture root cannot be opened safely") from exc
        try:
            if _stat_identity(root_metadata) != _stat_identity(os.fstat(descriptor)):
                raise BaselineCaptureError("capture root changed before capture")
            self._capture_posix_directory(
                descriptor,
                relative_directory=".",
                root=canonical_root,
                entries=entries,
                state=state,
            )
        finally:
            os.close(descriptor)
        entries.sort(key=lambda entry: entry.relative_path)
        return FilesystemBaseline(
            root=canonical_root.as_posix(),
            entries=tuple(entries),
            policy=self.policy,
            source_type=detect_source_type(canonical_root),
        )

    def capture_revision(
        self,
        root: Path,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str,
        host_identity: str,
        captured_at: datetime,
        runtime_metadata: dict[str, object] | None = None,
        database_metadata: dict[str, object] | None = None,
        evidence_class: EvidenceClass = EvidenceClass.FIXTURE,
        evidence_reference: str | None = None,
        baseline_id: str | None = None,
        live_authorization: LiveCaptureAuthorization | None = None,
    ) -> CapturedApplicationRevision:
        baseline = self.capture(root)
        source_revision = (
            read_git_revision(Path(baseline.root)) if baseline.source_type == "git" else None
        )
        if baseline.source_type == "git" and source_revision is None:
            raise BaselineCaptureError("Git source revision is unavailable")
        return CapturedApplicationRevision.from_filesystem_baseline(
            baseline,
            tenant_id=tenant_id,
            application_id=application_id,
            target_reference=target_reference,
            host_identity=host_identity,
            captured_at=captured_at,
            runtime_metadata=runtime_metadata,
            database_metadata=database_metadata,
            source_revision=source_revision,
            evidence_class=evidence_class,
            evidence_reference=evidence_reference,
            baseline_id=baseline_id,
            live_authorization=live_authorization,
        )

    def _canonical_root(self, root: Path) -> Path:
        if not isinstance(root, Path) or not root.is_absolute():
            raise BaselineCaptureError("capture root must be absolute")
        try:
            metadata = root.lstat()
            resolved = root.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError) as exc:
            raise BaselineCaptureError("capture root is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise BaselineCaptureError("capture root is not a real directory")
        if resolved != root:
            raise BaselineCaptureError("capture root crosses a symlink")
        if resolved == Path(resolved.anchor):
            raise BaselineCaptureError("capture root is too broad")
        return resolved

    def _capture_posix_directory(
        self,
        directory_fd: int,
        *,
        relative_directory: str,
        root: Path,
        entries: list[BaselineEntry],
        state: _CaptureState,
    ) -> None:
        before = os.fstat(directory_fd)
        names: list[str] = []
        remaining = self.policy.max_entries - state.entries
        try:
            with os.scandir(directory_fd) as iterator:
                for item in iterator:
                    if len(names) >= remaining:
                        raise BaselineCaptureError("source has too many entries")
                    names.append(item.name)
        except BaselineCaptureError:
            raise
        except (OSError, TypeError) as exc:
            raise BaselineCaptureError("directory listing failed") from exc
        names.sort(key=lambda item: os.fsencode(item))
        for name in names:
            self._validate_name(name)
            relative = self._relative_child(relative_directory, name)
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise BaselineCaptureError("source entry disappeared") from exc
            if stat.S_ISLNK(metadata.st_mode):
                entries.append(
                    self._symlink_entry(
                        name, relative, relative_directory, directory_fd, root, metadata
                    )
                )
                state.add_entry(entries[-1])
                continue
            if stat.S_ISDIR(metadata.st_mode):
                entry = self._directory_entry(relative, metadata)
                entries.append(entry)
                state.add_entry(entry)
                if is_secret_path_name(name):
                    entries[-1] = self._classified(entry, "excluded-secret-tree")
                    state.replace_last(entries[-1])
                    continue
                try:
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise BaselineCaptureError("directory cannot be opened safely") from exc
                try:
                    self._capture_posix_directory(
                        child_fd,
                        relative_directory=relative,
                        root=root,
                        entries=entries,
                        state=state,
                    )
                finally:
                    os.close(child_fd)
                continue
            if stat.S_ISREG(metadata.st_mode):
                entry = self._capture_file_posix(
                    name,
                    relative,
                    directory_fd,
                    metadata,
                    state,
                )
                entries.append(entry)
                state.add_entry(entry)
                continue
            raise BaselineCaptureError("unsafe special file in source tree")
        after = os.fstat(directory_fd)
        if _stat_identity(before) != _stat_identity(after):
            raise BaselineCaptureError("source directory changed during capture")

    def _capture_file_posix(
        self,
        name: str,
        relative: str,
        directory_fd: int,
        metadata: os.stat_result,
        state: _CaptureState,
    ) -> BaselineEntry:
        if is_secret_path_name(name):
            return BaselineEntry(
                relative,
                "file",
                metadata.st_size,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_uid,
                metadata.st_gid,
                classification="excluded-secret",
            )
        return self._hash_open_file(
            relative,
            metadata,
            state,
            opener=lambda: os.open(
                name,
                os.O_RDONLY | _O_NOFOLLOW | _O_BINARY,
                dir_fd=directory_fd,
            ),
        )

    def _hash_open_file(
        self,
        relative: str,
        metadata: os.stat_result,
        state: _CaptureState,
        *,
        opener: Callable[[], int],
    ) -> BaselineEntry:
        if metadata.st_nlink != 1:
            raise BaselineCaptureError("hard-linked source file is not accepted")
        if metadata.st_size > self.policy.max_file_bytes:
            raise BaselineCaptureError("source file exceeds capture limit")
        try:
            descriptor = opener()
        except OSError as exc:
            raise BaselineCaptureError("source file cannot be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            if _stat_identity(metadata) != _stat_identity(opened):
                raise BaselineCaptureError("source file was replaced during capture")
            digest = hashlib.sha256()
            read_bytes = 0
            while True:
                chunk = os.read(descriptor, self.policy.chunk_bytes)
                if not chunk:
                    break
                read_bytes += len(chunk)
                state.add_bytes(len(chunk))
                if read_bytes > self.policy.max_file_bytes:
                    raise BaselineCaptureError("source file grew beyond capture limit")
                digest.update(chunk)
            final = os.fstat(descriptor)
            if _stat_identity(metadata) != _stat_identity(final) or read_bytes != metadata.st_size:
                raise BaselineCaptureError("source file changed during capture")
        except BaselineCaptureError:
            raise
        except OSError as exc:
            raise BaselineCaptureError("source file read failed") from exc
        finally:
            os.close(descriptor)
        return BaselineEntry(
            relative,
            "file",
            metadata.st_size,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            sha256=digest.hexdigest(),
        )

    @staticmethod
    def _directory_entry(relative: str, metadata: os.stat_result) -> BaselineEntry:
        return BaselineEntry(
            relative,
            "directory",
            metadata.st_size,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
        )

    @staticmethod
    def _classified(entry: BaselineEntry, classification: str) -> BaselineEntry:
        return BaselineEntry(
            entry.relative_path,
            entry.entry_type,
            entry.size_bytes,
            entry.mode,
            entry.uid,
            entry.gid,
            classification=classification,  # type: ignore[arg-type]
        )

    def _symlink_entry(
        self,
        name: str,
        relative: str,
        relative_directory: str,
        directory_fd: int,
        root: Path,
        metadata: os.stat_result,
    ) -> BaselineEntry:
        try:
            target = os.readlink(name, dir_fd=directory_fd)
        except OSError as exc:
            raise BaselineCaptureError("symlink target cannot be read") from exc
        return self._validate_symlink(relative, relative_directory, target, root, metadata)

    @staticmethod
    def _validate_symlink(
        relative: str,
        relative_directory: str,
        target: str,
        root: Path,
        metadata: os.stat_result,
    ) -> BaselineEntry:
        if not isinstance(target, str) or not target or any(ord(char) < 32 for char in target):
            raise BaselineCaptureError("malformed symlink target")
        parent = "" if relative_directory == "." else relative_directory
        if os.path.isabs(target) or (len(target) >= 2 and target[1] == ":"):
            joined = target
        else:
            joined = os.path.join(root.as_posix(), parent, target)
        normalized = os.path.abspath(joined)
        try:
            inside = os.path.commonpath(
                (os.path.abspath(root.as_posix()), normalized)
            ) == os.path.abspath(root.as_posix())
        except ValueError:
            inside = False
        if not inside:
            raise BaselineCaptureError("symlink escapes approved root")
        return BaselineEntry(
            relative,
            "symlink",
            0,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            symlink_target=target,
            classification="excluded-symlink",
        )

    @staticmethod
    def _validate_name(name: str) -> None:
        if (
            not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
        ):
            raise BaselineCaptureError("source filename is unsafe")

    def _relative_child(self, parent: str, name: str) -> str:
        relative = name if parent == "." else f"{parent}/{name}"
        if len(relative.encode("utf-8")) > self.policy.max_path_bytes:
            raise BaselineCaptureError("source path exceeds capture limit")
        path = PurePosixPath(relative)
        if relative != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
            raise BaselineCaptureError("source path is unsafe")
        return relative


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


class _CaptureState:
    def __init__(self, policy: BaselinePolicy) -> None:
        self.policy = policy
        self.entries = 0
        self.total_bytes = 0

    def add_entry(self, _entry: BaselineEntry) -> None:
        self.entries += 1
        if self.entries > self.policy.max_entries:
            raise BaselineCaptureError("source has too many entries")

    def replace_last(self, _entry: BaselineEntry) -> None:
        return

    def add_bytes(self, count: int) -> None:
        self.total_bytes += count
        if self.total_bytes > self.policy.max_total_bytes:
            raise BaselineCaptureError("source exceeds capture byte limit")


__all__ = ["FilesystemBaselineCapturer", "detect_source_type", "read_git_revision"]
