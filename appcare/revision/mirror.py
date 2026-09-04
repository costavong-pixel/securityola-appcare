"""Source-only immutable mirror storage for AppCare P03."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import threading
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .capture import FilesystemBaselineCapturer
from .contracts import (
    BaselineCaptureError,
    BaselineEntry,
    CapturedApplicationRevision,
    MirrorCaptureError,
    MirrorCaptureOutcome,
    MirrorPolicy,
    MirrorReceipt,
    validate_digest,
    validate_identifier,
    validate_root,
)

INTERNAL_MIRROR_ROOT = Path("/var/lib/securityola/appcare/revisions")
_SEAL_MARKER = b"SECURITYOLA_APPCARE_MIRROR_SEALED_V1\n"
_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, threading.RLock] = {}
_SECRET_CONTENT_MARKERS = (
    b"-----begin ",
    b"aws_access_key_id",
    b"authorization: bearer ",
    b"private_key",
    b"password=",
    b"password:",
    b"secret_key",
    b"api_key=",
    b"api-key=",
)
_SECRET_ASSIGNMENT = re.compile(
    rb"(?ix)"
    rb"(?:^|[\s\"'{}\[\](,;])"
    rb"\$?(?:password|passphrase|secret|token|api[_-]?key|client[_-]?secret|"
    rb"private[_-]?key|access[_-]?key|aws[_-]?access[_-]?key[_-]?id|"
    rb"aws[_-]?secret[_-]?access[_-]?key|database[_-]?url|connection[_-]?string|dsn)"
    rb"\$?(?:\s*[\"'])?\s*[:=]\s*(?:[\"'])?"
)
_SECRET_NAME = (
    rb"(?:db[_-]?)?(?:password|passphrase|secret|token|api[_-]?key|"
    rb"client[_-]?secret|private[_-]?key|access[_-]?key|auth[_-]?key|"
    rb"security[_-]?key|encryption[_-]?key|signing[_-]?key|cookie[_-]?key|"
    rb"aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key|"
    rb"database[_-]?url|connection[_-]?string|dsn)"
)
_PHP_SECRET_DEFINE = re.compile(rb"(?ix)\bdefine\s*\(\s*[\"']" + _SECRET_NAME + rb"[\"']\s*,")
_SECRET_CONFIG_KEY = re.compile(
    rb"(?ix)(?:[\"']" + _SECRET_NAME + rb"[\"']|\b" + _SECRET_NAME + rb")"
    rb"\s*(?:=>|[:=])"
)
_SECRET_AUTHORIZATION = re.compile(rb"(?ix)\bauthorization\s*:\s*bearer\s+\S+")
_SECRET_SCAN_CARRY = 8 * 1024
_RESERVED_MIRROR_NAMES = frozenset({"manifest.json", "receipt.json", "SEALED"})
_MAX_MIRROR_ENTRIES = 100_000


class ImmutableSourceMirror:
    """Seal a bounded source-only mirror in a tenant/application namespace."""

    def __init__(
        self, root: Path = INTERNAL_MIRROR_ROOT, *, policy: MirrorPolicy | None = None
    ) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise MirrorCaptureError("mirror root must be absolute")
        try:
            resolved = root.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise MirrorCaptureError("mirror root is unavailable") from exc
        if resolved == Path(resolved.anchor) or resolved != root:
            raise MirrorCaptureError("mirror root is too broad")
        self._validate_mirror_root_ancestry(resolved)
        self.root = resolved
        self.policy = policy or MirrorPolicy()
        self._active_root_fd: int | None = None
        self._active_parent_fd: int | None = None
        self._active_parent_path: Path | None = None
        with _LOCKS_GUARD:
            self._lock = _LOCKS.setdefault(self.root.as_posix(), threading.RLock())

    @classmethod
    def for_test(cls, root: Path, *, policy: MirrorPolicy | None = None) -> ImmutableSourceMirror:
        return cls(root, policy=policy)

    def capture(
        self,
        revision: CapturedApplicationRevision,
        source_root: Path,
    ) -> MirrorCaptureOutcome:
        """Capture through a pinned, trusted mirror-root descriptor on POSIX."""

        if os.name != "posix":
            return self._capture_impl(revision, source_root)
        with self._lock:
            root_fd = self._open_trusted_root(create=True)
            parent_fd = -1
            try:
                parent_fd = self._open_scope_parent(root_fd, revision)
                self._active_root_fd = root_fd
                self._active_parent_fd = parent_fd
                self._active_parent_path = self._scope_path(revision).parent
                return self._capture_impl(revision, source_root)
            finally:
                self._active_root_fd = None
                self._active_parent_fd = None
                self._active_parent_path = None
                if parent_fd >= 0:
                    os.close(parent_fd)
                os.close(root_fd)

    def _capture_impl(
        self,
        revision: CapturedApplicationRevision,
        source_root: Path,
    ) -> MirrorCaptureOutcome:
        if revision.source_type != "direct-filesystem":
            raise MirrorCaptureError("only direct filesystem revisions use this mirror")
        source = self._canonical_source(source_root, revision.approved_root)
        try:
            mirror_root = self.root.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise MirrorCaptureError("mirror root is unavailable") from exc
        if mirror_root == source or mirror_root in source.parents or source in mirror_root.parents:
            raise MirrorCaptureError("mirror root overlaps source root")
        active_capturer = FilesystemBaselineCapturer()
        baseline = active_capturer.capture(source)
        if (
            baseline.root != revision.approved_root
            or baseline.source_type != revision.source_type
            or baseline.manifest_digest != revision.manifest_digest
            or baseline.source_host_identity != revision._source_host_identity
            or baseline.root_identity != revision._source_root_identity
        ):
            raise MirrorCaptureError("source identity or manifest does not match revision")
        final = self._scope_path(revision)
        with self._lock:
            if final.exists() or final.is_symlink():
                raise MirrorCaptureError("mirror replay or overwrite is forbidden")
            parent = final.parent
            self._mkdir_secure(parent)
            claim = parent / f".claim-{revision.baseline_id}"
            try:
                self._create_claim(claim)
            except FileExistsError as exc:
                raise MirrorCaptureError("mirror capture is already active") from exc
            except OSError as exc:
                raise MirrorCaptureError("mirror claim cannot be created") from exc
            # Keep the transient name short enough for hosts that do not have
            # Windows long-path support enabled.  The staging directory is
            # already inside the scope-specific parent, and the UUID keeps it
            # collision-resistant without duplicating the baseline identifier.
            staging = parent / f".staging-{uuid.uuid4().hex}"
            try:
                self._mkdir_exclusive(staging)
            except (MirrorCaptureError, OSError) as exc:
                try:
                    self._unlink_entry(claim)
                except OSError as cleanup_exc:
                    raise MirrorCaptureError("mirror claim cleanup failed") from cleanup_exc
                raise MirrorCaptureError("mirror staging cannot be created") from exc
            committed = False
            try:
                copied: list[dict[str, object]] = []
                bytes_copied = 0
                excluded_files = 0
                for entry in revision.manifest:
                    if entry.entry_type == "directory":
                        if entry.relative_path != "." and entry.classification == "included":
                            self._mkdir_secure(self._destination_path(staging, entry.relative_path))
                        continue
                    if entry.entry_type != "file" or entry.classification != "included":
                        if entry.entry_type == "file":
                            excluded_files += 1
                        continue
                    if not self.policy.allows(entry.relative_path):
                        excluded_files += 1
                        continue
                    if entry.relative_path.rsplit("/", 1)[-1] in _RESERVED_MIRROR_NAMES:
                        raise MirrorCaptureError("source path conflicts with mirror metadata")
                    copied_entry = self._copy_file(
                        source,
                        staging,
                        entry,
                        bytes_already_copied=bytes_copied,
                    )
                    if copied_entry is None:
                        excluded_files += 1
                        continue
                    copied.append(copied_entry)
                    bytes_copied += entry.size_bytes
                    if bytes_copied > self.policy.max_mirror_bytes:
                        raise MirrorCaptureError("mirror exceeds byte limit")
                copied.sort(key=lambda item: str(item["relative_path"]))
                mirror_digest = self._mirror_digest(revision, copied)
                manifest_payload = {
                    "schema_version": 1,
                    "baseline_id": revision.baseline_id,
                    "source_manifest_digest": revision.manifest_digest,
                    "baseline_digest": revision.baseline_digest,
                    "entries": copied,
                    "excluded_file_count": excluded_files,
                    "bytes_copied": bytes_copied,
                    "mirror_digest": mirror_digest,
                }
                self._write_json(
                    staging / "manifest.json",
                    manifest_payload,
                    maximum=self.policy.max_manifest_bytes,
                )
                receipt = MirrorReceipt(
                    tenant_id=revision.tenant_id,
                    application_id=revision.application_id,
                    target_reference=revision.target_reference,
                    baseline_id=revision.baseline_id,
                    mirror_identity=self._mirror_identity(revision),
                    mirror_path=final.as_posix(),
                    source_manifest_digest=revision.manifest_digest,
                    mirror_digest=mirror_digest,
                    file_count=len(copied),
                    bytes_copied=bytes_copied,
                    excluded_file_count=excluded_files,
                    sealed=True,
                    sealed_at=datetime.now(UTC),
                    evidence_class=revision.evidence_class,
                )
                self._write_json(staging / "receipt.json", receipt.as_dict(), maximum=32 * 1024)
                self._write_marker(staging / "SEALED")
                self._seal_permissions(staging)
                self._replace_staging(staging, final)
                committed = True
                try:
                    if self._active_parent_fd is not None:
                        os.fsync(self._active_parent_fd)
                    else:
                        self._fsync_directory(parent)
                    if not self.verify(receipt):
                        raise MirrorCaptureError("mirror readback verification failed")
                except MirrorCaptureError:
                    committed = False
                    self._remove_tree(final)
                    raise
                except OSError as exc:
                    committed = False
                    self._remove_tree(final)
                    raise MirrorCaptureError("mirror durability verification failed") from exc
                try:
                    self._unlink_entry(claim)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    raise MirrorCaptureError("mirror claim cleanup failed") from exc
                try:
                    post = active_capturer.capture(source)
                except (BaselineCaptureError, OSError, ValueError, TypeError, UnicodeError):
                    committed = False
                    self._remove_tree(final)
                    raise MirrorCaptureError(
                        "source changed while mirror was being captured"
                    ) from None
                if (
                    post.manifest_digest != revision.manifest_digest
                    or post.source_host_identity != revision._source_host_identity
                    or post.root_identity != revision._source_root_identity
                ):
                    committed = False
                    self._remove_tree(final)
                    raise MirrorCaptureError(
                        "source identity or contents changed while mirror was being captured"
                    )
                return MirrorCaptureOutcome(
                    revision=revision.with_mirror(receipt=receipt),
                    receipt=receipt,
                )
            except (MirrorCaptureError, BaselineCaptureError):
                raise
            except (OSError, ValueError, TypeError, UnicodeError) as exc:
                raise MirrorCaptureError("mirror capture failed") from exc
            finally:
                if not committed and staging.exists():
                    try:
                        self._remove_tree(staging)
                    except OSError as exc:
                        raise MirrorCaptureError("mirror cleanup failed") from exc
                if claim.exists() or claim.is_symlink():
                    try:
                        self._unlink_entry(claim)
                    except OSError as exc:
                        raise MirrorCaptureError("mirror claim cleanup failed") from exc

    def verify(self, receipt: MirrorReceipt) -> bool:
        """Verify a sealed mirror without trusting a caller-supplied path."""

        final = self._scope_path_from_receipt(receipt)
        expected_identity = self._mirror_identity_values(
            receipt.tenant_id,
            receipt.application_id,
            receipt.target_reference,
            receipt.baseline_id,
        )
        if (
            receipt.mirror_identity != expected_identity
            or final.as_posix() != receipt.mirror_path
            or not self._trusted_mirror_path(final)
        ):
            return False
        try:
            marker = self._read_bounded(final / "SEALED", len(_SEAL_MARKER))
            receipt_raw = self._read_bounded(final / "receipt.json", 32_768)
            manifest_raw = self._read_bounded(
                final / "manifest.json", self.policy.max_manifest_bytes
            )
            receipt_payload = json.loads(receipt_raw.decode("utf-8"))
            manifest_payload = json.loads(manifest_raw.decode("utf-8"))
            if marker != _SEAL_MARKER or receipt_payload != receipt.as_dict():
                return False
            copied = self._verified_manifest_entries(final, manifest_payload, receipt)
            return self._verified_mirror_metadata(final, manifest_payload, copied, receipt)
        except (OSError, ValueError, TypeError, UnicodeError, MirrorCaptureError):
            return False

    def _copy_file(
        self,
        source_root: Path,
        staging: Path,
        entry: BaselineEntry,
        *,
        bytes_already_copied: int,
    ) -> dict[str, object] | None:
        source_path = self._source_path(source_root, entry.relative_path)
        destination = self._destination_path(staging, entry.relative_path)
        if entry.sha256 is None:
            raise MirrorCaptureError("included mirror file has no source digest")
        try:
            source_metadata = source_path.lstat()
        except OSError as exc:
            raise MirrorCaptureError("source file disappeared") from exc
        if not stat.S_ISREG(source_metadata.st_mode) or source_metadata.st_nlink != 1:
            raise MirrorCaptureError("source file is no longer a safe regular file")
        if (
            source_metadata.st_size != entry.size_bytes
            or source_metadata.st_size > self.policy.max_file_bytes
        ):
            raise MirrorCaptureError("source file metadata changed")
        self._mkdir_secure(destination.parent)
        partial = destination.with_name(f".{destination.name}.partial")
        if (
            partial.exists()
            or partial.is_symlink()
            or destination.exists()
            or destination.is_symlink()
        ):
            raise MirrorCaptureError("mirror destination collision")
        digest = hashlib.sha256()
        read_bytes = 0
        secret_window = b""
        secret_found = False
        try:
            source_handle = self._open_source(source_root, entry.relative_path)
            try:
                opened = os.fstat(source_handle.fileno())
                if _source_stat_tuple(source_metadata) != _source_stat_tuple(opened):
                    raise MirrorCaptureError("source file was replaced while mirroring")
                # Scan the complete source stream before creating any
                # destination file.  A second pass copies only after the
                # structured secret policy has cleared the source.
                while True:
                    chunk = source_handle.read(self.policy.chunk_bytes)
                    if not chunk:
                        break
                    read_bytes += len(chunk)
                    if bytes_already_copied + read_bytes > self.policy.max_mirror_bytes:
                        raise MirrorCaptureError("mirror exceeds byte limit")
                    digest.update(chunk)
                    secret_window += chunk
                    if _looks_secret(secret_window):
                        secret_found = True
                    secret_window = secret_window[-_SECRET_SCAN_CARRY:]
                if secret_found:
                    return None
                if read_bytes != entry.size_bytes or digest.hexdigest() != entry.sha256:
                    raise MirrorCaptureError("source file changed while mirroring")
                source_handle.seek(0)
                copied_digest = hashlib.sha256()
                copied_bytes = 0
                with partial.open("xb") as output:
                    while True:
                        chunk = source_handle.read(self.policy.chunk_bytes)
                        if not chunk:
                            break
                        copied_bytes += len(chunk)
                        if (
                            bytes_already_copied + copied_bytes > self.policy.max_mirror_bytes
                            or copied_bytes > self.policy.max_file_bytes
                        ):
                            raise MirrorCaptureError("mirror exceeds byte limit")
                        copied_digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                if copied_bytes != read_bytes or copied_digest.hexdigest() != digest.hexdigest():
                    raise MirrorCaptureError("source file changed while mirroring")
            finally:
                source_handle.close()
            after = source_path.lstat()
        except MirrorCaptureError:
            raise
        except (OSError, UnicodeError) as exc:
            raise MirrorCaptureError("source file copy failed") from exc
        finally:
            if partial.exists() or partial.is_symlink():
                if secret_found:
                    partial.unlink(missing_ok=True)
        if (
            read_bytes != entry.size_bytes
            or digest.hexdigest() != entry.sha256
            or _source_stat_tuple(source_metadata) != _source_stat_tuple(after)
        ):
            raise MirrorCaptureError("source file changed while mirroring")
        os.chmod(partial, 0o400)
        os.replace(partial, destination)
        return {
            "relative_path": entry.relative_path,
            "size_bytes": entry.size_bytes,
            "sha256": entry.sha256,
        }

    def _verified_manifest_entries(
        self,
        final: Path,
        payload: object,
        receipt: MirrorReceipt,
    ) -> list[dict[str, object]]:
        if not isinstance(payload, dict):
            raise MirrorCaptureError("mirror manifest is invalid")
        expected_keys = {
            "schema_version",
            "baseline_id",
            "source_manifest_digest",
            "baseline_digest",
            "entries",
            "excluded_file_count",
            "bytes_copied",
            "mirror_digest",
        }
        if set(payload) != expected_keys:
            raise MirrorCaptureError("mirror manifest schema is invalid")
        if (
            payload["schema_version"] != 1
            or payload["baseline_id"] != receipt.baseline_id
            or payload["source_manifest_digest"] != receipt.source_manifest_digest
            or payload["mirror_digest"] != receipt.mirror_digest
        ):
            raise MirrorCaptureError("mirror manifest binding is invalid")
        entries = payload["entries"]
        if not isinstance(entries, list) or len(entries) > _MAX_MIRROR_ENTRIES:
            raise MirrorCaptureError("mirror entry list is invalid")
        copied: list[dict[str, object]] = []
        seen: set[str] = set()
        for raw in entries:
            if not isinstance(raw, dict) or set(raw) != {"relative_path", "size_bytes", "sha256"}:
                raise MirrorCaptureError("mirror entry schema is invalid")
            relative = raw["relative_path"]
            size_bytes = raw["size_bytes"]
            digest = raw["sha256"]
            if (
                not isinstance(relative, str)
                or relative in seen
                or relative.rsplit("/", 1)[-1] in _RESERVED_MIRROR_NAMES
                or not self.policy.allows(relative)
                or isinstance(size_bytes, bool)
                or not isinstance(size_bytes, int)
                or size_bytes < 0
                or size_bytes > self.policy.max_file_bytes
            ):
                raise MirrorCaptureError("mirror entry values are invalid")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or not all(character in "0123456789abcdef" for character in digest)
            ):
                raise MirrorCaptureError("mirror entry digest is invalid")
            path = self._destination_path(final, relative)
            try:
                metadata = path.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size != size_bytes
                    or path.is_symlink()
                ):
                    raise MirrorCaptureError("mirror file is unsafe")
                actual_digest, secret_found = self._hash_mirror_file(path)
            except OSError as exc:
                raise MirrorCaptureError("mirror file is unavailable") from exc
            if secret_found or actual_digest != digest:
                raise MirrorCaptureError("mirror file digest mismatch")
            copied.append({"relative_path": relative, "size_bytes": size_bytes, "sha256": digest})
            seen.add(relative)
        copied_paths: list[str] = []
        for item in copied:
            relative = item["relative_path"]
            if not isinstance(relative, str):
                raise MirrorCaptureError("mirror entry path is invalid")
            copied_paths.append(relative)
        if copied_paths != sorted(copied_paths):
            raise MirrorCaptureError("mirror entries are not canonical")
        return copied

    def _verified_mirror_metadata(
        self,
        final: Path,
        payload: dict[str, object],
        copied: list[dict[str, object]],
        receipt: MirrorReceipt,
    ) -> bool:
        bytes_copied = payload["bytes_copied"]
        excluded_file_count = payload["excluded_file_count"]
        copied_bytes = 0
        for item in copied:
            size_bytes = item["size_bytes"]
            if not isinstance(size_bytes, int):
                return False
            copied_bytes += size_bytes
        if (
            isinstance(bytes_copied, bool)
            or not isinstance(bytes_copied, int)
            or bytes_copied < 0
            or isinstance(excluded_file_count, bool)
            or not isinstance(excluded_file_count, int)
            or excluded_file_count < 0
            or bytes_copied != copied_bytes
            or len(copied) != receipt.file_count
            or bytes_copied != receipt.bytes_copied
            or excluded_file_count != receipt.excluded_file_count
        ):
            return False
        baseline_digest = payload["baseline_digest"]
        source_manifest_digest = payload["source_manifest_digest"]
        if not isinstance(baseline_digest, str) or not isinstance(source_manifest_digest, str):
            return False
        try:
            validate_digest(baseline_digest, field_name="baseline digest")
            validate_digest(source_manifest_digest, field_name="source manifest digest")
        except ValueError:
            return False
        mirror_digest = self._mirror_digest_values(baseline_digest, source_manifest_digest, copied)
        if mirror_digest != payload["mirror_digest"] or mirror_digest != receipt.mirror_digest:
            return False
        expected_paths = {str(item["relative_path"]) for item in copied}
        expected_paths.update(_RESERVED_MIRROR_NAMES)
        expected_directories = {"."}
        for relative in expected_paths:
            relative_path = PurePosixPath(relative)
            expected_directories.update(
                "/".join(relative_path.parts[:index])
                for index in range(1, len(relative_path.parts))
            )
        for current, directories, files in os.walk(final, topdown=True, followlinks=False):
            current_path = Path(current)
            if os.name == "posix" and stat.S_IMODE(current_path.stat().st_mode) & 0o222:
                return False
            for name in directories:
                child_path = current_path / name
                if child_path.is_symlink() or (
                    os.name == "posix" and stat.S_IMODE(child_path.stat().st_mode) & 0o222
                ):
                    return False
                if child_path.relative_to(final).as_posix() not in expected_directories:
                    return False
            for name in files:
                path = current_path / name
                if path.is_symlink() or (
                    os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o222
                ):
                    return False
                relative = path.relative_to(final).as_posix()
                if relative not in expected_paths:
                    return False
        return True

    @staticmethod
    def _hash_mirror_file(path: Path) -> tuple[str, bool]:
        digest = hashlib.sha256()
        window = b""
        secret_found = False
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                window += chunk.lower()
                if _looks_secret(window):
                    secret_found = True
                window = window[-_SECRET_SCAN_CARRY:]
        return digest.hexdigest(), secret_found

    @staticmethod
    def _open_source(root: Path, relative: str) -> BinaryIO:
        parts = PurePosixPath(relative).parts
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        if os.name != "posix":
            descriptor = os.open(root.joinpath(*parts), flags)
            return os.fdopen(descriptor, "rb", closefd=True)
        directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
        current = os.open(root, directory_flags)
        try:
            for component in parts[:-1]:
                child = os.open(component, directory_flags, dir_fd=current)
                os.close(current)
                current = child
            descriptor = os.open(parts[-1], flags, dir_fd=current)
            return os.fdopen(descriptor, "rb", closefd=True)
        finally:
            os.close(current)

    @staticmethod
    def _trusted_directory_metadata(metadata: os.stat_result) -> bool:
        if not stat.S_ISDIR(metadata.st_mode):
            return False
        if os.name != "posix":
            return True
        current_uid = getattr(os, "getuid", lambda: -1)()
        mode = stat.S_IMODE(metadata.st_mode)
        return metadata.st_uid in {0, current_uid} and (
            not mode & 0o022 or bool(metadata.st_mode & stat.S_ISVTX)
        )

    @classmethod
    def _validate_mirror_root_ancestry(cls, root: Path) -> None:
        """Reject symlinked or writable mirror ancestry before any writes."""

        if os.name != "posix":
            return
        current = Path(root.anchor)
        for component in root.parts[1:]:
            current /= component
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                break
            except OSError as exc:
                raise MirrorCaptureError("mirror root ancestry is unavailable") from exc
            if stat.S_ISLNK(metadata.st_mode) or not cls._trusted_directory_metadata(metadata):
                raise MirrorCaptureError("mirror root ancestry is untrusted")

    @staticmethod
    def _open_directory_descriptor(path: Path) -> int:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(path, flags)
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise MirrorCaptureError("mirror directory cannot be opened safely") from exc
        if not ImmutableSourceMirror._trusted_directory_metadata(metadata):
            os.close(descriptor)
            raise MirrorCaptureError("mirror directory trust validation failed")
        return descriptor

    def _open_trusted_root(self, *, create: bool) -> int:
        if create:
            self._mkdir_secure(self.root)
        self._validate_mirror_root_ancestry(self.root)
        return self._open_directory_descriptor(self.root)

    @classmethod
    def _mkdir_relative(cls, root_fd: int, parts: tuple[str, ...]) -> None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        current = os.dup(root_fd)
        try:
            for component in parts:
                if not component or component in {".", ".."} or "/" in component:
                    raise MirrorCaptureError("mirror directory component is unsafe")
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                try:
                    child = os.open(component, flags, dir_fd=current)
                except OSError as exc:
                    raise MirrorCaptureError("mirror directory cannot be opened safely") from exc
                try:
                    if not cls._trusted_directory_metadata(os.fstat(child)):
                        raise MirrorCaptureError("mirror directory trust validation failed")
                except MirrorCaptureError:
                    os.close(child)
                    raise
                os.close(current)
                current = child
        finally:
            os.close(current)

    def _open_scope_parent(self, root_fd: int, revision: CapturedApplicationRevision) -> int:
        parts = tuple(
            self._validate_scope_path_identifier(value, field_name=name)
            for value, name in (
                (revision.tenant_id, "tenant_id"),
                (revision.application_id, "application_id"),
                (revision.target_reference, "target_reference"),
            )
        )
        self._mkdir_relative(root_fd, parts)
        current = os.dup(root_fd)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            for component in parts:
                child = os.open(component, flags, dir_fd=current)
                os.close(current)
                current = child
            return current
        except OSError as exc:
            os.close(current)
            raise MirrorCaptureError("mirror scope cannot be pinned") from exc

    def _trusted_mirror_path(self, path: Path) -> bool:
        if os.name != "posix":
            return path.is_dir() and not path.is_symlink()
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            return False
        root_fd: int | None = self._active_root_fd
        owns_root_fd = root_fd is None
        try:
            if root_fd is None:
                root_fd = self._open_trusted_root(create=False)
            parts = tuple(relative.parts)
            descriptor = os.dup(root_fd)
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                for component in parts:
                    child = os.open(component, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                return self._trusted_directory_metadata(os.fstat(descriptor))
            finally:
                os.close(descriptor)
        except (OSError, MirrorCaptureError, ValueError):
            return False
        finally:
            if owns_root_fd and root_fd is not None:
                os.close(root_fd)

    def _mkdir_exclusive(self, path: Path) -> None:
        if os.name == "posix" and self._active_parent_fd is not None:
            try:
                os.mkdir(path.name, 0o700, dir_fd=self._active_parent_fd)
            except FileExistsError as exc:
                raise MirrorCaptureError("mirror staging collision") from exc
            return
        try:
            path.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise MirrorCaptureError("mirror staging collision") from exc

    def _create_claim(self, path: Path) -> None:
        if os.name == "posix" and self._active_parent_fd is not None:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                descriptor = os.open(path.name, flags, 0o600, dir_fd=self._active_parent_fd)
            except FileExistsError as exc:
                raise MirrorCaptureError("mirror capture is already active") from exc
            except OSError as exc:
                raise MirrorCaptureError("mirror claim cannot be created") from exc
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return
        with path.open("xb") as handle:
            handle.flush()
            os.fsync(handle.fileno())

    def _unlink_entry(self, path: Path) -> None:
        if os.name == "posix" and self._active_parent_fd is not None:
            try:
                os.unlink(path.name, dir_fd=self._active_parent_fd)
            except FileNotFoundError:
                pass
            return
        path.unlink()

    def _replace_staging(self, staging: Path, final: Path) -> None:
        if os.name == "posix" and self._active_parent_fd is not None:
            try:
                os.replace(
                    staging.name,
                    final.name,
                    src_dir_fd=self._active_parent_fd,
                    dst_dir_fd=self._active_parent_fd,
                )
            except OSError as exc:
                raise MirrorCaptureError("mirror promotion failed") from exc
            return
        os.replace(staging, final)

    def _scope_path(self, revision: CapturedApplicationRevision) -> Path:
        return self._scope_path_values(
            revision.tenant_id,
            revision.application_id,
            revision.target_reference,
            revision.baseline_id,
        )

    def _scope_path_from_receipt(self, receipt: MirrorReceipt) -> Path:
        return self._scope_path_values(
            receipt.tenant_id,
            receipt.application_id,
            receipt.target_reference,
            receipt.baseline_id,
        )

    def _scope_path_values(
        self,
        tenant_id: str,
        application_id: str,
        target_reference: str,
        baseline_id: str,
    ) -> Path:
        parts = tuple(
            self._validate_scope_path_identifier(value, field_name=name)
            for value, name in (
                (tenant_id, "tenant_id"),
                (application_id, "application_id"),
                (target_reference, "target_reference"),
                (baseline_id, "baseline_id"),
            )
        )
        candidate = self.root.joinpath(*parts)
        if candidate != self.root and self.root not in candidate.parents:
            raise MirrorCaptureError("mirror scope escaped root")
        return candidate

    @staticmethod
    def _validate_scope_path_identifier(value: str, *, field_name: str) -> str:
        normalized = validate_identifier(value, field_name=field_name)
        if os.name == "nt" and ":" in normalized:
            raise MirrorCaptureError(f"{field_name} is not a safe path segment")
        return normalized

    @staticmethod
    def _canonical_source(source_root: Path, approved_root: str) -> Path:
        if not isinstance(source_root, Path) or not source_root.is_absolute():
            raise MirrorCaptureError("source root must be absolute")
        try:
            lexical_metadata = source_root.lstat()
            if not stat.S_ISDIR(lexical_metadata.st_mode) or source_root.is_symlink():
                raise MirrorCaptureError("source root is not a real directory")
            source = source_root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise MirrorCaptureError("source root is unavailable") from exc
        if source.as_posix() != validate_root(approved_root):
            raise MirrorCaptureError("source root does not match revision")
        if os.name == "posix" and source != source_root:
            raise MirrorCaptureError("source root crosses a symlink")
        if not source.is_dir() or source.is_symlink():
            raise MirrorCaptureError("source root is not a real directory")
        return source

    @staticmethod
    def _source_path(root: Path, relative: str) -> Path:
        if relative == ".":
            raise MirrorCaptureError("root cannot be copied as a file")
        path = PurePosixPath(relative)
        if any(part in {"", ".", ".."} for part in path.parts) or "\\" in relative:
            raise MirrorCaptureError("source path is unsafe")
        candidate = root.joinpath(*path.parts)
        if root not in candidate.parents:
            raise MirrorCaptureError("source path escaped root")
        return candidate

    @staticmethod
    def _destination_path(root: Path, relative: str) -> Path:
        if relative == ".":
            return root
        path = PurePosixPath(relative)
        if any(part in {"", ".", ".."} for part in path.parts) or "\\" in relative:
            raise MirrorCaptureError("destination path is unsafe")
        candidate = root.joinpath(*path.parts)
        if root not in candidate.parents:
            raise MirrorCaptureError("destination path escaped mirror")
        return candidate

    def _mkdir_secure(self, path: Path) -> None:
        if os.name == "posix":
            if path != self.root and self.root not in path.parents:
                raise MirrorCaptureError("mirror directory escaped root")
            if self._active_root_fd is not None:
                try:
                    relative = path.relative_to(self.root)
                except ValueError as exc:
                    raise MirrorCaptureError("mirror directory escaped root") from exc
                self._mkdir_relative(self._active_root_fd, tuple(relative.parts))
                return
            self._validate_mirror_root_ancestry(self.root)
            anchor_fd = self._open_directory_descriptor(Path(path.anchor))
            try:
                self._mkdir_relative(anchor_fd, tuple(path.parts[1:]))
            finally:
                os.close(anchor_fd)
            return
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_dir():
                raise MirrorCaptureError("mirror directory is unsafe")
            return
        parent = path.parent
        if parent != path:
            self._mkdir_secure(parent)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            if path.is_symlink() or not path.is_dir():
                raise MirrorCaptureError("mirror directory is unsafe") from None

    @staticmethod
    def _write_json(path: Path, payload: dict[str, object], *, maximum: int) -> None:
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        if len(encoded) > maximum:
            raise MirrorCaptureError("mirror metadata is too large")
        with path.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o400)

    @staticmethod
    def _write_marker(path: Path) -> None:
        with path.open("xb") as handle:
            handle.write(_SEAL_MARKER)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o400)

    @staticmethod
    def _mirror_identity(revision: CapturedApplicationRevision) -> str:
        return ImmutableSourceMirror._mirror_identity_values(
            revision.tenant_id,
            revision.application_id,
            revision.target_reference,
            revision.baseline_id,
        )

    @staticmethod
    def _mirror_identity_values(
        tenant_id: str,
        application_id: str,
        target_reference: str,
        baseline_id: str,
    ) -> str:
        return f"mirror://{tenant_id}/{application_id}/{target_reference}/{baseline_id}"

    @staticmethod
    def _mirror_digest(
        revision: CapturedApplicationRevision, copied: Iterable[dict[str, object]]
    ) -> str:
        return ImmutableSourceMirror._mirror_digest_values(
            revision.baseline_digest, revision.manifest_digest, copied
        )

    @staticmethod
    def _mirror_digest_values(
        baseline_digest: str,
        source_manifest_digest: str,
        copied: Iterable[dict[str, object]],
    ) -> str:
        payload = {
            "baseline_digest": baseline_digest,
            "source_manifest_digest": source_manifest_digest,
            "entries": list(copied),
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _seal_permissions(root: Path) -> None:
        for current, directories, files in os.walk(root, topdown=False, followlinks=False):
            current_path = Path(current)
            for name in files:
                path = current_path / name
                if path.is_symlink():
                    raise MirrorCaptureError("mirror contains a symlink")
                os.chmod(path, 0o400)
            for name in directories:
                path = current_path / name
                if path.is_symlink():
                    raise MirrorCaptureError("mirror contains a symlink")
                os.chmod(path, 0o500)
        os.chmod(root, 0o500)

    @staticmethod
    def _remove_tree(path: Path) -> None:
        if path.is_symlink() or not path.exists():
            if path.is_symlink():
                path.unlink()
            return
        for current, directories, files in os.walk(path, topdown=False, followlinks=False):
            current_path = Path(current)
            for name in files:
                child = current_path / name
                if not child.is_symlink():
                    os.chmod(child, 0o700)
            for name in directories:
                child = current_path / name
                if not child.is_symlink():
                    os.chmod(child, 0o700)
        os.chmod(path, 0o700)
        shutil.rmtree(path)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name != "posix":
            return
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _read_bounded(path: Path, maximum: int) -> bytes:
        if maximum < 0:
            raise OSError("mirror metadata limit is invalid")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("mirror metadata is not a regular file")
            chunks = bytearray()
            while len(chunks) <= maximum:
                chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(chunks)))
                if not chunk:
                    return bytes(chunks)
                chunks.extend(chunk)
            raise OSError("mirror metadata is too large")
        finally:
            os.close(descriptor)


def _source_stat_tuple(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
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


def _looks_secret(window: bytes) -> bool:
    lowered = window.lower()
    return any(marker in lowered for marker in _SECRET_CONTENT_MARKERS) or any(
        pattern.search(window) is not None
        for pattern in (
            _SECRET_ASSIGNMENT,
            _PHP_SECRET_DEFINE,
            _SECRET_CONFIG_KEY,
            _SECRET_AUTHORIZATION,
        )
    )


__all__ = ["INTERNAL_MIRROR_ROOT", "ImmutableSourceMirror"]
