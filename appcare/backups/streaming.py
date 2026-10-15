"""Bounded, authenticated chunk artifacts for filesystem backups.

The legacy backup coordinator intentionally remains an in-memory fixture path.
This module is the repository-side contract for large filesystem captures: a
source is observed once, each safe file is encrypted in bounded chunks, and a
reserved artifact directory becomes readable only after every chunk and the
final manifest have been verified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..services.security import is_safe_credential_reference
from .contracts import BackupBoundaryError, BackupTarget, utc, validate_backup_id
from .filesystem import (
    FilesystemCapture,
    FilesystemEntry,
    FilesystemEntryClass,
)
from .paths import BackupFilesystemBoundary


class StreamingBackupError(BackupBoundaryError):
    """A chunked backup artifact failed closed."""


_SCHEMA_VERSION: Final = 1
_ALGORITHM: Final = "AES-256-GCM-CHUNKED"
_MAX_MANIFEST_BYTES: Final = 32 * 1024 * 1024
_MAX_CHUNKS: Final = 1_000_000
_MAX_CHUNK_BYTES: Final = 8 * 1024 * 1024
_MAX_TOTAL_BYTES: Final = 2 * 1024 * 1024 * 1024
_CHUNK_FILE = re.compile(r"^[0-9]{12}\.bin$")
_SAFE_SOURCE_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_COMPLETE_MARKER = b"securityola-appcare-streaming-complete-v1\n"


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise StreamingBackupError(f"{field} is invalid")
    if any(character not in "0123456789abcdef" for character in value.casefold()):
        raise StreamingBackupError(f"{field} is invalid")
    return value.casefold()


def _validate_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise StreamingBackupError("streaming encryption key must be 32 bytes")
    return key


def _manifest_authentication(key: bytes, manifest_bytes: bytes) -> str:
    mac_key = hashlib.sha256(b"securityola-appcare-streaming-manifest\x00" + key).digest()
    return hmac.new(mac_key, manifest_bytes, hashlib.sha256).hexdigest()


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise StreamingBackupError("streaming entry path is invalid")
    parts = value.split("/")
    if value == ".":
        return value
    if any(not part or part in {".", ".."} for part in parts):
        raise StreamingBackupError("streaming entry path escapes the source root")
    return value


def _write_private(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(
            os.fspath(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise StreamingBackupError("streaming artifact file cannot be created") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise StreamingBackupError("streaming artifact file cannot be finalized") from exc


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(parents=False, exist_ok=False, mode=0o700)
        path.chmod(0o700)
    except OSError as exc:
        raise StreamingBackupError("streaming artifact directory cannot be created") from exc


def _reserve_private_directory(path: Path) -> None:
    """Reserve a final artifact directory without an overwrite race.

    The directory is intentionally visible while it is being assembled, but
    it is not a readable artifact until the complete marker is written. Using
    mkdir with ``exist_ok=False`` makes same-ID publication a no-replace
    operation instead of a check followed by overwrite-capable rename.
    """

    try:
        path.mkdir(parents=False, exist_ok=False, mode=0o700)
        path.chmod(0o700)
    except OSError as exc:
        raise StreamingBackupError("streaming artifact directory cannot be reserved") from exc


@dataclass(frozen=True, slots=True)
class ChunkedBackupLimits:
    """Hard caps for a chunked artifact; callers may only lower them."""

    chunk_bytes: int = 1024 * 1024
    max_chunks: int = _MAX_CHUNKS
    max_total_bytes: int = _MAX_TOTAL_BYTES
    max_manifest_bytes: int = _MAX_MANIFEST_BYTES

    def __post_init__(self) -> None:
        for name, value, upper in (
            ("chunk_bytes", self.chunk_bytes, _MAX_CHUNK_BYTES),
            ("max_chunks", self.max_chunks, _MAX_CHUNKS),
            ("max_total_bytes", self.max_total_bytes, _MAX_TOTAL_BYTES),
            ("max_manifest_bytes", self.max_manifest_bytes, _MAX_MANIFEST_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= upper:
                raise StreamingBackupError(f"{name} is outside bounds")


@dataclass(frozen=True, slots=True)
class ChunkedBackupRequest:
    """Immutable scope and source binding for one streaming artifact."""

    backup_id: str
    target: BackupTarget
    source_revision: str
    source_manifest_digest: str
    key_reference: str
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "backup_id", validate_backup_id(self.backup_id))
        if not isinstance(self.target.target_reference, str) or not self.target.target_reference:
            raise StreamingBackupError("streaming target reference is required")
        if (
            not isinstance(self.source_revision, str)
            or _SAFE_SOURCE_REVISION.fullmatch(self.source_revision) is None
            or ".." in self.source_revision
            or any(character.isspace() or ord(character) < 32 for character in self.source_revision)
        ):
            raise StreamingBackupError("source revision is invalid")
        object.__setattr__(
            self,
            "source_manifest_digest",
            _validate_digest(self.source_manifest_digest, field="source manifest digest"),
        )
        if not is_safe_credential_reference(self.key_reference):
            raise StreamingBackupError("streaming key reference is unsafe")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise StreamingBackupError("streaming capture timestamp must be timezone-aware")


class StreamingBackupSource(Protocol):
    """The bounded source contract consumed by :class:`ChunkedBackupWriter`."""

    def capture(self, target: BackupTarget) -> FilesystemCapture:
        """Return metadata and content digests without retaining file payloads."""

    def iter_file_chunks(self, target: BackupTarget, entry: FilesystemEntry) -> Iterator[bytes]:
        """Yield bounded plaintext chunks for one safe file."""


@dataclass(frozen=True, slots=True)
class ChunkRecord:
    entry_path: str
    sequence: int
    plaintext_size: int
    ciphertext_size: int
    ciphertext_sha256: str
    filename: str

    def as_dict(self) -> dict[str, object]:
        return {
            "entry_path": self.entry_path,
            "sequence": self.sequence,
            "plaintext_size": self.plaintext_size,
            "ciphertext_size": self.ciphertext_size,
            "ciphertext_sha256": self.ciphertext_sha256,
            "filename": self.filename,
        }


@dataclass(frozen=True, slots=True)
class ChunkedBackupArtifact:
    """A sealed, path-backed streaming artifact."""

    path: Path
    manifest_digest: str
    artifact_digest: str
    backup_id: str
    tenant_id: str
    application_id: str


def _entry_payload(entry: FilesystemEntry) -> dict[str, object]:
    payload = entry.as_dict()
    payload["relative_path"] = _validate_relative_path(payload["relative_path"])
    return payload


def _chunk_aad(
    request: ChunkedBackupRequest,
    capture_digest: str,
    entry_path: str,
    sequence: int,
    size: int,
) -> bytes:
    return _canonical_json(
        {
            "schema_version": _SCHEMA_VERSION,
            "algorithm": _ALGORITHM,
            "backup_id": request.backup_id,
            "tenant_id": request.target.tenant_id,
            "application_id": request.target.application_id,
            "target_reference": request.target.target_reference,
            "source_reference": request.target.source_reference,
            "source_revision": request.source_revision,
            "source_manifest_digest": request.source_manifest_digest,
            "capture_manifest_digest": capture_digest,
            "entry_path": entry_path,
            "sequence": sequence,
            "plaintext_size": size,
        }
    )


def _chunk_nonce(aad: bytes) -> bytes:
    return hashlib.sha256(b"securityola-appcare-chunk-nonce\x00" + aad).digest()[:12]


def _artifact_digest(manifest_bytes: bytes, chunks: tuple[ChunkRecord, ...]) -> str:
    payload = (
        manifest_bytes + b"\n" + b"\n".join(_canonical_json(record.as_dict()) for record in chunks)
    )
    return _digest(payload)


class ChunkedBackupWriter:
    """Encrypt and atomically seal one bounded filesystem artifact."""

    def __init__(
        self,
        filesystem: BackupFilesystemBoundary,
        key: bytes,
        *,
        limits: ChunkedBackupLimits | None = None,
    ) -> None:
        self.filesystem = filesystem
        self._key = _validate_key(key)
        self.limits = limits or ChunkedBackupLimits()

    def write(
        self,
        request: ChunkedBackupRequest,
        *,
        source: StreamingBackupSource,
    ) -> ChunkedBackupArtifact:
        if not callable(getattr(source, "capture", None)) or not callable(
            getattr(source, "iter_file_chunks", None)
        ):
            raise StreamingBackupError("streaming source contract is unavailable")
        self.filesystem.ensure_data_dirs()
        final_path = self.filesystem.staging_path(request.backup_id)
        _reserve_private_directory(final_path)
        chunk_path = final_path / "chunks"
        committed = False
        try:
            _ensure_private_directory(chunk_path)
            capture = source.capture(request.target)
            self._validate_capture(capture, request)
            entries = tuple(sorted(capture.entries, key=lambda entry: entry.relative_path))
            manifest_base = {
                "schema_version": _SCHEMA_VERSION,
                "algorithm": _ALGORITHM,
                "backup_id": request.backup_id,
                "tenant_id": request.target.tenant_id,
                "application_id": request.target.application_id,
                "target_reference": request.target.target_reference,
                "source_reference": request.target.source_reference,
                "source_revision": request.source_revision,
                "source_manifest_digest": request.source_manifest_digest,
                "capture_manifest_digest": capture.manifest_digest,
                "created_at": utc(request.created_at).isoformat(),
                "key_reference": request.key_reference,
                "entries": [_entry_payload(entry) for entry in entries],
                "chunks": [],
                # Reserve the maximum decimal width while projecting the
                # manifest budget; the final value is replaced with the exact
                # captured total after all chunks are accepted.
                "total_plaintext_bytes": self.limits.max_total_bytes,
            }
            manifest_base_bytes = _canonical_json(manifest_base)
            if len(manifest_base_bytes) > self.limits.max_manifest_bytes:
                raise StreamingBackupError("streaming manifest exceeds size limit")
            projected_chunk_bytes = 2
            records: list[ChunkRecord] = []
            total_bytes = 0
            for entry in entries:
                if entry.classification is not FilesystemEntryClass.SAFE_FILE:
                    continue
                if entry.sha256 is None:
                    raise StreamingBackupError("safe file is missing a content digest")
                file_total = 0
                file_digest = hashlib.sha256()
                for sequence, plaintext in enumerate(
                    source.iter_file_chunks(request.target, entry)
                ):
                    if not isinstance(plaintext, bytes) or not plaintext:
                        raise StreamingBackupError("streaming source returned an invalid chunk")
                    if len(plaintext) > self.limits.chunk_bytes:
                        raise StreamingBackupError("streaming source exceeded chunk limit")
                    file_total += len(plaintext)
                    total_bytes += len(plaintext)
                    if file_total > entry.size_bytes or total_bytes > self.limits.max_total_bytes:
                        raise StreamingBackupError("streaming artifact exceeds size limit")
                    file_digest.update(plaintext)
                    if len(records) >= self.limits.max_chunks:
                        raise StreamingBackupError("streaming artifact exceeds chunk limit")
                    aad = _chunk_aad(
                        request,
                        capture.manifest_digest,
                        entry.relative_path,
                        sequence,
                        len(plaintext),
                    )
                    ciphertext = AESGCM(self._key).encrypt(_chunk_nonce(aad), plaintext, aad)
                    filename = f"{len(records):012d}.bin"
                    record = ChunkRecord(
                        entry.relative_path,
                        sequence,
                        len(plaintext),
                        len(ciphertext),
                        _digest(ciphertext),
                        filename,
                    )
                    next_projected_chunk_bytes = projected_chunk_bytes + len(
                        _canonical_json(record.as_dict())
                    )
                    if records:
                        next_projected_chunk_bytes += 1
                    if (
                        len(manifest_base_bytes) - 2 + next_projected_chunk_bytes
                        > self.limits.max_manifest_bytes
                    ):
                        raise StreamingBackupError("streaming manifest exceeds size limit")
                    _write_private(chunk_path / filename, ciphertext)
                    records.append(record)
                    projected_chunk_bytes = next_projected_chunk_bytes
                if file_total != entry.size_bytes or file_digest.hexdigest() != entry.sha256:
                    raise StreamingBackupError("source file changed during streaming capture")

            manifest = dict(manifest_base)
            manifest["chunks"] = [record.as_dict() for record in records]
            manifest["total_plaintext_bytes"] = total_bytes
            manifest_bytes = _canonical_json(manifest)
            if len(manifest_bytes) > self.limits.max_manifest_bytes:
                raise StreamingBackupError("streaming manifest exceeds size limit")
            manifest_digest = _digest(manifest_bytes)
            artifact_digest = _artifact_digest(manifest_bytes, tuple(records))
            _write_private(final_path / "manifest.json", manifest_bytes)
            _write_private(final_path / "artifact.sha256", artifact_digest.encode("ascii"))
            _write_private(
                final_path / "seal.json",
                _canonical_json(
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "manifest_digest": manifest_digest,
                        "artifact_digest": artifact_digest,
                        "manifest_authentication": _manifest_authentication(
                            self._key, manifest_bytes
                        ),
                    }
                ),
            )
            _write_private(final_path / "COMPLETE", _COMPLETE_MARKER)
            self._fsync_directory(final_path)
            self._fsync_directory(final_path.parent)
            committed = True
            return ChunkedBackupArtifact(
                final_path,
                manifest_digest,
                artifact_digest,
                request.backup_id,
                request.target.tenant_id,
                request.target.application_id,
            )
        finally:
            if not committed and final_path.exists() and not final_path.is_symlink():
                shutil.rmtree(final_path, ignore_errors=True)

    @staticmethod
    def _validate_capture(capture: FilesystemCapture, request: ChunkedBackupRequest) -> None:
        if not isinstance(capture, FilesystemCapture) or not capture.entries:
            raise StreamingBackupError("streaming source returned no capture")
        _validate_digest(capture.manifest_digest, field="streaming source capture digest")
        if (
            isinstance(capture.root_device, bool)
            or not isinstance(capture.root_device, int)
            or capture.root_device < 0
            or isinstance(capture.root_inode, bool)
            or not isinstance(capture.root_inode, int)
            or capture.root_inode < 1
            or isinstance(capture.included_bytes, bool)
            or not isinstance(capture.included_bytes, int)
            or capture.included_bytes < 0
        ):
            raise StreamingBackupError("streaming source root or size metadata is invalid")
        paths = tuple(entry.relative_path for entry in capture.entries)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise StreamingBackupError("streaming source manifest is not deterministic")
        if len(paths) > _MAX_CHUNKS:
            raise StreamingBackupError("streaming source entry limit exceeded")
        if capture.root != request.target.source_reference:
            raise StreamingBackupError("streaming source root does not match target")
        included_bytes = sum(
            entry.size_bytes
            for entry in capture.entries
            if entry.classification is FilesystemEntryClass.SAFE_FILE
        )
        if included_bytes != capture.included_bytes or included_bytes > _MAX_TOTAL_BYTES:
            raise StreamingBackupError("streaming source size metadata is inconsistent")

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        try:
            descriptor = os.open(os.fspath(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError as exc:
            if os.name == "nt":
                return
            raise StreamingBackupError("streaming artifact directory cannot be synced") from exc
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if os.name != "nt":
                raise StreamingBackupError("streaming artifact directory cannot be synced") from exc
        finally:
            os.close(descriptor)


class ChunkedBackupReader:
    """Verify and stream plaintext from one sealed artifact."""

    def __init__(
        self,
        filesystem: BackupFilesystemBoundary,
        key: bytes,
        *,
        limits: ChunkedBackupLimits | None = None,
    ) -> None:
        self.filesystem = filesystem
        self._key = _validate_key(key)
        self.limits = limits or ChunkedBackupLimits()

    def iter_file_chunks(
        self,
        artifact: ChunkedBackupArtifact,
        request: ChunkedBackupRequest,
        entry_path: str,
    ) -> Iterator[bytes]:
        manifest, manifest_bytes, records = self._load(artifact, request)
        _validate_relative_path(entry_path)
        expected = [record for record in records if record.entry_path == entry_path]
        if not expected:
            manifest_entries = manifest.get("entries")
            if not isinstance(manifest_entries, list):
                raise StreamingBackupError("streaming artifact entries are malformed")
            entries: dict[str, Mapping[str, object]] = {}
            for payload in manifest_entries:
                if isinstance(payload, Mapping) and isinstance(payload.get("relative_path"), str):
                    entries[payload["relative_path"]] = payload
            entry = entries.get(entry_path)
            if not isinstance(entry, Mapping) or entry.get("classification") != "safe_file":
                raise StreamingBackupError("requested artifact entry is not a safe file")
            if entry.get("size_bytes") != 0:
                raise StreamingBackupError("artifact is missing file chunks")
            return
        for record in expected:
            ciphertext = self._read_chunk(artifact.path, record)
            aad = _chunk_aad(
                request,
                str(manifest["capture_manifest_digest"]),
                record.entry_path,
                record.sequence,
                record.plaintext_size,
            )
            try:
                plaintext = AESGCM(self._key).decrypt(_chunk_nonce(aad), ciphertext, aad)
            except InvalidTag as exc:
                raise StreamingBackupError("streaming chunk authentication failed") from exc
            if len(plaintext) != record.plaintext_size:
                raise StreamingBackupError("streaming chunk size mismatch")
            yield plaintext

    def _load(
        self,
        artifact: ChunkedBackupArtifact,
        request: ChunkedBackupRequest,
    ) -> tuple[dict[str, object], bytes, tuple[ChunkRecord, ...]]:
        expected_path = self.filesystem.staging_path(request.backup_id)
        if artifact.path != expected_path or artifact.path.is_symlink():
            raise StreamingBackupError("streaming artifact path is outside the AppCare boundary")
        if not artifact.path.is_dir() or (
            os.name == "posix" and artifact.path.stat().st_mode & stat.S_IWOTH
        ):
            raise StreamingBackupError("streaming artifact directory is unsafe")
        manifest_path = artifact.path / "manifest.json"
        seal_path = artifact.path / "seal.json"
        digest_path = artifact.path / "artifact.sha256"
        complete_path = artifact.path / "COMPLETE"
        for path in (manifest_path, seal_path, digest_path, complete_path):
            if path.is_symlink() or not path.is_file():
                raise StreamingBackupError("streaming artifact seal is incomplete")
        try:
            if self._read_bounded(complete_path, len(_COMPLETE_MARKER)) != _COMPLETE_MARKER:
                raise StreamingBackupError("streaming artifact completion marker is invalid")
            manifest_bytes = self._read_bounded(manifest_path, self.limits.max_manifest_bytes)
            seal = json.loads(self._read_bounded(seal_path, 4096).decode("utf-8"))
            artifact_digest = self._read_bounded(digest_path, 128).decode("ascii").strip()
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, StreamingBackupError) as exc:
            raise StreamingBackupError("streaming artifact metadata is malformed") from exc
        if _canonical_json(manifest) != manifest_bytes:
            raise StreamingBackupError("streaming manifest is not canonical")
        manifest_digest = _digest(manifest_bytes)
        if not isinstance(seal, dict) or seal.get("manifest_digest") != manifest_digest:
            raise StreamingBackupError("streaming manifest seal mismatch")
        if seal.get("manifest_authentication") != _manifest_authentication(
            self._key, manifest_bytes
        ):
            raise StreamingBackupError("streaming manifest authentication failed")
        if (
            artifact_digest != artifact.artifact_digest
            or seal.get("artifact_digest") != artifact_digest
        ):
            raise StreamingBackupError("streaming artifact digest mismatch")
        if manifest_digest != artifact.manifest_digest:
            raise StreamingBackupError("streaming manifest digest mismatch")
        if (
            manifest.get("schema_version") != _SCHEMA_VERSION
            or manifest.get("algorithm") != _ALGORITHM
            or manifest.get("backup_id") != request.backup_id
            or manifest.get("tenant_id") != request.target.tenant_id
            or manifest.get("application_id") != request.target.application_id
            or manifest.get("target_reference") != request.target.target_reference
            or manifest.get("source_reference") != request.target.source_reference
            or manifest.get("source_revision") != request.source_revision
            or manifest.get("source_manifest_digest") != request.source_manifest_digest
            or manifest.get("key_reference") != request.key_reference
        ):
            raise StreamingBackupError("streaming artifact scope binding mismatch")
        if len(manifest_bytes) > self.limits.max_manifest_bytes:
            raise StreamingBackupError("streaming manifest exceeds size limit")
        entries = manifest.get("entries")
        chunks_payload = manifest.get("chunks")
        if not isinstance(entries, list) or not isinstance(chunks_payload, list):
            raise StreamingBackupError("streaming artifact manifest is malformed")
        if len(entries) > self.limits.max_chunks:
            raise StreamingBackupError("streaming artifact entry limit exceeded")
        entry_map: dict[str, Mapping[str, object]] = {}
        entry_paths: list[str] = []
        for payload in entries:
            if not isinstance(payload, dict):
                raise StreamingBackupError("streaming entry record is malformed")
            entry_path = _validate_relative_path(payload.get("relative_path"))
            if entry_path in entry_map:
                raise StreamingBackupError("streaming entry record is duplicated")
            entry_map[entry_path] = payload
            entry_paths.append(entry_path)
        if entry_paths != sorted(entry_paths):
            raise StreamingBackupError("streaming entries are not deterministically ordered")
        if len(chunks_payload) > self.limits.max_chunks:
            raise StreamingBackupError("streaming artifact exceeds chunk limit")
        records: list[ChunkRecord] = []
        for payload in chunks_payload:
            if not isinstance(payload, dict):
                raise StreamingBackupError("streaming chunk record is malformed")
            try:
                record = ChunkRecord(
                    _validate_relative_path(payload["entry_path"]),
                    payload["sequence"],
                    payload["plaintext_size"],
                    payload["ciphertext_size"],
                    _validate_digest(payload["ciphertext_sha256"], field="chunk digest"),
                    payload["filename"],
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise StreamingBackupError("streaming chunk record is malformed") from exc
            if (
                isinstance(record.sequence, bool)
                or not isinstance(record.sequence, int)
                or isinstance(record.plaintext_size, bool)
                or not isinstance(record.plaintext_size, int)
                or isinstance(record.ciphertext_size, bool)
                or not isinstance(record.ciphertext_size, int)
                or record.sequence < 0
                or record.plaintext_size < 1
                or record.plaintext_size > self.limits.chunk_bytes
                or record.ciphertext_size != record.plaintext_size + 16
                or not isinstance(record.filename, str)
                or _CHUNK_FILE.fullmatch(record.filename) is None
            ):
                raise StreamingBackupError("streaming chunk record is outside bounds")
            entry = entry_map.get(record.entry_path)
            if entry is None or entry.get("classification") != FilesystemEntryClass.SAFE_FILE.value:
                raise StreamingBackupError("streaming chunk is not bound to a safe file")
            records.append(record)
        ordered = tuple(sorted(records, key=lambda record: (record.entry_path, record.sequence)))
        if ordered != tuple(records) or len({record.filename for record in records}) != len(
            records
        ):
            raise StreamingBackupError("streaming chunks are not deterministically ordered")
        total_plaintext = 0
        for entry_path, entry in entry_map.items():
            entry_size = entry.get("size_bytes")
            if isinstance(entry_size, bool) or not isinstance(entry_size, int) or entry_size < 0:
                raise StreamingBackupError("streaming entry size is invalid")
            path_records = [record for record in records if record.entry_path == entry_path]
            if entry.get("classification") == FilesystemEntryClass.SAFE_FILE.value:
                if entry_size == 0 and path_records:
                    raise StreamingBackupError("zero-length safe file has chunks")
                if entry_size > 0:
                    if not path_records or [r.sequence for r in path_records] != list(
                        range(len(path_records))
                    ):
                        raise StreamingBackupError("streaming file chunk sequence is incomplete")
                    if sum(record.plaintext_size for record in path_records) != entry_size:
                        raise StreamingBackupError("streaming file size does not match chunks")
                elif path_records:
                    raise StreamingBackupError("streaming file chunk sequence is invalid")
                total_plaintext += entry_size
            elif path_records:
                raise StreamingBackupError("excluded entry has file chunks")
        manifest_total = manifest.get("total_plaintext_bytes")
        if (
            isinstance(manifest_total, bool)
            or not isinstance(manifest_total, int)
            or manifest_total != total_plaintext
            or manifest_total > self.limits.max_total_bytes
        ):
            raise StreamingBackupError("streaming plaintext total is invalid")
        if _artifact_digest(manifest_bytes, tuple(records)) != artifact.artifact_digest:
            raise StreamingBackupError("streaming chunk digest list mismatch")
        chunk_dir = artifact.path / "chunks"
        if chunk_dir.is_symlink() or not chunk_dir.is_dir():
            raise StreamingBackupError("streaming chunk directory is unsafe")
        actual_files = tuple(sorted(path.name for path in chunk_dir.iterdir()))
        expected_files = tuple(sorted(record.filename for record in records))
        if actual_files != expected_files:
            raise StreamingBackupError("streaming artifact has missing or extra chunks")
        return manifest, manifest_bytes, tuple(records)

    @staticmethod
    def _read_chunk(root: Path, record: ChunkRecord) -> bytes:
        path = root / "chunks" / record.filename
        if path.is_symlink() or not path.is_file():
            raise StreamingBackupError("streaming chunk is unavailable")
        try:
            descriptor = os.open(
                os.fspath(path),
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > record.ciphertext_size:
                os.close(descriptor)
                raise StreamingBackupError("streaming chunk exceeds its declared size")
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                payload = stream.read(record.ciphertext_size + 1)
        except OSError as exc:
            raise StreamingBackupError("streaming chunk cannot be read") from exc
        if len(payload) != record.ciphertext_size or _digest(payload) != record.ciphertext_sha256:
            raise StreamingBackupError("streaming chunk checksum mismatch")
        return payload

    @staticmethod
    def _read_bounded(path: Path, maximum: int) -> bytes:
        try:
            descriptor = os.open(
                os.fspath(path),
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                os.close(descriptor)
                raise StreamingBackupError("streaming metadata exceeds its size limit")
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                payload = stream.read(maximum + 1)
        except OSError as exc:
            raise StreamingBackupError("streaming metadata cannot be read") from exc
        if len(payload) > maximum:
            raise StreamingBackupError("streaming metadata exceeds its size limit")
        return payload


__all__ = [
    "ChunkRecord",
    "ChunkedBackupArtifact",
    "ChunkedBackupLimits",
    "ChunkedBackupReader",
    "ChunkedBackupRequest",
    "ChunkedBackupWriter",
    "StreamingBackupError",
    "StreamingBackupSource",
]
