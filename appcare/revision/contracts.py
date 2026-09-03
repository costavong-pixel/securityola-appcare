"""Immutable, secret-safe application revision contracts for AppCare P03."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Final, Literal, cast

from ..connectors.linux_ssh_contracts import EvidenceClass
from ..readiness.contracts import CapabilityEvidence, CapabilityStatus
from ..services.security import contains_credential_like, is_secret_key

SourceType = Literal["git", "direct-filesystem"]
EntryType = Literal["directory", "file", "symlink"]
EntryClassification = Literal[
    "included",
    "excluded-secret",
    "excluded-secret-tree",
    "excluded-symlink",
]

_SAFE_IDENTIFIER: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_HOST: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,253}$")
_SAFE_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REVISION: Final = re.compile(r"^[0-9a-f]{40,64}$")
_SAFE_REFERENCE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,499}$")
_SAFE_MIRROR_REFERENCE: Final = re.compile(r"^mirror://[A-Za-z0-9][A-Za-z0-9._:/-]{0,480}$")


def _current_host_identity() -> str:
    uname = cast(Callable[[], object], getattr(os, "uname"))  # noqa: B009
    result = uname()
    hostname = getattr(result, "nodename", None)  # noqa: B009
    if not isinstance(hostname, str) or not hostname:
        raise OSError("host identity is unavailable")
    return hostname.casefold()


_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_ROOT: Final = re.compile(r"^[A-Za-z]:/[^/].*$")
_MAX_BASELINE_ENTRIES: Final = 100_000
_MAX_BASELINE_TOTAL_BYTES: Final = 16 * 1024 * 1024 * 1024
_MAX_BASELINE_FILE_BYTES: Final = 1024 * 1024 * 1024
_MAX_CHUNK_BYTES: Final = 8 * 1024 * 1024
_MAX_MIRROR_BYTES: Final = 2 * 1024 * 1024 * 1024
_SECRET_FILE_NAMES: Final = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        "authorized_keys",
        "credentials",
        "credentials.json",
        "credential",
        "id_ed25519",
        "id_rsa",
        "passwd",
        "private",
        "private.key",
        "secret",
        "secrets",
        "secrets.json",
        "shadow",
        "settings.php",
        "config.php",
        "wp-config.php",
    }
)
_SECRET_SUFFIXES: Final = (".pem", ".p12", ".pfx", ".key")


class RevisionError(ValueError):
    """A baseline or mirror contract cannot be accepted safely."""


class BaselineCaptureError(RevisionError):
    """A source tree cannot be captured as a stable, bounded observation."""


class MirrorCaptureError(RevisionError):
    """An internal source mirror cannot be sealed safely."""


def _valid_live_authority(
    receipt_path: object,
    *,
    tenant_id: str,
    application_id: str,
    target_reference: str,
    host_identity: str,
    approved_root: str,
    inventory_evidence_digest: str,
    evidence_reference: str,
) -> bool:
    if not isinstance(receipt_path, str):
        return False
    from ..connectors.linux_ssh_contracts import verify_live_capture_receipt_reference

    return verify_live_capture_receipt_reference(
        receipt_path,
        tenant_id=tenant_id,
        application_id=application_id,
        target_reference=target_reference,
        host_identity=host_identity,
        approved_root=approved_root,
        inventory_evidence_digest=inventory_evidence_digest,
        evidence_reference=evidence_reference,
    )


def _valid_live_revision_authority(
    receipt_path: object,
    *,
    tenant_id: str,
    application_id: str,
    target_reference: str,
    host_identity: str,
    approved_root: str,
    inventory_evidence_digest: object,
    evidence_reference: str,
) -> bool:
    if not isinstance(receipt_path, str) or not isinstance(inventory_evidence_digest, str):
        return False
    from ..connectors.linux_ssh_contracts import verify_live_capture_receipt_reference

    return verify_live_capture_receipt_reference(
        receipt_path,
        tenant_id=tenant_id,
        application_id=application_id,
        target_reference=target_reference,
        host_identity=host_identity,
        approved_root=approved_root,
        inventory_evidence_digest=inventory_evidence_digest,
        evidence_reference=evidence_reference,
    )


def _valid_verified_mirror_receipt(
    receipt: object,
    *,
    tenant_id: str,
    application_id: str,
    target_reference: str,
    baseline_id: str,
    mirror_identity: str,
    mirror_path: str,
    mirror_digest: str,
    evidence_class: EvidenceClass,
) -> bool:
    """Accept mirror evidence only after durable sealed-artifact readback."""

    if not isinstance(receipt, MirrorReceipt):
        return False
    if (
        receipt.tenant_id != tenant_id
        or receipt.application_id != application_id
        or receipt.target_reference != target_reference
        or receipt.baseline_id != baseline_id
        or receipt.mirror_identity != mirror_identity
        or receipt.mirror_path != mirror_path
        or receipt.mirror_digest != mirror_digest
    ):
        return False
    try:
        from .mirror import INTERNAL_MIRROR_ROOT, ImmutableSourceMirror

        mirror_path_value = Path(receipt.mirror_path)
        if len(mirror_path_value.parents) < 4:
            return False
        if evidence_class is EvidenceClass.REAL_TARGET:
            mirror = ImmutableSourceMirror()
            expected_path = (
                INTERNAL_MIRROR_ROOT
                / receipt.tenant_id
                / receipt.application_id
                / receipt.target_reference
                / receipt.baseline_id
            )
            if mirror_path_value != expected_path:
                return False
        else:
            mirror = ImmutableSourceMirror.for_test(mirror_path_value.parents[3])
        return mirror.verify(receipt)
    except (OSError, RuntimeError, RevisionError, ValueError, TypeError):
        return False


def _capture_source_binding(
    source_root: Path,
    *,
    approved_root: str,
    expected_hostname: str,
) -> tuple[str, tuple[int, int]]:
    if os.name != "posix" or not isinstance(source_root, Path) or not source_root.is_absolute():
        raise BaselineCaptureError("live source capture requires a local POSIX source root")
    try:
        metadata = source_root.lstat()
        resolved = source_root.resolve(strict=True)
        local_hostname = _current_host_identity()
    except (AttributeError, OSError, RuntimeError) as exc:
        raise BaselineCaptureError("live source root identity is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or resolved != source_root
        or resolved.as_posix() != validate_root(approved_root)
        or local_hostname != expected_hostname
    ):
        raise BaselineCaptureError("live source root is not bound to the target host")
    return local_hostname, (metadata.st_dev, metadata.st_ino)


def _validate_source_root_identity(value: object) -> tuple[int, int]:
    if (
        not isinstance(value, tuple)
        or len(value) != 2
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value)
    ):
        raise BaselineCaptureError("source root identity is invalid")
    return value


@dataclass(frozen=True, slots=True)
class LiveCaptureAuthorization:
    """Opaque coordinator authorization for a completed live inventory.

    A caller-provided evidence class is never sufficient to create real-target
    revision evidence.  The authorization is minted only from a live SSH
    snapshot produced by the live transport and is intentionally not
    serializable into a baseline or receipt.
    """

    tenant_id: str
    application_id: str
    target_reference: str
    host_identity: str
    approved_root: str
    inventory_evidence_digest: str
    evidence_reference: str
    source_host_identity: str | None = None
    source_root_identity: tuple[int, int] | None = None
    _live_receipt_path: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "tenant_id", validate_identifier(self.tenant_id, field_name="tenant_id")
        )
        object.__setattr__(
            self,
            "application_id",
            validate_identifier(self.application_id, field_name="application_id"),
        )
        object.__setattr__(
            self,
            "target_reference",
            validate_identifier(self.target_reference, field_name="target_reference"),
        )
        object.__setattr__(self, "host_identity", validate_host_identity(self.host_identity))
        object.__setattr__(
            self, "approved_root", validate_root(self.approved_root, field_name="approved_root")
        )
        object.__setattr__(
            self,
            "inventory_evidence_digest",
            validate_digest(self.inventory_evidence_digest, field_name="inventory evidence digest"),
        )
        object.__setattr__(
            self,
            "evidence_reference",
            validate_reference(self.evidence_reference, field_name="evidence reference"),
        )
        if self.source_host_identity is None or self.source_root_identity is None:
            raise RevisionError("live capture source binding is required")
        object.__setattr__(
            self,
            "source_host_identity",
            validate_host_identity(self.source_host_identity),
        )
        object.__setattr__(
            self,
            "source_root_identity",
            _validate_source_root_identity(self.source_root_identity),
        )
        if not _valid_live_authority(
            tenant_id=self.tenant_id,
            application_id=self.application_id,
            target_reference=self.target_reference,
            host_identity=self.host_identity,
            approved_root=self.approved_root,
            inventory_evidence_digest=self.inventory_evidence_digest,
            evidence_reference=self.evidence_reference,
            receipt_path=self._live_receipt_path,
        ):
            raise RevisionError("live capture authorization must come from live transport")

    @classmethod
    def from_inventory(
        cls,
        snapshot: object,
        *,
        approved_root: str,
        source_root: Path | None = None,
        evidence_reference: str | None = None,
    ) -> LiveCaptureAuthorization:
        """Mint authorization only from a complete, live-attested snapshot."""

        from ..connectors.linux_ssh_contracts import LinuxInventorySnapshot

        if not isinstance(snapshot, LinuxInventorySnapshot) or not snapshot.live_attested:
            raise BaselineCaptureError("live capture requires a live transport snapshot")
        if not snapshot.complete:
            raise BaselineCaptureError("live capture requires complete inventory")
        target = snapshot.target
        normalized_root = validate_root(approved_root, field_name="approved_root")
        if normalized_root not in target.approved_application_roots:
            raise BaselineCaptureError("live capture root is not approved for target")
        reference = evidence_reference or (
            f"live://{target.target_reference}/inventory/{snapshot.inventory.evidence_digest}"
        )
        receipt_path = snapshot.live_receipt_path
        if receipt_path is None:
            raise BaselineCaptureError("live capture requires a durable receipt")
        expected_reference = (
            f"live://{target.target_reference}/inventory/{snapshot.inventory.evidence_digest}"
        )
        if reference != expected_reference:
            raise BaselineCaptureError("live capture reference must match durable receipt")
        source_binding = snapshot.live_source_binding(normalized_root)
        if source_binding is None:
            raise BaselineCaptureError("live capture requires a bound target-host source root")
        source_host_identity, source_root_identity = source_binding
        if source_root is not None:
            local_binding = _capture_source_binding(
                source_root,
                approved_root=normalized_root,
                expected_hostname=target.expected_hostname,
            )
            if local_binding != source_binding:
                raise BaselineCaptureError("source root does not match live target observation")
        return cls(
            tenant_id=target.tenant_id,
            application_id=target.application_id,
            target_reference=target.target_reference,
            host_identity=target.expected_hostname,
            approved_root=normalized_root,
            inventory_evidence_digest=snapshot.inventory.evidence_digest,
            evidence_reference=reference,
            source_host_identity=source_host_identity,
            source_root_identity=source_root_identity,
            _live_receipt_path=receipt_path,
        )

    def is_valid_for(
        self,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str,
        host_identity: str,
        approved_root: str,
    ) -> bool:
        return (
            _valid_live_authority(
                self._live_receipt_path,
                tenant_id=self.tenant_id,
                application_id=self.application_id,
                target_reference=self.target_reference,
                host_identity=self.host_identity,
                approved_root=self.approved_root,
                inventory_evidence_digest=self.inventory_evidence_digest,
                evidence_reference=self.evidence_reference,
            )
            and self.tenant_id == tenant_id
            and self.application_id == application_id
            and self.target_reference == target_reference
            and self.host_identity == host_identity
            and self.approved_root == approved_root
        )


def _safe_text(value: object, *, field_name: str, maximum: int = 1024) -> str:
    if not isinstance(value, str):
        raise RevisionError(f"{field_name} is invalid")
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > maximum
        or _CONTROL.search(candidate) is not None
        or contains_credential_like(candidate)
    ):
        raise RevisionError(f"{field_name} is unsafe")
    return candidate


def validate_identifier(value: object, *, field_name: str) -> str:
    candidate = _safe_text(value, field_name=field_name, maximum=128)
    if _SAFE_IDENTIFIER.fullmatch(candidate) is None:
        raise RevisionError(f"{field_name} is invalid")
    return candidate


def validate_host_identity(value: object) -> str:
    candidate = _safe_text(value, field_name="host identity", maximum=254)
    if _SAFE_HOST.fullmatch(candidate) is None:
        raise RevisionError("host identity is invalid")
    return candidate


def validate_root(value: object, *, field_name: str = "approved root") -> str:
    if not isinstance(value, str):
        raise RevisionError(f"{field_name} is invalid")
    candidate = value.strip()
    path = PurePosixPath(candidate)
    is_posix_root = candidate.startswith("/")
    is_windows_root = _WINDOWS_ROOT.fullmatch(candidate) is not None
    if (
        (not is_posix_root and not is_windows_root)
        or (is_posix_root and candidate != path.as_posix())
        or candidate in {"/", candidate[:3] if is_windows_root else ""}
        or _CONTROL.search(candidate) is not None
        or any(
            part in {"", ".", ".."}
            for part in path.parts
            if not (len(part) == 2 and part[1] == ":")
        )
    ):
        raise RevisionError(f"{field_name} is invalid")
    return candidate


def validate_digest(value: object, *, field_name: str = "digest") -> str:
    if not isinstance(value, str) or _SAFE_DIGEST.fullmatch(value) is None:
        raise RevisionError(f"{field_name} is invalid")
    return value


def validate_git_revision(value: object) -> str:
    if not isinstance(value, str) or _SAFE_REVISION.fullmatch(value) is None:
        raise RevisionError("source revision is invalid")
    return value


def validate_reference(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _SAFE_REFERENCE.fullmatch(value) is None:
        raise RevisionError(f"{field_name} is invalid")
    if ".." in value or _CONTROL.search(value) is not None or contains_credential_like(value):
        raise RevisionError(f"{field_name} is unsafe")
    return value


def is_secret_path_name(name: str) -> bool:
    """Classify path names before opening their contents."""

    lowered = name.casefold()
    return (
        lowered in _SECRET_FILE_NAMES
        or lowered.startswith(".env.")
        or lowered.endswith(_SECRET_SUFFIXES)
    )


def normalize_metadata(value: Mapping[str, object], *, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or len(value) > 32:
        raise RevisionError(f"{field_name} is invalid")
    normalized: dict[str, object] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 64
            or _CONTROL.search(key) is not None
            or is_secret_key(key)
        ):
            raise RevisionError(f"{field_name} contains an unsafe key")
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise RevisionError(f"{field_name} contains an unsupported value")
        if isinstance(item, str):
            normalized[key] = _safe_text(item, field_name=key, maximum=512)
        else:
            normalized[key] = item
    return MappingProxyType(dict(sorted(normalized.items())))


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise RevisionError("manifest relative path is invalid")
    if value == ".":
        return value
    path = PurePosixPath(value)
    if (
        value.startswith("/")
        or "\\" in value
        or value != path.as_posix()
        or _CONTROL.search(value) is not None
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RevisionError("manifest relative path is unsafe")
    return value


@dataclass(frozen=True, slots=True)
class BaselinePolicy:
    """Bounded source-capture limits; no limit may be caller-expanded at runtime."""

    max_entries: int = 50_000
    max_total_bytes: int = 4 * 1024 * 1024 * 1024
    max_file_bytes: int = 256 * 1024 * 1024
    chunk_bytes: int = 1024 * 1024
    max_path_bytes: int = 1024

    def __post_init__(self) -> None:
        for name in ("max_entries", "max_total_bytes", "max_file_bytes", "chunk_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise BaselineCaptureError(f"{name} is invalid")
        if self.max_entries > _MAX_BASELINE_ENTRIES:
            raise BaselineCaptureError("max_entries exceeds hard limit")
        if self.max_total_bytes > _MAX_BASELINE_TOTAL_BYTES:
            raise BaselineCaptureError("max_total_bytes exceeds hard limit")
        if self.max_file_bytes > _MAX_BASELINE_FILE_BYTES:
            raise BaselineCaptureError("max_file_bytes exceeds hard limit")
        if self.chunk_bytes > _MAX_CHUNK_BYTES:
            raise BaselineCaptureError("chunk_bytes exceeds hard limit")
        if self.max_file_bytes > self.max_total_bytes:
            raise BaselineCaptureError("file limit exceeds total limit")
        if (
            isinstance(self.max_path_bytes, bool)
            or not isinstance(self.max_path_bytes, int)
            or not 1 <= self.max_path_bytes <= 4096
        ):
            raise BaselineCaptureError("path limit is invalid")


@dataclass(frozen=True, slots=True)
class MirrorPolicy:
    """Only source-like text/code files may enter the internal mirror."""

    max_mirror_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    chunk_bytes: int = 1024 * 1024
    max_manifest_bytes: int = 8 * 1024 * 1024
    allowed_suffixes: frozenset[str] = frozenset(
        {
            ".cjs",
            ".conf",
            ".css",
            ".html",
            ".htm",
            ".inc",
            ".ini",
            ".js",
            ".json",
            ".lock",
            ".mjs",
            ".md",
            ".php",
            ".phtml",
            ".txt",
            ".xml",
            ".yaml",
            ".yml",
        }
    )
    allowed_names: frozenset[str] = frozenset(
        {".htaccess", "composer.json", "composer.lock", "Dockerfile", "Makefile"}
    )

    def __post_init__(self) -> None:
        for name in (
            "max_mirror_bytes",
            "max_file_bytes",
            "chunk_bytes",
            "max_manifest_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise MirrorCaptureError(f"{name} is invalid")
        if self.max_mirror_bytes > _MAX_MIRROR_BYTES:
            raise MirrorCaptureError("max_mirror_bytes exceeds hard limit")
        if self.max_file_bytes > _MAX_BASELINE_FILE_BYTES:
            raise MirrorCaptureError("max_file_bytes exceeds hard limit")
        if self.chunk_bytes > _MAX_CHUNK_BYTES:
            raise MirrorCaptureError("chunk_bytes exceeds hard limit")
        if self.max_manifest_bytes > 16 * 1024 * 1024:
            raise MirrorCaptureError("max_manifest_bytes exceeds hard limit")
        if self.max_file_bytes > self.max_mirror_bytes:
            raise MirrorCaptureError("mirror file limit exceeds total limit")
        for suffix in self.allowed_suffixes:
            if not isinstance(suffix, str) or not suffix.startswith(".") or "/" in suffix:
                raise MirrorCaptureError("mirror suffix is invalid")
        for name in self.allowed_names:
            _validate_relative_path(name)

    def allows(self, relative_path: str) -> bool:
        name = relative_path.rsplit("/", 1)[-1]
        return name in self.allowed_names or PurePosixPath(name).suffix.casefold() in {
            suffix.casefold() for suffix in self.allowed_suffixes
        }


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    relative_path: str
    entry_type: EntryType
    size_bytes: int
    mode: int
    uid: int
    gid: int
    sha256: str | None = None
    symlink_target: str | None = None
    classification: EntryClassification = "included"

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", _validate_relative_path(self.relative_path))
        if self.entry_type not in {"directory", "file", "symlink"}:
            raise RevisionError("manifest entry type is invalid")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or self.size_bytes < 0
            or isinstance(self.mode, bool)
            or not isinstance(self.mode, int)
            or not 0 <= self.mode <= 0o7777
            or isinstance(self.uid, bool)
            or not isinstance(self.uid, int)
            or self.uid < 0
            or isinstance(self.gid, bool)
            or not isinstance(self.gid, int)
            or self.gid < 0
        ):
            raise RevisionError("manifest entry metadata is invalid")
        if self.classification not in {
            "included",
            "excluded-secret",
            "excluded-secret-tree",
            "excluded-symlink",
        }:
            raise RevisionError("manifest entry classification is invalid")
        if self.entry_type == "directory":
            if self.sha256 is not None or self.symlink_target is not None:
                raise RevisionError("directory manifest entry contains file data")
            if self.classification not in {"included", "excluded-secret-tree"}:
                raise RevisionError("directory classification is invalid")
        elif self.entry_type == "file":
            if self.symlink_target is not None:
                raise RevisionError("file manifest entry contains symlink data")
            if self.classification == "included":
                if self.sha256 is None:
                    raise RevisionError("included file is missing its digest")
                validate_digest(self.sha256, field_name="file digest")
            elif self.sha256 is not None:
                raise RevisionError("excluded file must not carry a digest")
        else:
            if self.size_bytes != 0 or self.sha256 is not None or not self.symlink_target:
                raise RevisionError("symlink manifest entry is malformed")
            if self.classification != "excluded-symlink":
                raise RevisionError("symlink manifest entry must be excluded")
            _safe_text(self.symlink_target, field_name="symlink target", maximum=4096)
        if self.relative_path == "." and self.entry_type != "directory":
            raise RevisionError("manifest root entry must be a directory")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "entry_type": self.entry_type,
            "size_bytes": self.size_bytes,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "sha256": self.sha256,
            "symlink_target": self.symlink_target,
            "classification": self.classification,
        }


@dataclass(frozen=True, slots=True)
class FilesystemBaseline:
    root: str
    entries: tuple[BaselineEntry, ...]
    policy: BaselinePolicy = field(repr=False, compare=False)
    source_type: SourceType = "direct-filesystem"
    source_host_identity: str | None = None
    root_identity: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy, BaselinePolicy):
            raise RevisionError("filesystem baseline policy is invalid")
        object.__setattr__(self, "root", validate_root(self.root))
        object.__setattr__(self, "entries", tuple(self.entries))
        if self.source_type not in {"git", "direct-filesystem"}:
            raise RevisionError("filesystem baseline source type is invalid")
        if self.source_type == "git":
            raise RevisionError("Git-bound capture requires verified tree binding")
        if self.source_host_identity is not None:
            object.__setattr__(
                self,
                "source_host_identity",
                validate_host_identity(self.source_host_identity),
            )
        if self.root_identity is not None:
            object.__setattr__(
                self,
                "root_identity",
                _validate_source_root_identity(self.root_identity),
            )
        if not self.entries or len(self.entries) > self.policy.max_entries:
            raise BaselineCaptureError("filesystem baseline entry count is invalid")
        paths = tuple(entry.relative_path for entry in self.entries)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)) or paths[0] != ".":
            raise RevisionError("filesystem manifest must be sorted and rooted")

    @property
    def total_files(self) -> int:
        return sum(
            entry.entry_type == "file" and entry.classification == "included"
            for entry in self.entries
        )

    @property
    def total_bytes(self) -> int:
        return sum(
            entry.size_bytes
            for entry in self.entries
            if entry.entry_type == "file" and entry.classification == "included"
        )

    def manifest_payload(self) -> dict[str, object]:
        return {
            "root": self.root,
            "source_type": self.source_type,
            "source_host_identity": self.source_host_identity,
            "root_identity": list(self.root_identity) if self.root_identity is not None else None,
            "entries": [entry.canonical_payload() for entry in self.entries],
        }

    def canonical_manifest_bytes(self) -> bytes:
        return json.dumps(
            self.manifest_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    @property
    def manifest_digest(self) -> str:
        return hashlib.sha256(self.canonical_manifest_bytes()).hexdigest()


def _canonical_metadata(value: Mapping[str, object]) -> dict[str, object]:
    return dict(value)


@dataclass(frozen=True, slots=True)
class CapturedApplicationRevision:
    """A sanitized source identity; direct-filesystem captures are not snapshots."""

    tenant_id: str
    application_id: str
    target_reference: str
    host_identity: str
    approved_root: str
    captured_at: datetime
    source_type: SourceType
    baseline_id: str
    manifest: tuple[BaselineEntry, ...]
    manifest_digest: str
    baseline_digest: str
    runtime_metadata: Mapping[str, object] = field(default_factory=dict)
    database_metadata: Mapping[str, object] = field(default_factory=dict)
    source_revision: str | None = None
    mirror_identity: str | None = None
    mirror_digest: str | None = None
    _mirror_receipt: object | None = field(default=None, repr=False, compare=False)
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE
    evidence_reference: str = "revision://fixture/baseline"
    snapshot_semantics: str = "observed-tree-merkle-race-checked"
    _live_receipt_path: str | None = field(default=None, repr=False, compare=False)
    _live_inventory_evidence_digest: str | None = field(default=None, repr=False, compare=False)
    _source_host_identity: str | None = field(default=None, repr=False, compare=False)
    _source_root_identity: tuple[int, int] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        for value, name in (
            (self.tenant_id, "tenant_id"),
            (self.application_id, "application_id"),
            (self.target_reference, "target_reference"),
        ):
            object.__setattr__(self, name, validate_identifier(value, field_name=name))
        object.__setattr__(self, "host_identity", validate_host_identity(self.host_identity))
        object.__setattr__(
            self, "approved_root", validate_root(self.approved_root, field_name="approved_root")
        )
        if (
            not isinstance(self.captured_at, datetime)
            or self.captured_at.tzinfo is None
            or self.captured_at.utcoffset() is None
        ):
            raise RevisionError("capture timestamp must be timezone-aware")
        if self.source_type not in {"git", "direct-filesystem"}:
            raise RevisionError("source type is invalid")
        if self.source_type == "git":
            raise RevisionError("Git-bound capture requires verified tree binding")
        object.__setattr__(
            self, "baseline_id", validate_identifier(self.baseline_id, field_name="baseline_id")
        )
        object.__setattr__(self, "manifest", tuple(self.manifest))
        if (
            not self.manifest
            or tuple(entry.relative_path for entry in self.manifest)
            != tuple(sorted(entry.relative_path for entry in self.manifest))
            or len({entry.relative_path for entry in self.manifest}) != len(self.manifest)
        ):
            raise RevisionError("revision manifest is not canonical")
        if any(not isinstance(entry, BaselineEntry) for entry in self.manifest):
            raise RevisionError("revision manifest contains an invalid entry")
        expected_manifest_digest = hashlib.sha256(
            json.dumps(
                {
                    "root": self.approved_root,
                    "source_type": self.source_type,
                    "source_host_identity": self._source_host_identity,
                    "source_root_identity": (
                        list(self._source_root_identity)
                        if self._source_root_identity is not None
                        else None
                    ),
                    "entries": [entry.canonical_payload() for entry in self.manifest],
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        object.__setattr__(
            self,
            "manifest_digest",
            validate_digest(self.manifest_digest, field_name="manifest digest"),
        )
        if self.manifest_digest != expected_manifest_digest:
            raise RevisionError("manifest digest does not match its content")
        object.__setattr__(
            self,
            "baseline_digest",
            validate_digest(self.baseline_digest, field_name="baseline digest"),
        )
        object.__setattr__(
            self,
            "runtime_metadata",
            normalize_metadata(self.runtime_metadata, field_name="runtime metadata"),
        )
        object.__setattr__(
            self,
            "database_metadata",
            normalize_metadata(self.database_metadata, field_name="database metadata"),
        )
        if self.source_revision is not None:
            object.__setattr__(self, "source_revision", validate_git_revision(self.source_revision))
        if self.mirror_identity is not None:
            if _SAFE_MIRROR_REFERENCE.fullmatch(self.mirror_identity) is None:
                raise RevisionError("mirror identity is invalid")
            expected_mirror_identity = (
                f"mirror://{self.tenant_id}/{self.application_id}/"
                f"{self.target_reference}/{self.baseline_id}"
            )
            if self.mirror_identity != expected_mirror_identity:
                raise RevisionError("mirror identity does not match revision scope")
        if self.mirror_digest is not None:
            object.__setattr__(
                self,
                "mirror_digest",
                validate_digest(self.mirror_digest, field_name="mirror digest"),
            )
        if not isinstance(self.evidence_class, EvidenceClass):
            try:
                object.__setattr__(self, "evidence_class", EvidenceClass(str(self.evidence_class)))
            except ValueError as exc:
                raise RevisionError("evidence class is invalid") from exc
        object.__setattr__(
            self,
            "evidence_reference",
            validate_reference(self.evidence_reference, field_name="evidence reference"),
        )
        if self.evidence_class is EvidenceClass.REAL_TARGET:
            if (
                self._source_host_identity != self.host_identity
                or self._source_root_identity is None
            ):
                raise RevisionError("real-target evidence requires bound source capture")
            if not _valid_live_revision_authority(
                tenant_id=self.tenant_id,
                application_id=self.application_id,
                target_reference=self.target_reference,
                host_identity=self.host_identity,
                approved_root=self.approved_root,
                inventory_evidence_digest=self._live_inventory_evidence_digest,
                evidence_reference=self.evidence_reference,
                receipt_path=self._live_receipt_path,
            ):
                raise RevisionError("real-target evidence requires live capture authorization")
        elif (
            self._live_receipt_path is not None or self._live_inventory_evidence_digest is not None
        ):
            raise RevisionError("live capture authorization is not valid for fixture evidence")
        if self.snapshot_semantics not in {"git-bound", "observed-tree-merkle-race-checked"}:
            raise RevisionError("snapshot semantics are invalid")
        if (
            self.source_type == "direct-filesystem"
            and self.snapshot_semantics != "observed-tree-merkle-race-checked"
        ):
            raise RevisionError("direct filesystem captures require race-checked semantics")
        expected = self._compute_baseline_digest()
        if expected != self.baseline_digest:
            raise RevisionError("baseline digest does not match its content")
        mirror_identity = self.mirror_identity
        mirror_digest = self.mirror_digest
        if mirror_identity is None or mirror_digest is None:
            if mirror_identity is not None or mirror_digest is not None:
                raise RevisionError("mirror identity and digest must be provided together")
            if self._mirror_receipt is not None:
                raise RevisionError("mirror receipt requires a mirror identity")
        else:
            if not _valid_verified_mirror_receipt(
                self._mirror_receipt,
                tenant_id=self.tenant_id,
                application_id=self.application_id,
                target_reference=self.target_reference,
                baseline_id=self.baseline_id,
                mirror_identity=mirror_identity,
                mirror_path=self._mirror_receipt.mirror_path
                if isinstance(self._mirror_receipt, MirrorReceipt)
                else "",
                mirror_digest=mirror_digest,
                evidence_class=self.evidence_class,
            ):
                raise RevisionError("mirror evidence requires a verified sealed receipt")

    @classmethod
    def from_filesystem_baseline(
        cls,
        baseline: FilesystemBaseline,
        *,
        tenant_id: str,
        application_id: str,
        target_reference: str,
        host_identity: str,
        captured_at: datetime,
        runtime_metadata: Mapping[str, object] | None = None,
        database_metadata: Mapping[str, object] | None = None,
        source_revision: str | None = None,
        evidence_class: EvidenceClass = EvidenceClass.FIXTURE,
        evidence_reference: str | None = None,
        baseline_id: str | None = None,
        live_authorization: LiveCaptureAuthorization | None = None,
    ) -> CapturedApplicationRevision:
        tenant = validate_identifier(tenant_id, field_name="tenant_id")
        application = validate_identifier(application_id, field_name="application_id")
        target = validate_identifier(target_reference, field_name="target_reference")
        stable_id = baseline_id or (
            "baseline-"
            + hashlib.sha256(
                f"{tenant}\0{application}\0{target}\0{baseline.root}\0{baseline.manifest_digest}".encode()
            ).hexdigest()[:32]
        )
        normalized_ref = evidence_reference or f"revision://{target}/{stable_id}"
        runtime = normalize_metadata(runtime_metadata or {}, field_name="runtime metadata")
        database = normalize_metadata(database_metadata or {}, field_name="database metadata")
        source = baseline.source_type
        if source == "git":
            raise BaselineCaptureError("Git-bound capture requires verified tree binding")
        semantics = "observed-tree-merkle-race-checked"
        normalized_host = validate_host_identity(host_identity)
        if live_authorization is not None:
            if not live_authorization.is_valid_for(
                tenant_id=tenant,
                application_id=application,
                target_reference=target,
                host_identity=normalized_host,
                approved_root=baseline.root,
            ):
                raise BaselineCaptureError("live capture authorization does not match baseline")
            if (
                baseline.source_host_identity != live_authorization.source_host_identity
                or baseline.root_identity != live_authorization.source_root_identity
            ):
                raise BaselineCaptureError("source capture is not bound to live target")
            final_evidence_class = EvidenceClass.REAL_TARGET
            normalized_ref = live_authorization.evidence_reference
        else:
            if evidence_class is EvidenceClass.REAL_TARGET:
                raise BaselineCaptureError(
                    "real-target evidence requires live capture authorization"
                )
            final_evidence_class = evidence_class
        if source_revision is not None:
            raise RevisionError("direct filesystem captures cannot claim a Git revision")
        digest_payload = {
            "tenant_id": tenant,
            "application_id": application,
            "target_reference": target,
            "host_identity": normalized_host,
            "approved_root": baseline.root,
            "source_type": source,
            "baseline_id": stable_id,
            "manifest_digest": baseline.manifest_digest,
            "runtime_metadata": dict(runtime),
            "database_metadata": dict(database),
            "source_revision": source_revision,
            "snapshot_semantics": semantics,
            "live_inventory_evidence_digest": (
                live_authorization.inventory_evidence_digest
                if live_authorization is not None
                else None
            ),
            "source_host_identity": baseline.source_host_identity,
            "source_root_identity": (
                list(baseline.root_identity) if baseline.root_identity is not None else None
            ),
        }
        digest = hashlib.sha256(
            json.dumps(
                digest_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest()
        return cls(
            tenant_id=tenant,
            application_id=application,
            target_reference=target,
            host_identity=normalized_host,
            approved_root=baseline.root,
            captured_at=captured_at,
            source_type=baseline.source_type,
            baseline_id=stable_id,
            manifest=baseline.entries,
            manifest_digest=baseline.manifest_digest,
            baseline_digest=digest,
            runtime_metadata=runtime,
            database_metadata=database,
            source_revision=source_revision,
            evidence_class=final_evidence_class,
            evidence_reference=normalized_ref,
            snapshot_semantics=semantics,
            _live_receipt_path=(
                live_authorization._live_receipt_path if live_authorization is not None else None
            ),
            _live_inventory_evidence_digest=(
                live_authorization.inventory_evidence_digest
                if live_authorization is not None
                else None
            ),
            _source_host_identity=baseline.source_host_identity,
            _source_root_identity=baseline.root_identity,
        )

    def _baseline_payload(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "target_reference": self.target_reference,
            "host_identity": self.host_identity,
            "approved_root": self.approved_root,
            "source_type": self.source_type,
            "baseline_id": self.baseline_id,
            "manifest_digest": self.manifest_digest,
            "runtime_metadata": _canonical_metadata(self.runtime_metadata),
            "database_metadata": _canonical_metadata(self.database_metadata),
            "source_revision": self.source_revision,
            "snapshot_semantics": self.snapshot_semantics,
            "live_inventory_evidence_digest": self._live_inventory_evidence_digest,
            "source_host_identity": self._source_host_identity,
            "source_root_identity": (
                list(self._source_root_identity) if self._source_root_identity is not None else None
            ),
        }

    def _compute_baseline_digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                self._baseline_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {
            **self._baseline_payload(),
            "captured_at": self.captured_at.astimezone(UTC).isoformat(),
            "manifest": [entry.canonical_payload() for entry in self.manifest],
            "baseline_digest": self.baseline_digest,
            "mirror_identity": self.mirror_identity,
            "mirror_digest": self.mirror_digest,
            "mirror_path": (
                self._mirror_receipt.mirror_path
                if isinstance(self._mirror_receipt, MirrorReceipt)
                else None
            ),
            "evidence_class": self.evidence_class.value,
            "evidence_reference": self.evidence_reference,
        }

    @property
    def evidence_digest(self) -> str:
        encoded = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @property
    def promotes_real_target(self) -> bool:
        return self.evidence_class is EvidenceClass.REAL_TARGET

    def capability_evidence(self, *, stack_id: str) -> CapabilityEvidence:
        """Return coordinator-consumable source-revision evidence.

        A direct-filesystem baseline uses its stable baseline digest as the
        source identity.  The evidence class remains attached, so fixture or
        reference captures cannot be promoted to live readiness by relabeling.
        A sealed mirror is required before this capability is reported as
        supported.
        """

        if (
            self.mirror_identity is None
            or self.mirror_digest is None
            or not _valid_verified_mirror_receipt(
                self._mirror_receipt,
                tenant_id=self.tenant_id,
                application_id=self.application_id,
                target_reference=self.target_reference,
                baseline_id=self.baseline_id,
                mirror_identity=self.mirror_identity,
                mirror_path=(
                    self._mirror_receipt.mirror_path
                    if isinstance(self._mirror_receipt, MirrorReceipt)
                    else ""
                ),
                mirror_digest=self.mirror_digest,
                evidence_class=self.evidence_class,
            )
        ):
            status = CapabilityStatus.UNSUPPORTED
            artifact_digest = self.evidence_digest
        else:
            status = CapabilityStatus.SUPPORTED
            artifact_digest = self.mirror_digest
        return CapabilityEvidence(
            tenant_id=self.tenant_id,
            application_id=self.application_id,
            stack_id=stack_id,
            capability="source_revision",
            status=status,
            evidence_class=self.evidence_class,
            evidence_ref=self.evidence_reference,
            observed_at=self.captured_at,
            source_revision=self.source_revision or self.baseline_digest,
            artifact_digest=artifact_digest,
        )

    def with_mirror(
        self,
        *,
        receipt: MirrorReceipt,
    ) -> CapturedApplicationRevision:
        if not isinstance(receipt, MirrorReceipt):
            raise RevisionError("mirror evidence requires a verified sealed receipt")
        return type(self)(
            tenant_id=self.tenant_id,
            application_id=self.application_id,
            target_reference=self.target_reference,
            host_identity=self.host_identity,
            approved_root=self.approved_root,
            captured_at=self.captured_at,
            source_type=self.source_type,
            baseline_id=self.baseline_id,
            manifest=self.manifest,
            manifest_digest=self.manifest_digest,
            baseline_digest=self.baseline_digest,
            runtime_metadata=self.runtime_metadata,
            database_metadata=self.database_metadata,
            source_revision=self.source_revision,
            mirror_identity=receipt.mirror_identity,
            mirror_digest=receipt.mirror_digest,
            _mirror_receipt=receipt,
            evidence_class=self.evidence_class,
            evidence_reference=self.evidence_reference,
            snapshot_semantics=self.snapshot_semantics,
            _live_receipt_path=self._live_receipt_path,
            _live_inventory_evidence_digest=self._live_inventory_evidence_digest,
            _source_host_identity=self._source_host_identity,
            _source_root_identity=self._source_root_identity,
        )


@dataclass(frozen=True, slots=True)
class MirrorReceipt:
    tenant_id: str
    application_id: str
    target_reference: str
    baseline_id: str
    mirror_identity: str
    mirror_path: str
    source_manifest_digest: str
    mirror_digest: str
    file_count: int
    bytes_copied: int
    excluded_file_count: int
    sealed: bool
    sealed_at: datetime
    evidence_class: EvidenceClass

    def __post_init__(self) -> None:
        for value, name in (
            (self.tenant_id, "tenant_id"),
            (self.application_id, "application_id"),
            (self.target_reference, "target_reference"),
            (self.baseline_id, "baseline_id"),
        ):
            object.__setattr__(self, name, validate_identifier(value, field_name=name))
        for value, name in (
            (self.source_manifest_digest, "source manifest digest"),
            (self.mirror_digest, "mirror digest"),
        ):
            validate_digest(value, field_name=name)
        if _SAFE_MIRROR_REFERENCE.fullmatch(self.mirror_identity) is None:
            raise MirrorCaptureError("mirror identity is invalid")
        expected_mirror_identity = (
            f"mirror://{self.tenant_id}/{self.application_id}/"
            f"{self.target_reference}/{self.baseline_id}"
        )
        if self.mirror_identity != expected_mirror_identity:
            raise MirrorCaptureError("mirror identity does not match receipt scope")
        object.__setattr__(
            self, "mirror_path", validate_root(self.mirror_path, field_name="mirror path")
        )
        if not isinstance(self.evidence_class, EvidenceClass):
            try:
                object.__setattr__(self, "evidence_class", EvidenceClass(str(self.evidence_class)))
            except ValueError as exc:
                raise MirrorCaptureError("mirror evidence class is invalid") from exc
        if (
            isinstance(self.file_count, bool)
            or not isinstance(self.file_count, int)
            or self.file_count < 0
            or isinstance(self.bytes_copied, bool)
            or not isinstance(self.bytes_copied, int)
            or self.bytes_copied < 0
            or isinstance(self.excluded_file_count, bool)
            or not isinstance(self.excluded_file_count, int)
            or self.excluded_file_count < 0
            or not self.sealed
        ):
            raise MirrorCaptureError("mirror receipt is invalid")
        if (
            not isinstance(self.sealed_at, datetime)
            or self.sealed_at.tzinfo is None
            or self.sealed_at.utcoffset() is None
        ):
            raise MirrorCaptureError("mirror receipt timestamp is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "target_reference": self.target_reference,
            "baseline_id": self.baseline_id,
            "mirror_identity": self.mirror_identity,
            "mirror_path": self.mirror_path,
            "source_manifest_digest": self.source_manifest_digest,
            "mirror_digest": self.mirror_digest,
            "file_count": self.file_count,
            "bytes_copied": self.bytes_copied,
            "excluded_file_count": self.excluded_file_count,
            "sealed": self.sealed,
            "sealed_at": self.sealed_at.astimezone(UTC).isoformat(),
            "evidence_class": self.evidence_class.value,
        }


@dataclass(frozen=True, slots=True)
class MirrorCaptureOutcome:
    revision: CapturedApplicationRevision
    receipt: MirrorReceipt

    def __post_init__(self) -> None:
        if (
            self.revision.mirror_identity != self.receipt.mirror_identity
            or self.revision.mirror_digest != self.receipt.mirror_digest
            or self.revision.tenant_id != self.receipt.tenant_id
            or self.revision.application_id != self.receipt.application_id
            or self.revision.target_reference != self.receipt.target_reference
            or self.revision.baseline_id != self.receipt.baseline_id
            or not isinstance(self.revision._mirror_receipt, MirrorReceipt)
            or self.revision._mirror_receipt is not self.receipt
        ):
            raise MirrorCaptureError("mirror outcome is not scope-bound")


__all__ = [
    "BaselineCaptureError",
    "BaselineEntry",
    "BaselinePolicy",
    "CapturedApplicationRevision",
    "EvidenceClass",
    "FilesystemBaseline",
    "LiveCaptureAuthorization",
    "MirrorCaptureError",
    "MirrorCaptureOutcome",
    "MirrorPolicy",
    "MirrorReceipt",
    "RevisionError",
    "SourceType",
    "is_secret_path_name",
    "normalize_metadata",
    "validate_digest",
    "validate_git_revision",
    "validate_host_identity",
    "validate_identifier",
    "validate_reference",
    "validate_root",
]
