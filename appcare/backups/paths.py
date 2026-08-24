"""Canonical AppCare backup filesystem paths and provider namespaces."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .contracts import BackupBoundaryError, validate_path_segment

BACKUP_ROOT: Final = Path("/var/lib/securityola/appcare/backups")
BACKUP_LOG_ROOT: Final = Path("/var/log/securityola/appcare/backups")
BACKUP_CONFIG_ROOT: Final = Path("/etc/securityola/appcare/backups")
BACKUP_TMP_ROOT: Final = Path("/var/tmp/securityola/appcare-backups")  # noqa: S108

B2_BACKUP_PREFIX: Final = "appcare/backups"
GLACIER_ARCHIVE_PREFIX: Final = "appcare/archive"

_DATA_SUBDIRECTORIES: Final = (
    "staging",
    "snapshots",
    "manifests",
    "restore-rehearsal",
    "jobs",
    "failed",
)
_PROTECTED_ROOTS: Final = (
    Path("/var/www"),
    Path("/root"),
    Path("/home/debian/apps/appcare-opencode"),
)
_PROTECTED_MARKERS: Final = ("wordpress", "barnd", "shield", "api.securityola.com")


def _within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _canonical_path(path: Path, *, field: str) -> Path:
    if not path.is_absolute():
        raise BackupBoundaryError(f"{field} must be absolute")
    try:
        absolute = Path(os.path.abspath(path))
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise BackupBoundaryError(f"{field} cannot be resolved") from exc
    if os.path.normcase(os.fspath(absolute)) != os.path.normcase(os.fspath(resolved)):
        raise BackupBoundaryError(f"{field} cannot cross a symlink")
    return resolved


def _reject_protected_path(path: Path, *, field: str) -> Path:
    resolved = _canonical_path(path, field=field)
    normalized = os.path.normcase(os.fspath(resolved)).replace("\\", "/").casefold()
    for protected in _PROTECTED_ROOTS:
        protected_path = Path(os.path.abspath(protected))
        if _within(resolved, protected_path):
            raise BackupBoundaryError(f"{field} is outside the AppCare boundary")
    if any(marker in normalized for marker in _PROTECTED_MARKERS):
        raise BackupBoundaryError(f"{field} is outside the AppCare boundary")
    if resolved == Path(resolved.anchor):
        raise BackupBoundaryError(f"{field} is too broad")
    return resolved


def _safe_join(root: Path, parts: tuple[str, ...], *, field: str) -> Path:
    canonical_root = _reject_protected_path(root, field=f"{field} root")
    current = canonical_root
    for index, part in enumerate(parts):
        validate_path_segment(part, field=f"{field} segment {index + 1}")
        current = current / part
        if current.is_symlink():
            raise BackupBoundaryError(f"{field} cannot cross a symlink")
        try:
            resolved = current.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise BackupBoundaryError(f"{field} cannot be resolved") from exc
        if not _within(resolved, canonical_root):
            raise BackupBoundaryError(f"{field} crossed the isolation boundary")
    return current


@dataclass(frozen=True, slots=True)
class BackupFilesystemBoundary:
    """The only local filesystem boundary available to AppCare backup jobs."""

    backup_root: Path = BACKUP_ROOT
    log_root: Path = BACKUP_LOG_ROOT
    config_root: Path = BACKUP_CONFIG_ROOT
    tmp_root: Path = BACKUP_TMP_ROOT

    def __post_init__(self) -> None:
        for field_name in ("backup_root", "log_root", "config_root", "tmp_root"):
            path = _reject_protected_path(
                Path(getattr(self, field_name)),
                field=f"backup {field_name}",
            )
            object.__setattr__(self, field_name, path)
        roots = (
            ("backup_root", self.backup_root),
            ("log_root", self.log_root),
            ("config_root", self.config_root),
            ("tmp_root", self.tmp_root),
        )
        for left_name, left in roots:
            for right_name, right in roots:
                if left_name == right_name:
                    continue
                if _within(left, right) or _within(right, left):
                    raise BackupBoundaryError(
                        f"backup {left_name} overlaps backup {right_name}"
                    )

    @classmethod
    def canonical(cls) -> BackupFilesystemBoundary:
        """Return the fixed production AppCare boundary."""

        return cls(BACKUP_ROOT, BACKUP_LOG_ROOT, BACKUP_CONFIG_ROOT, BACKUP_TMP_ROOT)

    @classmethod
    def for_test(cls, root: Path) -> BackupFilesystemBoundary:
        """Build an isolated test boundary; production code uses canonical()."""

        base = _reject_protected_path(root, field="test backup root")
        return cls(
            base / "data",
            base / "logs",
            base / "config",
            base / "tmp",
        )

    @property
    def data_directories(self) -> tuple[Path, ...]:
        return (self.backup_root,) + tuple(
            self._static_subdirectory(name) for name in _DATA_SUBDIRECTORIES
        )

    def ensure_data_dirs(self) -> None:
        """Create only missing data directories inside the fixed boundary."""

        for directory in self.data_directories:
            if directory.exists() and directory.is_symlink():
                raise BackupBoundaryError("backup data directory is a symlink")
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            _canonical_path(directory, field="backup data directory")

    def _static_subdirectory(self, name: str) -> Path:
        return _safe_join(self.backup_root, (name,), field=f"backup {name}")

    def staging_path(self, job_id: str) -> Path:
        return _safe_join(
            self._static_subdirectory("staging"),
            (job_id,),
            field="backup staging path",
        )

    def snapshot_path(self, tenant_id: str, application_id: str, backup_id: str) -> Path:
        return _safe_join(
            self._static_subdirectory("snapshots"),
            (tenant_id, application_id, backup_id),
            field="backup snapshot path",
        )

    def snapshot_file(
        self,
        tenant_id: str,
        application_id: str,
        backup_id: str,
        filename: str,
    ) -> Path:
        return _safe_join(
            self.snapshot_path(tenant_id, application_id, backup_id),
            (filename,),
            field="backup snapshot file",
        )

    def manifest_path(self, tenant_id: str, application_id: str, backup_id: str) -> Path:
        validate_path_segment(backup_id, field="manifest backup_id")
        return _safe_join(
            self._static_subdirectory("manifests"),
            (tenant_id, application_id, f"{backup_id}.json"),
            field="backup manifest path",
        )

    def restore_rehearsal_path(
        self,
        tenant_id: str,
        application_id: str,
        restore_job_id: str,
    ) -> Path:
        return _safe_join(
            self._static_subdirectory("restore-rehearsal"),
            (tenant_id, application_id, restore_job_id),
            field="restore rehearsal path",
        )

    def job_path(self, job_id: str) -> Path:
        return _safe_join(
            self._static_subdirectory("jobs"),
            (job_id,),
            field="backup job path",
        )

    def failed_path(self, job_id: str) -> Path:
        return _safe_join(
            self._static_subdirectory("failed"),
            (job_id,),
            field="failed backup path",
        )

    def b2_prefix(self, tenant_id: str, application_id: str, backup_id: str) -> str:
        for value, field_name in (
            (tenant_id, "B2 tenant_id"),
            (application_id, "B2 application_id"),
            (backup_id, "B2 backup_id"),
        ):
            validate_path_segment(value, field=field_name)
        return f"{B2_BACKUP_PREFIX}/{tenant_id}/{application_id}/{backup_id}/"

    def glacier_prefix(self, tenant_id: str, application_id: str, backup_id: str) -> str:
        for value, field_name in (
            (tenant_id, "Glacier tenant_id"),
            (application_id, "Glacier application_id"),
            (backup_id, "Glacier backup_id"),
        ):
            validate_path_segment(value, field=field_name)
        return f"{GLACIER_ARCHIVE_PREFIX}/{tenant_id}/{application_id}/{backup_id}/"


def validate_read_only_source(path: Path) -> Path:
    """Reject protected source paths before an authorized read-only open."""

    return _reject_protected_path(path, field="backup source path")
