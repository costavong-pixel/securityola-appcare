"""Real, bounded filesystem deployment adapter for AppCare reference targets.

This adapter is deliberately provider-neutral. It deploys an immutable
artifact directory, switches an atomic ``current`` symlink, restarts the
named systemd service, and verifies the loopback health endpoint. It never
accepts a caller-selected arbitrary path and never invokes a shell.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .contracts import (
    DeploymentIntent,
    ProductionControlError,
    ProviderDeployment,
    ProviderRollback,
    ProviderVerification,
    _digest,
    _revision,
    validate_opaque_reference,
)


def _inside(path: Path, root: Path, *, field_name: str) -> Path:
    root_resolved = Path(os.path.abspath(root))
    candidate = Path(os.path.abspath(path))
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ProductionControlError(f"{field_name} is outside the AppCare target") from exc
    return candidate


def _reject_symlink_parents(path: Path, root: Path, *, field_name: str) -> None:
    root_resolved = root.resolve(strict=False)
    current = path
    parents: list[Path] = []
    while current != root_resolved and current != current.parent:
        parents.append(current)
        current = current.parent
    for candidate in parents:
        if candidate.is_symlink():
            raise ProductionControlError(f"{field_name} crosses a symlink")


def _safe_tree(path: Path, root: Path, *, field_name: str) -> Path:
    candidate = _inside(path, root, field_name=field_name)
    _reject_symlink_parents(candidate, root, field_name=field_name)
    if candidate.exists() and candidate.is_symlink():
        raise ProductionControlError(f"{field_name} must not be a symlink")
    if candidate.exists():
        for directory, directories, files in os.walk(candidate, followlinks=False):
            directory_path = Path(directory)
            if directory_path.is_symlink():
                raise ProductionControlError(f"{field_name} contains a symlink")
            for name in (*directories, *files):
                if (directory_path / name).is_symlink():
                    raise ProductionControlError(f"{field_name} contains a symlink")
    return candidate


def _loopback_url(value: str, *, field_name: str) -> str:
    """Accept only a literal loopback HTTP endpoint with no redirect tricks."""

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ProductionControlError(f"{field_name} must be a loopback URL") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise ProductionControlError(f"{field_name} must be a loopback URL")
    return value


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep health verification on the configured loopback endpoint."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _reject_protected_target(path: Path) -> Path:
    candidate = Path(os.path.abspath(path))
    if candidate == Path(candidate.anchor):
        raise ProductionControlError("target_root is too broad")
    normalized = os.fspath(candidate).replace("\\", "/").casefold()
    protected = (
        "/var/www",
        "/root",
        "/home/debian/apps/appcare-opencode",
    )
    markers = ("wordpress", "barnd", "shield", "api.securityola.com")
    if any(normalized == value or normalized.startswith(f"{value}/") for value in protected):
        raise ProductionControlError("target_root is outside the AppCare boundary")
    if any(marker in normalized for marker in markers):
        raise ProductionControlError("target_root is outside the AppCare boundary")
    return candidate


@dataclass(frozen=True, slots=True)
class ReferenceDeploymentConfig:
    target_root: Path
    artifact_root: Path
    service_name: str
    health_url: str
    systemctl_path: str = "/usr/bin/systemctl"
    failure_health_url: str | None = None
    service_user: str | None = None
    service_group: str | None = None

    def __post_init__(self) -> None:
        target_root = _reject_protected_target(self.target_root)
        artifact_root = Path(os.path.abspath(self.artifact_root))
        object.__setattr__(self, "target_root", target_root)
        object.__setattr__(self, "artifact_root", artifact_root)
        validate_opaque_reference(self.service_name, field_name="service_name")
        if self.systemctl_path != "/usr/bin/systemctl":
            raise ProductionControlError("systemctl_path is fixed to the AppCare systemd binary")
        if (self.service_user is None) != (self.service_group is None):
            raise ProductionControlError("service user and group must be configured together")
        if self.service_user is not None:
            validate_opaque_reference(self.service_user, field_name="service_user")
            validate_opaque_reference(self.service_group or "", field_name="service_group")
        _loopback_url(self.health_url, field_name="reference health URL")
        if self.failure_health_url is not None:
            _loopback_url(self.failure_health_url, field_name="failure health URL")
        _inside(self.artifact_root, self.target_root, field_name="artifact_root")


class FilesystemReferenceProvider:
    """A real controlled target adapter used by the VPS rehearsal."""

    def __init__(self, config: ReferenceDeploymentConfig) -> None:
        self.config = config
        self._last_deployment: ProviderDeployment | None = None
        self._failure_health_used = False
        self.deploy_calls = 0
        self.verify_calls = 0
        self.rollback_calls = 0

    @property
    def _releases(self) -> Path:
        return _inside(
            self.config.target_root / "releases", self.config.target_root, field_name="releases"
        )

    @property
    def _current(self) -> Path:
        return Path(
            _inside(
                self.config.target_root / "current", self.config.target_root, field_name="current"
            )
        )

    @property
    def _previous(self) -> Path:
        return Path(
            _inside(
                self.config.target_root / "previous", self.config.target_root, field_name="previous"
            )
        )

    def _artifact(self, digest: str) -> tuple[Path, dict[str, str]]:
        artifact = _safe_tree(
            self.config.artifact_root / _digest(digest, field_name="artifact_digest"),
            self.config.artifact_root,
            field_name="artifact",
        )
        if not artifact.is_dir():
            raise ProductionControlError("artifact directory is missing")
        source = _safe_tree(artifact / "source", artifact, field_name="artifact source")
        if not source.is_dir():
            raise ProductionControlError("artifact source directory is missing")
        manifest_path = _inside(
            artifact / ".appcare-artifact.json", artifact, field_name="manifest"
        )
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ProductionControlError("artifact manifest is missing")
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProductionControlError("artifact manifest is malformed") from exc
        if not isinstance(raw, dict):
            raise ProductionControlError("artifact manifest is malformed")
        source_revision = raw.get("source_revision")
        artifact_digest = raw.get("artifact_digest")
        if not isinstance(source_revision, str) or not isinstance(artifact_digest, str):
            raise ProductionControlError("artifact identity is incomplete")
        normalized = {
            "source_revision": _revision(source_revision, field_name="source_revision"),
            "artifact_digest": _digest(artifact_digest, field_name="artifact_digest"),
        }
        if normalized["artifact_digest"] != artifact.name:
            raise ProductionControlError("artifact directory identity mismatch")
        return artifact, normalized

    def _ensure_layout(self) -> None:
        _reject_symlink_parents(
            self.config.target_root,
            self.config.target_root.parent,
            field_name="target_root",
        )
        if self.config.target_root.exists() and self.config.target_root.is_symlink():
            raise ProductionControlError("target_root must not be a symlink")
        self.config.target_root.mkdir(parents=True, exist_ok=True)
        _reject_symlink_parents(
            self._releases,
            self.config.target_root,
            field_name="releases",
        )
        _reject_symlink_parents(
            self.config.artifact_root,
            self.config.target_root,
            field_name="artifact_root",
        )
        self._releases.mkdir(parents=True, exist_ok=True)
        self.config.artifact_root.mkdir(parents=True, exist_ok=True)

    def _restart(self) -> bool:
        try:
            result = subprocess.run(  # noqa: S603 - executable and arguments are fixed by the boundary.
                [self.config.systemctl_path, "restart", self.config.service_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if result.returncode != 0:
            return False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._health_check()[0]:
                return True
            time.sleep(0.25)
        return False

    def _set_release_owner(self, release: Path) -> None:
        if self.config.service_user is None or self.config.service_group is None:
            return
        for directory, directories, files in os.walk(release, followlinks=False):
            paths = (
                Path(directory),
                *(Path(directory) / name for name in directories),
                *(Path(directory) / name for name in files),
            )
            for path in paths:
                if path.is_symlink():
                    raise ProductionControlError("release contains a symlink")
                try:
                    shutil.chown(
                        path, user=self.config.service_user, group=self.config.service_group
                    )
                except (LookupError, OSError) as exc:
                    raise ProductionControlError("release owner could not be assigned") from exc

    def _switch_current(self, release: Path) -> None:
        release = _inside(release, self._releases, field_name="release")
        if not release.is_dir() or release.is_symlink():
            raise ProductionControlError("release is not an ordinary directory")
        temporary = _inside(
            self.config.target_root / "current.next",
            self.config.target_root,
            field_name="current.next",
        )
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
        temporary.symlink_to(release, target_is_directory=True)
        os.replace(temporary, self._current)

    def _current_release(self) -> Path | None:
        if not self._current.is_symlink():
            return None
        resolved = self._current.resolve(strict=False)
        return _inside(resolved, self._releases, field_name="current release")

    def deploy(self, intent: DeploymentIntent) -> ProviderDeployment:
        self.deploy_calls += 1
        self._ensure_layout()
        artifact, identity = self._artifact(intent.artifact_digest)
        if identity["source_revision"] != intent.source_revision:
            raise ProductionControlError("artifact source revision mismatch")
        previous = self._current_release()
        if previous is not None:
            if self._previous.is_symlink():
                raise ProductionControlError("previous release pointer must not be a symlink")
            self._previous.write_text(str(previous), encoding="utf-8")
        release = _inside(
            self._releases / intent.artifact_digest,
            self._releases,
            field_name="release",
        )
        if not release.exists():
            shutil.copytree(artifact, release, symlinks=False)
        _safe_tree(release, self._releases, field_name="release")
        self._set_release_owner(release)
        self._switch_current(release)
        deployment = ProviderDeployment(
            deployment_ref=f"filesystem:{self.config.service_name}:{intent.artifact_digest[:24]}",
            target_environment="production",
            source_revision=identity["source_revision"],
            artifact_digest=identity["artifact_digest"],
        )
        self._last_deployment = deployment
        self._failure_health_used = False
        self._restart()
        return deployment

    def _health_check(self, health_url: str | None = None) -> tuple[bool, str]:
        target_url = health_url or self.config.health_url
        try:
            with _NO_REDIRECT_OPENER.open(target_url, timeout=5) as response:  # noqa: S310
                payload = response.read(16_384)
            decoded: Any = json.loads(payload.decode("utf-8"))
            passed = isinstance(decoded, dict) and decoded.get("status") == "ready"
        except (OSError, ValueError, UnicodeError, urllib.error.URLError):
            passed = False
            decoded = {"status": "unavailable"}
        receipt_digest = sha256(
            json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return passed, f"health:{receipt_digest[:32]}"

    def verify(
        self, intent: DeploymentIntent, deployment: ProviderDeployment
    ) -> ProviderVerification:
        self.verify_calls += 1
        del intent
        if (
            self._last_deployment is not None
            and deployment.deployment_ref != self._last_deployment.deployment_ref
        ):
            return ProviderVerification(
                deployment_ref=deployment.deployment_ref,
                passed=False,
                verification_ref="health:deployment-mismatch",
                failure_code="verification_identity_mismatch",
            )
        health_url = self.config.health_url
        if self.config.failure_health_url is not None and not self._failure_health_used:
            health_url = self.config.failure_health_url
            self._failure_health_used = True
        passed, receipt = self._health_check(health_url)
        return ProviderVerification(
            deployment_ref=deployment.deployment_ref,
            passed=passed,
            verification_ref=receipt,
            failure_code=None if passed else "health_check_failed",
        )

    def rollback(
        self, intent: DeploymentIntent, deployment: ProviderDeployment
    ) -> ProviderRollback:
        self.rollback_calls += 1
        del deployment
        try:
            previous_raw = self._previous.read_text(encoding="utf-8").strip()
            previous = _inside(Path(previous_raw), self._releases, field_name="previous release")
            _safe_tree(previous, self._releases, field_name="previous release")
            manifest = json.loads(
                (
                    _inside(previous / ".appcare-artifact.json", previous, field_name="manifest")
                ).read_text(encoding="utf-8")
            )
            if (
                manifest.get("source_revision") != intent.rollback_reference
                or manifest.get("artifact_digest") != intent.rollback_artifact_digest
            ):
                raise ProductionControlError("rollback artifact identity mismatch")
            self._switch_current(previous)
            restart_passed = self._restart()
            health_passed, _receipt = self._health_check()
            succeeded = restart_passed and health_passed
            return ProviderRollback(
                rollback_ref=f"filesystem-rollback:{intent.rollback_reference[:24]}",
                rollback_reference=intent.rollback_reference,
                succeeded=succeeded,
                failure_code=None if succeeded else "rollback_health_failed",
            )
        except (OSError, ValueError, ProductionControlError, KeyError):
            return ProviderRollback(
                rollback_ref="filesystem-rollback-failed",
                rollback_reference=intent.rollback_reference,
                succeeded=False,
                failure_code="rollback_reference_unavailable",
            )

    def recover_current(self) -> bool:
        """Rebuild the current release identity after a process restart."""

        current = self._current_release()
        if current is None:
            return False
        manifest_path = _inside(current / ".appcare-artifact.json", current, field_name="manifest")
        if not manifest_path.is_file() or manifest_path.is_symlink():
            return False
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return isinstance(manifest, dict) and self._health_check()[0]


__all__ = ["FilesystemReferenceProvider", "ReferenceDeploymentConfig"]
