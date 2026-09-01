"""Root-owned release binding for the AppCare SSH forced-command boundary."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import cast

APPCARE_SSH_WRAPPER_PATH = "/usr/local/libexec/securityola-appcare-ssh-wrapper"
APPCARE_RELEASE_GUARD_PATH = "/usr/local/libexec/securityola-appcare-release-guard"
APPCARE_RELEASE_MANIFEST_PATH = Path("/etc/securityola/appcare/ssh-release.json")
APPCARE_APPROVED_RELEASE_PATH = Path("/etc/securityola/appcare/approved-release.json")
_PACKAGE_NAME = "securityola-appcare"
_SCHEMA_VERSION = 1
_APPROVAL_SCHEMA_VERSION = 1
_MAX_MANIFEST_BYTES = 16_384
_MAX_BOUND_FILE_BYTES = 4 * 1024 * 1024
_MAX_PACKAGE_FILES = 4096
_MAX_PACKAGE_TREE_BYTES = 64 * 1024 * 1024
_EXPECTED_MODULE_RELATIVE_PATH = "connectors/ssh_command_wrapper.py"
_EXPECTED_BINDING_RELATIVE_PATH = "connectors/release_binding.py"
_RELEASE_REVISION = re.compile(r"^[0-9a-f]{40,64}$")
_PACKAGE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseBindingError(ValueError):
    """The installed launcher and AppCare module are not release-bound."""


def verify_release_binding(*, module_path: Path) -> None:
    """Fail closed unless the root-owned manifest binds the active module."""

    module = _resolved_path(module_path, "AppCare SSH module")
    manifest_path = _validated_path(APPCARE_RELEASE_MANIFEST_PATH, "release manifest")
    manifest = _manifest(_read_trusted_file(manifest_path, "release manifest"))
    approved = _approved_release()
    if manifest["release_revision"] != approved["release_revision"]:
        raise ReleaseBindingError("release revision is not approved")
    expected_module = manifest["module_path"]
    if expected_module != module.as_posix():
        raise ReleaseBindingError("release module binding does not match")
    if manifest["wrapper_path"] != APPCARE_SSH_WRAPPER_PATH:
        raise ReleaseBindingError("release wrapper binding does not match")
    if manifest["guard_path"] != APPCARE_RELEASE_GUARD_PATH:
        raise ReleaseBindingError("release guard binding does not match")
    package_version = _package_version()
    if (
        manifest["package_version"] != package_version
        or approved["package_version"] != package_version
    ):
        raise ReleaseBindingError("release package binding does not match")
    module_sha256 = _sha256_file(module, "AppCare SSH module")
    if manifest["module_sha256"] != module_sha256:
        raise ReleaseBindingError("release module digest does not match")
    package_root = _package_root(module)
    if _package_relative_path(module, package_root) != _EXPECTED_MODULE_RELATIVE_PATH:
        raise ReleaseBindingError("release module path is not the approved entrypoint")
    binding = _resolved_path(Path(__file__), "release binding module")
    if manifest["binding_path"] != binding.as_posix():
        raise ReleaseBindingError("release binding module does not match")
    binding_sha256 = _sha256_file(binding, "release binding module")
    if manifest["binding_sha256"] != binding_sha256:
        raise ReleaseBindingError("release binding module digest does not match")
    wrapper = _validated_path(Path(APPCARE_SSH_WRAPPER_PATH), "SSH wrapper")
    wrapper_sha256 = _sha256_file(wrapper, "SSH wrapper", executable=True)
    if manifest["wrapper_sha256"] != wrapper_sha256:
        raise ReleaseBindingError("release wrapper digest does not match")
    guard = _validated_path(Path(APPCARE_RELEASE_GUARD_PATH), "release guard")
    guard_sha256 = _sha256_file(guard, "release guard", executable=True)
    if manifest["guard_sha256"] != guard_sha256:
        raise ReleaseBindingError("release guard digest does not match")
    package_tree_sha256 = _package_tree_sha256(package_root)
    if manifest["package_tree_sha256"] != package_tree_sha256:
        raise ReleaseBindingError("release package tree digest does not match")
    artifact_sha256 = _artifact_sha256(
        package_version=package_version,
        wrapper_sha256=wrapper_sha256,
        guard_sha256=guard_sha256,
        module_sha256=module_sha256,
        binding_sha256=binding_sha256,
        package_tree_sha256=package_tree_sha256,
    )
    if (
        manifest["artifact_sha256"] != artifact_sha256
        or approved["artifact_sha256"] != artifact_sha256
    ):
        raise ReleaseBindingError("release artifact digest does not match")


def install_release_binding(release_revision: str) -> None:
    """Write the root-owned manifest after the approved artifact is installed."""

    if os.name != "posix":
        raise ReleaseBindingError("release binding installation requires root")
    geteuid = cast(Callable[[], int], getattr(os, "geteuid"))  # noqa: B009
    if geteuid() != 0:
        raise ReleaseBindingError("release binding installation requires root")
    approved = _approved_release()
    release_revision = _validate_release_revision(release_revision, field_name="release revision")
    if release_revision != approved["release_revision"]:
        raise ReleaseBindingError("release revision is not approved")
    wrapper = _validated_path(Path(APPCARE_SSH_WRAPPER_PATH), "SSH wrapper")
    module = _installed_ssh_module_path()
    payload = build_release_manifest(
        release_revision,
        module_path=module,
        wrapper_path=wrapper,
    )
    if (
        payload["package_version"] != approved["package_version"]
        or payload["artifact_sha256"] != approved["artifact_sha256"]
    ):
        raise ReleaseBindingError("installed artifact is not approved")
    _write_manifest(APPCARE_RELEASE_MANIFEST_PATH, payload)


def build_release_manifest(
    release_revision: str,
    *,
    module_path: Path,
    wrapper_path: Path,
    binding_path: Path | None = None,
    guard_path: Path | None = None,
    package_version: str | None = None,
) -> dict[str, object]:
    """Build a non-secret manifest from trusted installed release files."""

    _validate_release_revision(release_revision, field_name="release revision")
    module = _resolved_path(module_path, "AppCare SSH module")
    wrapper = _validated_path(wrapper_path, "SSH wrapper")
    if wrapper.as_posix() != APPCARE_SSH_WRAPPER_PATH:
        raise ReleaseBindingError("release wrapper path is invalid")
    guard = _validated_path(guard_path or Path(APPCARE_RELEASE_GUARD_PATH), "release guard")
    if guard.as_posix() != APPCARE_RELEASE_GUARD_PATH:
        raise ReleaseBindingError("release guard path is invalid")
    binding = _resolved_path(binding_path or Path(__file__), "release binding module")
    version = package_version or _package_version()
    if _PACKAGE_VERSION.fullmatch(version) is None:
        raise ReleaseBindingError("release package version is invalid")
    package_root = _package_root(module)
    if _package_relative_path(module, package_root) != _EXPECTED_MODULE_RELATIVE_PATH:
        raise ReleaseBindingError("release module path is not the approved entrypoint")
    wrapper_sha256 = _sha256_file(wrapper, "SSH wrapper", executable=True)
    guard_sha256 = _sha256_file(guard, "release guard", executable=True)
    module_sha256 = _sha256_file(module, "AppCare SSH module")
    binding_sha256 = _sha256_file(binding, "release binding module")
    package_tree_sha256 = _package_tree_sha256(package_root)
    return {
        "schema_version": _SCHEMA_VERSION,
        "release_revision": release_revision,
        "package_version": version,
        "wrapper_path": APPCARE_SSH_WRAPPER_PATH,
        "wrapper_sha256": wrapper_sha256,
        "guard_path": APPCARE_RELEASE_GUARD_PATH,
        "guard_sha256": guard_sha256,
        "module_path": module.as_posix(),
        "module_sha256": module_sha256,
        "binding_path": binding.as_posix(),
        "binding_sha256": binding_sha256,
        "package_tree_sha256": package_tree_sha256,
        "artifact_sha256": _artifact_sha256(
            package_version=version,
            wrapper_sha256=wrapper_sha256,
            guard_sha256=guard_sha256,
            module_sha256=module_sha256,
            binding_sha256=binding_sha256,
            package_tree_sha256=package_tree_sha256,
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] != "--release-revision":
        return _reject()
    try:
        install_release_binding(arguments[1])
    except (OSError, ReleaseBindingError, ValueError):
        return _reject()
    return 0


def _manifest(raw: bytes) -> dict[str, str | int]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBindingError("release manifest is invalid") from exc
    expected = {
        "schema_version",
        "release_revision",
        "package_version",
        "wrapper_path",
        "wrapper_sha256",
        "guard_path",
        "guard_sha256",
        "module_path",
        "module_sha256",
        "binding_path",
        "binding_sha256",
        "package_tree_sha256",
        "artifact_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ReleaseBindingError("release manifest schema is invalid")
    schema_version = value.get("schema_version")
    revision = value.get("release_revision")
    version = value.get("package_version")
    wrapper_path = value.get("wrapper_path")
    wrapper_sha256 = value.get("wrapper_sha256")
    guard_path = value.get("guard_path")
    guard_sha256 = value.get("guard_sha256")
    module_path = value.get("module_path")
    module_sha256 = value.get("module_sha256")
    binding_path = value.get("binding_path")
    binding_sha256 = value.get("binding_sha256")
    package_tree_sha256 = value.get("package_tree_sha256")
    artifact_sha256 = value.get("artifact_sha256")
    if (
        type(schema_version) is not int
        or schema_version != _SCHEMA_VERSION
        or not isinstance(revision, str)
        or _RELEASE_REVISION.fullmatch(revision) is None
        or not isinstance(version, str)
        or _PACKAGE_VERSION.fullmatch(version) is None
        or wrapper_path != APPCARE_SSH_WRAPPER_PATH
        or not isinstance(wrapper_sha256, str)
        or _SHA256.fullmatch(wrapper_sha256) is None
        or guard_path != APPCARE_RELEASE_GUARD_PATH
        or not isinstance(guard_sha256, str)
        or _SHA256.fullmatch(guard_sha256) is None
        or not isinstance(module_path, str)
        or not module_path.startswith("/")
        or ".." in Path(module_path).parts
        or not isinstance(module_sha256, str)
        or _SHA256.fullmatch(module_sha256) is None
        or not isinstance(binding_path, str)
        or not binding_path.startswith("/")
        or ".." in Path(binding_path).parts
        or not isinstance(binding_sha256, str)
        or _SHA256.fullmatch(binding_sha256) is None
        or not isinstance(package_tree_sha256, str)
        or _SHA256.fullmatch(package_tree_sha256) is None
        or not isinstance(artifact_sha256, str)
        or _SHA256.fullmatch(artifact_sha256) is None
    ):
        raise ReleaseBindingError("release manifest values are invalid")
    return {
        "schema_version": schema_version,
        "release_revision": revision,
        "package_version": version,
        "wrapper_path": wrapper_path,
        "wrapper_sha256": wrapper_sha256,
        "guard_path": guard_path,
        "guard_sha256": guard_sha256,
        "module_path": module_path,
        "module_sha256": module_sha256,
        "binding_path": binding_path,
        "binding_sha256": binding_sha256,
        "package_tree_sha256": package_tree_sha256,
        "artifact_sha256": artifact_sha256,
    }


def _validate_release_revision(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _RELEASE_REVISION.fullmatch(value) is None:
        raise ReleaseBindingError(f"{field_name} is invalid")
    return value


def _approved_release() -> dict[str, str]:
    raw = _read_trusted_file(
        _validated_path(APPCARE_APPROVED_RELEASE_PATH, "approved release"),
        "approved release",
    )
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ReleaseBindingError("approved release is too large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBindingError("approved release is invalid") from exc
    expected = {"schema_version", "release_revision", "package_version", "artifact_sha256"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ReleaseBindingError("approved release schema is invalid")
    schema_version = value.get("schema_version")
    release_revision = value.get("release_revision")
    package_version = value.get("package_version")
    artifact_sha256 = value.get("artifact_sha256")
    if (
        type(schema_version) is not int
        or schema_version != _APPROVAL_SCHEMA_VERSION
        or not isinstance(release_revision, str)
        or _RELEASE_REVISION.fullmatch(release_revision) is None
        or not isinstance(package_version, str)
        or _PACKAGE_VERSION.fullmatch(package_version) is None
        or not isinstance(artifact_sha256, str)
        or _SHA256.fullmatch(artifact_sha256) is None
    ):
        raise ReleaseBindingError("approved release values are invalid")
    return {
        "release_revision": release_revision,
        "package_version": package_version,
        "artifact_sha256": artifact_sha256,
    }


def _artifact_sha256(
    *,
    package_version: str,
    wrapper_sha256: str,
    guard_sha256: str,
    module_sha256: str,
    binding_sha256: str,
    package_tree_sha256: str,
) -> str:
    payload = json.dumps(
        {
            "package_name": _PACKAGE_NAME,
            "package_version": package_version,
            "wrapper_sha256": wrapper_sha256,
            "guard_sha256": guard_sha256,
            "module_sha256": module_sha256,
            "binding_sha256": binding_sha256,
            "package_tree_sha256": package_tree_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _package_root(module: Path) -> Path:
    if module.name != "ssh_command_wrapper.py" or module.parent.name != "connectors":
        raise ReleaseBindingError("release module path is invalid")
    root = module.parent.parent
    if root.name != "appcare":
        raise ReleaseBindingError("release package root is invalid")
    return root


def _package_relative_path(path: Path, package_root: Path) -> str:
    try:
        return path.relative_to(package_root).as_posix()
    except ValueError as exc:
        raise ReleaseBindingError("release module is outside the package") from exc


def _package_tree_sha256(package_root: Path) -> str:
    entries: list[bytes] = []
    total_bytes = 0
    for directory, dirnames, filenames in os.walk(package_root, topdown=True, followlinks=False):
        current = Path(directory)
        for dirname in dirnames:
            if (current / dirname).is_symlink():
                raise ReleaseBindingError("release package tree contains a symlink")
        dirnames[:] = sorted(dirname for dirname in dirnames if dirname != "__pycache__")
        for filename in sorted(filenames):
            if filename.endswith(".pyc"):
                raise ReleaseBindingError("release package tree contains bytecode")
            path = current / filename
            if path.is_symlink():
                raise ReleaseBindingError("release package tree contains a symlink")
            relative = _package_relative_path(path, package_root)
            raw = _read_trusted_file(path, f"package file {relative}")
            total_bytes += len(raw)
            if total_bytes > _MAX_PACKAGE_TREE_BYTES:
                raise ReleaseBindingError("release package tree is too large")
            entries.append(f"{relative}\0{hashlib.sha256(raw).hexdigest()}\n".encode())
            if len(entries) > _MAX_PACKAGE_FILES:
                raise ReleaseBindingError("release package tree has too many files")
    if not entries:
        raise ReleaseBindingError("release package tree is empty")
    return hashlib.sha256(b"".join(entries)).hexdigest()


def _package_version() -> str:
    try:
        return importlib.metadata.version(_PACKAGE_NAME)
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReleaseBindingError("release package metadata is unavailable") from exc


def _installed_ssh_module_path() -> Path:
    from . import ssh_command_wrapper

    return _resolved_path(Path(ssh_command_wrapper.__file__), "AppCare SSH module")


def _validated_path(path: Path, field_name: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path == Path(path.anchor)
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ReleaseBindingError(f"{field_name} path is unsafe")
    return path


def _resolved_path(path: Path, field_name: str) -> Path:
    path = _validated_path(path, field_name)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseBindingError(f"{field_name} is unavailable") from exc
    if resolved != path and field_name != "AppCare SSH module":
        raise ReleaseBindingError(f"{field_name} is a symlink")
    return resolved


def _trusted_parent(path: Path, field_name: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise ReleaseBindingError(f"{field_name} parent is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise ReleaseBindingError(f"{field_name} parent is invalid")
        if os.name == "posix" and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022):
            raise ReleaseBindingError(f"{field_name} parent ownership is unsafe")


def _read_trusted_file(path: Path, field_name: str, *, executable: bool = False) -> bytes:
    path = _validated_path(path, field_name)
    _trusted_parent(path, field_name)
    if path.is_symlink():
        raise ReleaseBindingError(f"{field_name} is a symlink")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_BOUND_FILE_BYTES:
            raise ReleaseBindingError(f"{field_name} is invalid")
        if os.name == "posix" and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022):
            raise ReleaseBindingError(f"{field_name} ownership is unsafe")
        if executable and not metadata.st_mode & 0o111:
            raise ReleaseBindingError(f"{field_name} is not executable")
        chunks: list[bytes] = []
        total = 0
        while total <= _MAX_BOUND_FILE_BYTES:
            chunk = os.read(descriptor, min(65_536, _MAX_BOUND_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size or len(raw) > _MAX_BOUND_FILE_BYTES:
            raise ReleaseBindingError(f"{field_name} read is incomplete")
        return raw
    except ReleaseBindingError:
        raise
    except OSError as exc:
        raise ReleaseBindingError(f"{field_name} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _sha256_file(path: Path, field_name: str, *, executable: bool = False) -> str:
    return hashlib.sha256(_read_trusted_file(path, field_name, executable=executable)).hexdigest()


def _write_manifest(path: Path, payload: Mapping[str, object]) -> None:
    path = _validated_path(path, "release manifest")
    _trusted_parent(path, "release manifest")
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ReleaseBindingError("release manifest is too large")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".ssh-release.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ReleaseBindingError("release manifest write failed")
            offset += written
        fchmod = cast(Callable[[int, int], None], getattr(os, "fchmod"))  # noqa: B009
        fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject() -> int:
    sys.stderr.write("AppCare release binding rejected\n")
    return 126


__all__ = [
    "APPCARE_APPROVED_RELEASE_PATH",
    "APPCARE_RELEASE_MANIFEST_PATH",
    "APPCARE_RELEASE_GUARD_PATH",
    "APPCARE_SSH_WRAPPER_PATH",
    "ReleaseBindingError",
    "build_release_manifest",
    "install_release_binding",
    "main",
    "verify_release_binding",
]


if __name__ == "__main__":
    raise SystemExit(main())
