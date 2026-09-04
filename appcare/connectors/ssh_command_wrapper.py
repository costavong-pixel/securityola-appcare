"""Server-side forced-command boundary for AppCare's Linux SSH account."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..readiness.contracts import validate_scope_segment
from .linux_ssh_contracts import (
    BoundedLimits,
    LinuxTarget,
    validate_absolute_root,
    validate_identifier,
)
from .release_binding import (
    APPCARE_SSH_WRAPPER_PATH,
    verify_release_binding,
)

DEFAULT_PROFILE_ROOT = Path("/etc/securityola/appcare/ssh-profiles")
_PROFILE_SCHEMA_VERSION = 1
_MAX_PROFILE_BYTES = 65_536
_MAX_FILE_BYTES = 1_048_576
_PROFILE_ID = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_COMMAND_CHARS = frozenset("\x00\n\r;|&$><*?{}[]()!'\"`\\")
_SECRET_PATH_PARTS = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        "authorized_keys",
        "credentials",
        "credential",
        "id_ed25519",
        "id_rsa",
        "passwd",
        "private",
        "secrets",
        "shadow",
    }
)
_EXECUTABLE_PATHS: dict[str, tuple[str, ...]] = {
    "apache2": ("/usr/sbin/apache2",),
    "cat": ("/usr/bin/cat", "/bin/cat"),
    "df": ("/usr/bin/df", "/bin/df"),
    "head": ("/usr/bin/head", "/bin/head"),
    "hostname": ("/usr/bin/hostname", "/bin/hostname"),
    "httpd": ("/usr/sbin/httpd", "/usr/bin/httpd"),
    "nginx": ("/usr/sbin/nginx", "/usr/bin/nginx"),
    "node": ("/usr/bin/node", "/usr/local/bin/node"),
    "php": ("/usr/bin/php", "/usr/local/bin/php"),
    "python3": ("/usr/bin/python3", "/usr/local/bin/python3"),
    "realpath": ("/usr/bin/realpath", "/bin/realpath"),
    "ss": ("/usr/bin/ss", "/bin/ss"),
    "stat": ("/usr/bin/stat", "/bin/stat"),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
    "true": ("/usr/bin/true", "/bin/true"),
    "uname": ("/usr/bin/uname", "/bin/uname"),
}


class SSHCommandRejected(ValueError):
    """A forced-command request is outside the target profile."""


def profile_id(target_reference: str) -> str:
    """Return the non-secret profile filename identifier for a target."""

    validate_scope_segment(target_reference, field_name="target_reference")
    return hashlib.sha256(target_reference.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SshCommandProfile:
    """Target-scoped data used by the root-installed wrapper."""

    target_reference: str
    approved_application_roots: tuple[str, ...]
    approved_service_names: tuple[str, ...]
    max_file_bytes: int = 32_768

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "target_reference",
            validate_scope_segment(self.target_reference, field_name="target_reference"),
        )
        roots = tuple(validate_absolute_root(root) for root in self.approved_application_roots)
        services = tuple(
            validate_identifier(service, field_name="approved_service_name")
            for service in self.approved_service_names
        )
        if not roots or len(roots) != len(set(roots)):
            raise SSHCommandRejected("application root profile is invalid")
        if len(services) != len(set(services)):
            raise SSHCommandRejected("service profile is invalid")
        if (
            isinstance(self.max_file_bytes, bool)
            or not isinstance(self.max_file_bytes, int)
            or not 1 <= self.max_file_bytes <= _MAX_FILE_BYTES
        ):
            raise SSHCommandRejected("file limit profile is invalid")
        object.__setattr__(self, "approved_application_roots", tuple(sorted(roots)))
        object.__setattr__(self, "approved_service_names", tuple(sorted(services)))

    @classmethod
    def from_target(
        cls,
        target: LinuxTarget,
        *,
        limits: BoundedLimits | None = None,
    ) -> SshCommandProfile:
        bounded = limits or BoundedLimits()
        return cls(
            target_reference=target.target_reference,
            approved_application_roots=target.approved_application_roots,
            approved_service_names=target.approved_service_names,
            max_file_bytes=bounded.max_file_bytes,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SshCommandProfile:
        expected = {
            "schema_version",
            "target_reference",
            "approved_application_roots",
            "approved_service_names",
            "max_file_bytes",
        }
        if set(value) != expected or value.get("schema_version") != _PROFILE_SCHEMA_VERSION:
            raise SSHCommandRejected("command profile schema is invalid")
        roots = value.get("approved_application_roots")
        services = value.get("approved_service_names")
        if (
            not isinstance(roots, list)
            or not all(isinstance(root, str) for root in roots)
            or not isinstance(services, list)
            or not all(isinstance(service, str) for service in services)
        ):
            raise SSHCommandRejected("command profile values are invalid")
        return cls(
            target_reference=_string_value(value, "target_reference"),
            approved_application_roots=tuple(roots),
            approved_service_names=tuple(services),
            max_file_bytes=value.get("max_file_bytes"),  # type: ignore[arg-type]
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _PROFILE_SCHEMA_VERSION,
            "target_reference": self.target_reference,
            "approved_application_roots": list(self.approved_application_roots),
            "approved_service_names": list(self.approved_service_names),
            "max_file_bytes": self.max_file_bytes,
        }


def validate_original_command(
    original_command: str,
    profile: SshCommandProfile,
) -> tuple[str, ...]:
    """Parse SSH_ORIGINAL_COMMAND and enforce the closed typed command set."""

    if (
        not isinstance(original_command, str)
        or not original_command.strip()
        or any(character in _FORBIDDEN_COMMAND_CHARS for character in original_command)
        or any(ord(character) < 32 for character in original_command)
    ):
        raise SSHCommandRejected("command syntax is invalid")
    try:
        argv = tuple(shlex.split(original_command, posix=True))
    except ValueError as exc:
        raise SSHCommandRejected("command syntax is invalid") from exc
    if not argv or any(not argument for argument in argv):
        raise SSHCommandRejected("command syntax is invalid")
    if _is_exact(argv, ("true",)):
        return argv
    if _is_exact(argv, ("hostname",)):
        return argv
    if _is_exact(argv, ("uname", "-srm")):
        return argv
    if _is_exact(argv, ("cat", "--", "/etc/os-release")):
        return argv
    if _is_exact(argv, ("ss", "-lntH")):
        return argv
    if len(argv) == 2 and argv in {
        ("nginx", "-V"),
        ("apache2", "-v"),
        ("httpd", "-v"),
        ("python3", "--version"),
        ("node", "--version"),
        ("php", "--version"),
    }:
        return argv
    if len(argv) == 5 and argv[:2] == ("head", "-c") and argv[3] == "--":
        limit = _decimal(argv[2])
        if 1 <= limit <= profile.max_file_bytes and _approved_path(argv[4], profile):
            return argv
    if (
        len(argv) == 4
        and argv[0] == "realpath"
        and argv[1:3] == ("-e", "--")
        and _approved_root(argv[3], profile)
    ):
        return argv
    if (
        len(argv) == 3
        and argv[0] == "realpath"
        and argv[1] == "--"
        and _approved_path(argv[2], profile)
    ):
        return argv
    if (
        len(argv) == 5
        and argv[0] == "df"
        and argv[1:3] == ("-P", "-k")
        and argv[3] == "--"
        and _approved_root(argv[4], profile)
    ):
        return argv
    if (
        len(argv) == 4
        and argv[0] == "stat"
        and argv[1] == "--format=%n:%F:%U:%G:%a:%s:%d:%i"
        and argv[2] == "--"
        and _approved_root(argv[3], profile)
    ):
        return argv
    if (
        len(argv) == 4
        and argv[0] == "stat"
        and argv[1] == "--format=%n:%F:%U:%G:%a"
        and argv[2] == "--"
        and _approved_root(argv[3], profile)
    ):
        return argv
    if (
        len(argv) == 4
        and argv[0] == "stat"
        and argv[1] == "--format=%F:%s"
        and argv[2] == "--"
        and _approved_path(argv[3], profile)
    ):
        return argv
    if (
        len(argv) == 5
        and argv[:4]
        == (
            "systemctl",
            "show",
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,FragmentPath",
        )
        and argv[4] in profile.approved_service_names
    ):
        return argv
    raise SSHCommandRejected("command is not allowlisted")


def load_profile(
    requested_profile_id: str,
    *,
    profile_root: Path = DEFAULT_PROFILE_ROOT,
) -> SshCommandProfile:
    if _PROFILE_ID.fullmatch(requested_profile_id) is None:
        raise SSHCommandRejected("profile identifier is invalid")
    if not profile_root.is_absolute() or any(part in {".", ".."} for part in profile_root.parts):
        raise SSHCommandRejected("profile root is invalid")
    if profile_root.is_symlink():
        raise SSHCommandRejected("profile root is a symlink")
    try:
        root_metadata = os.stat(profile_root, follow_symlinks=False)
    except OSError as exc:
        raise SSHCommandRejected("profile root is unavailable") from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise SSHCommandRejected("profile root is invalid")
    if os.name == "posix" and (
        root_metadata.st_uid != 0 or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise SSHCommandRejected("profile root ownership is unsafe")
    path = profile_root / f"{requested_profile_id}.json"
    if path.is_symlink():
        raise SSHCommandRejected("profile is a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_PROFILE_BYTES:
            raise SSHCommandRejected("profile is invalid")
        if os.name == "posix" and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022):
            raise SSHCommandRejected("profile ownership is unsafe")
        raw_bytes = bytearray()
        while len(raw_bytes) <= _MAX_PROFILE_BYTES:
            chunk = os.read(descriptor, min(4_096, _MAX_PROFILE_BYTES + 1 - len(raw_bytes)))
            if not chunk:
                break
            raw_bytes.extend(chunk)
            if len(raw_bytes) > _MAX_PROFILE_BYTES:
                raise SSHCommandRejected("profile is too large")
        if len(raw_bytes) != metadata.st_size:
            raise SSHCommandRejected("profile read is incomplete")
        raw = bytes(raw_bytes)
    except SSHCommandRejected:
        raise
    except (OSError, ValueError) as exc:
        raise SSHCommandRejected("profile is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SSHCommandRejected("profile is invalid") from exc
    if not isinstance(value, Mapping):
        raise SSHCommandRejected("profile is invalid")
    profile = SshCommandProfile.from_dict(value)
    if profile_id(profile.target_reference) != requested_profile_id:
        raise SSHCommandRejected("profile identity does not match")
    return profile


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] != "--profile-id":
        return _reject()
    try:
        verify_release_binding(module_path=Path(__file__))
        profile = load_profile(arguments[1])
        original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
        command = validate_original_command(original, profile)
        executable = _resolve_executable(command[0])
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
        os.execve(  # noqa: S606 - executable and argv are closed by the allowlist
            executable, (executable, *command[1:]), environment
        )
    except (SSHCommandRejected, OSError, ValueError):
        return _reject()
    return 126


def _is_exact(argv: tuple[str, ...], expected: tuple[str, ...]) -> bool:
    return argv == expected


def _decimal(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise SSHCommandRejected("command limit is invalid")
    return int(value)


def _approved_root(value: str, profile: SshCommandProfile) -> bool:
    try:
        root = validate_absolute_root(value)
    except ValueError:
        return False
    return root in profile.approved_application_roots


def _approved_path(value: str, profile: SshCommandProfile) -> bool:
    if not value.startswith("/") or "\\" in value or "//" in value:
        return False
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError):
        return False
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        return False
    if any(part.casefold() in _SECRET_PATH_PARTS for part in path.parts):
        return False
    if not any(
        value == root or value.startswith(f"{root}/") for root in profile.approved_application_roots
    ):
        return False
    if os.name != "posix":
        return True
    try:
        resolved = Path(value).resolve(strict=True)
    except OSError:
        return False
    resolved_text = resolved.as_posix()
    return any(
        resolved_text == root or resolved_text.startswith(f"{root}/")
        for root in profile.approved_application_roots
    )


def _resolve_executable(name: str) -> str:
    for candidate in _EXECUTABLE_PATHS.get(name, ()):
        try:
            metadata = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(candidate, os.X_OK):
            return candidate
    raise SSHCommandRejected("approved executable is unavailable")


def _reject() -> int:
    sys.stderr.write("AppCare SSH command rejected\n")
    return 126


def _string_value(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise SSHCommandRejected("profile value is invalid")
    return result


__all__ = [
    "APPCARE_SSH_WRAPPER_PATH",
    "DEFAULT_PROFILE_ROOT",
    "SSHCommandRejected",
    "SshCommandProfile",
    "load_profile",
    "main",
    "profile_id",
    "validate_original_command",
]


if __name__ == "__main__":
    raise SystemExit(main())
