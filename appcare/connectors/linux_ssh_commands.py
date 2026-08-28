"""Closed, read-only command registry for the Linux/SSH connector."""

from __future__ import annotations

from dataclasses import dataclass

from .linux_ssh_contracts import (
    DENIED_CAPABILITY_CLASSES,
    READ_ONLY_CAPABILITY_CLASSES,
    ApplicationRootVerification,
    BoundedLimits,
    CapabilityClass,
    ConnectionProbe,
    FilesystemMetadataRead,
    HostInventory,
    LinuxOperation,
    LinuxTarget,
    NetworkBindingRead,
    OperationKind,
    OperationRejected,
    RuntimeMetadataRead,
    SafeFileRead,
    ServiceMetadataRead,
    StorageMetadataRead,
    WebServerMetadataRead,
    join_approved_path,
)

_ALLOWED_PROGRAMS = frozenset(
    {
        "apache2",
        "cat",
        "df",
        "head",
        "hostname",
        "httpd",
        "nginx",
        "node",
        "php",
        "python3",
        "realpath",
        "ss",
        "stat",
        "systemctl",
        "true",
        "uname",
    }
)
_FORBIDDEN_COMMAND_CHARS = frozenset("\x00\n\r;|&$><*?{}[]()!") | {chr(96)}


@dataclass(frozen=True, slots=True)
class RemoteCommand:
    operation: OperationKind
    step: str
    capability_class: CapabilityClass
    argv: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.argv or self.argv[0] not in _ALLOWED_PROGRAMS:
            raise OperationRejected("command executable is not registered")
        if not self.step or any(ord(character) < 32 for character in self.step):
            raise OperationRejected("command step is invalid")
        for argument in self.argv:
            if (
                not isinstance(argument, str)
                or not argument
                or any(character in _FORBIDDEN_COMMAND_CHARS for character in argument)
                or any(ord(character) < 32 for character in argument)
            ):
                raise OperationRejected("command argument is unsafe")
        if self.capability_class in DENIED_CAPABILITY_CLASSES:
            raise OperationRejected("command capability class is denied")
        if self.capability_class not in READ_ONLY_CAPABILITY_CLASSES:
            raise OperationRejected("command capability class is not read-only")


class CommandRegistry:
    """Build only static command templates with validated typed arguments."""

    def commands_for(
        self,
        operation: LinuxOperation,
        *,
        target: LinuxTarget,
        limits: BoundedLimits,
    ) -> tuple[RemoteCommand, ...]:
        if isinstance(operation, ConnectionProbe):
            return (
                self._command(operation.kind, "probe", CapabilityClass.INVENTORY_READ, ("true",)),
            )
        if isinstance(operation, HostInventory):
            return (
                self._command(
                    operation.kind, "hostname", CapabilityClass.INVENTORY_READ, ("hostname",)
                ),
                self._command(
                    operation.kind, "kernel", CapabilityClass.INVENTORY_READ, ("uname", "-srm")
                ),
                self._command(
                    operation.kind,
                    "os_release",
                    CapabilityClass.INVENTORY_READ,
                    ("cat", "--", "/etc/os-release"),
                ),
            )
        if isinstance(operation, FilesystemMetadataRead):
            self._require_root(target, operation.approved_root)
            return (
                self._command(
                    operation.kind,
                    "resolved_root",
                    CapabilityClass.FILESYSTEM_READ,
                    ("realpath", "-e", "--", operation.approved_root),
                ),
                self._command(
                    operation.kind,
                    "metadata",
                    CapabilityClass.FILESYSTEM_READ,
                    (
                        "stat",
                        "--format=%n:%F:%U:%G:%a:%s",
                        "--",
                        operation.approved_root,
                    ),
                ),
            )
        if isinstance(operation, SafeFileRead):
            self._require_root(target, operation.approved_root)
            path = join_approved_path(operation.approved_root, operation.relative_path)
            return (
                self._command(
                    operation.kind,
                    "file_metadata",
                    CapabilityClass.FILESYSTEM_READ,
                    ("stat", "--format=%F:%s", "--", path),
                ),
                self._command(
                    operation.kind,
                    "resolved_path",
                    CapabilityClass.FILESYSTEM_READ,
                    ("realpath", "--", path),
                ),
                self._command(
                    operation.kind,
                    "bounded_content",
                    CapabilityClass.FILESYSTEM_READ,
                    ("head", "-c", str(limits.max_file_bytes), "--", path),
                ),
            )
        if isinstance(operation, ServiceMetadataRead):
            if operation.service_name not in target.approved_service_names:
                raise OperationRejected("service is not approved for this target")
            return (
                self._command(
                    operation.kind,
                    "service",
                    CapabilityClass.INVENTORY_READ,
                    (
                        "systemctl",
                        "show",
                        "--no-pager",
                        "--property=Id,LoadState,ActiveState,SubState,FragmentPath",
                        operation.service_name,
                    ),
                ),
            )
        if isinstance(operation, WebServerMetadataRead):
            return tuple(
                self._command(
                    operation.kind,
                    step,
                    CapabilityClass.INVENTORY_READ,
                    command,
                )
                for step, command in (
                    ("nginx", ("nginx", "-V")),
                    ("apache2", ("apache2", "-v")),
                    ("httpd", ("httpd", "-v")),
                )
            )
        if isinstance(operation, RuntimeMetadataRead):
            return tuple(
                self._command(
                    operation.kind,
                    step,
                    CapabilityClass.INVENTORY_READ,
                    command,
                )
                for step, command in (
                    ("python3", ("python3", "--version")),
                    ("node", ("node", "--version")),
                    ("php", ("php", "--version")),
                )
            )
        if isinstance(operation, NetworkBindingRead):
            return (
                self._command(
                    operation.kind,
                    "listeners",
                    CapabilityClass.MONITORING_READ,
                    ("ss", "-lntH"),
                ),
            )
        if isinstance(operation, StorageMetadataRead):
            self._require_root(target, operation.approved_root)
            return (
                self._command(
                    operation.kind,
                    "resolved_root",
                    CapabilityClass.FILESYSTEM_READ,
                    ("realpath", "-e", "--", operation.approved_root),
                ),
                self._command(
                    operation.kind,
                    "storage",
                    CapabilityClass.FILESYSTEM_READ,
                    ("df", "-P", "-k", "--", operation.approved_root),
                ),
            )
        if isinstance(operation, ApplicationRootVerification):
            self._require_root(target, operation.approved_root)
            return (
                self._command(
                    operation.kind,
                    "resolved_root",
                    CapabilityClass.FILESYSTEM_READ,
                    ("realpath", "-e", "--", operation.approved_root),
                ),
                self._command(
                    operation.kind,
                    "root",
                    CapabilityClass.FILESYSTEM_READ,
                    (
                        "stat",
                        "--format=%n:%F:%U:%G:%a",
                        "--",
                        operation.approved_root,
                    ),
                ),
            )
        raise OperationRejected("operation type is not registered")

    @staticmethod
    def _require_root(target: LinuxTarget, root: str) -> None:
        if root not in target.approved_application_roots:
            raise OperationRejected("root is not approved for this target")

    @staticmethod
    def _command(
        operation: OperationKind,
        step: str,
        capability_class: CapabilityClass,
        argv: tuple[str, ...],
    ) -> RemoteCommand:
        return RemoteCommand(operation, step, capability_class, argv)


__all__ = ["CommandRegistry", "RemoteCommand"]

