from __future__ import annotations

import base64
import hashlib

import pytest

from appcare.connectors.linux_ssh_commands import CommandRegistry, RemoteCommand
from appcare.connectors.linux_ssh_contracts import (
    BoundedLimits,
    CapabilityClass,
    ConnectionProbe,
    LinuxTarget,
    OperationKind,
    OperationRejected,
    ServiceMetadataRead,
)


def _target() -> LinuxTarget:
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(b"k").digest()).decode().rstrip("=")
    return LinuxTarget(
        tenant_id="tenant-a",
        application_id="app-a",
        environment="staging",
        host="192.0.2.10",
        expected_hostname="app-a.internal",
        ssh_port=22,
        expected_host_key_fingerprint=fingerprint,
        credential_reference="vault://appcare/linux-a",
        remote_user="appcare",
        approved_application_roots=("/srv/app",),
        approved_service_names=("app.service",),
        approved_database_identifiers=("postgresql",),
        target_reference="target-a",
    )


def test_registry_contains_only_typed_read_only_commands() -> None:
    commands = CommandRegistry().commands_for(
        ConnectionProbe("op-1"),
        target=_target(),
        limits=BoundedLimits(),
    )
    assert commands[0].argv == ("true",)
    assert commands[0].capability_class == CapabilityClass.INVENTORY_READ
    assert all(command.argv[0] not in {"sh", "bash", "sudo"} for command in commands)


def test_service_command_requires_target_allowlist() -> None:
    registry = CommandRegistry()
    with pytest.raises(OperationRejected):
        registry.commands_for(
            ServiceMetadataRead("op-1", "unexpected.service"),
            target=_target(),
            limits=BoundedLimits(),
        )


def test_command_contract_rejects_shell_interpretation() -> None:
    with pytest.raises(OperationRejected):
        RemoteCommand(
            OperationKind.CONNECTION_PROBE,
            "bad",
            CapabilityClass.INVENTORY_READ,
            ("true", "&&", "uname"),
        )
