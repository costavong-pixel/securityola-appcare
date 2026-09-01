from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any, cast

import pytest

import appcare.connectors.credential_vault as credential_vault_module
from appcare.connectors.credential_vault import (
    Ed25519KeyService,
    EncryptedCredentialVault,
    VaultCredentialProvider,
)
from appcare.connectors.linux_ssh_contracts import (
    BoundedLimits,
    ConnectionProbe,
    CredentialBoundaryError,
    HostKeyScanner,
    InMemoryOperationLedger,
    LinuxTarget,
    ProcessResult,
    ResolvedCredential,
)
from appcare.connectors.linux_ssh_transport import KnownHostsStore, LinuxSSHClient

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="Linux SSH runtime cleanup is POSIX-only"
)

KEY_BLOB = b"fixture-host-key"
KEY_DATA = base64.b64encode(KEY_BLOB).decode()
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(KEY_BLOB).digest()).decode().rstrip("=")


class _MasterKeyProvider:
    def load_key(self) -> bytes:
        return b"m" * 32


class _FaultingProvider(VaultCredentialProvider):
    def __init__(self, vault: EncryptedCredentialVault) -> None:
        super().__init__(vault)
        self.release_count = 0

    def release(self, credential: ResolvedCredential) -> None:
        self.release_count += 1
        super().release(credential)


def _target(credential_reference: str) -> LinuxTarget:
    return LinuxTarget(
        tenant_id="tenant-a",
        application_id="application-a",
        environment="staging",
        host="192.0.2.10",
        expected_hostname="app-a.internal",
        ssh_port=22,
        expected_host_key_fingerprint=FINGERPRINT,
        credential_reference=credential_reference,
        remote_user="appcare",
        approved_application_roots=("/srv/app",),
        approved_service_names=("app.service",),
        approved_database_identifiers=("mysql",),
        target_reference="target-a",
    )


class _Scanner(HostKeyScanner):
    def scan(self, target: LinuxTarget, *, limits: BoundedLimits) -> tuple[str, ...]:
        del target, limits
        return (f"192.0.2.10 ssh-ed25519 {KEY_DATA}",)


class _Runner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        stdout_limit: int,
        stderr_limit: int,
    ) -> ProcessResult:
        del timeout_seconds, stdout_limit, stderr_limit
        self.calls.append(argv)
        return ProcessResult(0, b"", b"")


def test_release_failure_abandons_claim_for_same_operation_retry(tmp_path: Path) -> None:
    vault = EncryptedCredentialVault(
        tmp_path / "credentials",
        master_key_provider=_MasterKeyProvider(),
    )
    record = Ed25519KeyService(vault).generate(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
    )
    provider = _FaultingProvider(vault)
    runner = _Runner()
    fsync_failure_injected = False
    scope = vault._runtime_scope(record.credential_reference)
    original_fsync = credential_vault_module._fsync_directory

    def fsync_with_post_unlink_failure(path: Path) -> None:
        nonlocal fsync_failure_injected
        if provider.release_count == 1 and path == scope and not fsync_failure_injected:
            fsync_failure_injected = True
            raise OSError("simulated post-unlink fsync failure")
        original_fsync(path)

    credential_vault_module._fsync_directory = fsync_with_post_unlink_failure
    try:
        client = LinuxSSHClient(
            _target(record.credential_reference),
            credential_provider=cast(Any, provider),
            runner=runner,
            known_hosts=KnownHostsStore(tmp_path / "known-hosts"),
            scanner=cast(HostKeyScanner, _Scanner()),
            operation_ledger=InMemoryOperationLedger(),
        )

        with pytest.raises(CredentialBoundaryError, match="durability|cleanup"):
            client.execute(ConnectionProbe("retry-release"))
        assert [entry.suffix for entry in scope.iterdir()] == [".lease"]
        result = client.execute(ConnectionProbe("retry-release"))
    finally:
        credential_vault_module._fsync_directory = original_fsync

    assert result.passed
    assert provider.release_count == 2
    assert fsync_failure_injected
    assert sum(call[0] == "ssh" for call in runner.calls) == 2
    EncryptedCredentialVault(
        vault.root,
        master_key_provider=_MasterKeyProvider(),
    )
    assert not scope.exists()
