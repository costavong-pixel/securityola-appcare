from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from appcare.connectors.linux_ssh_contracts import (
    BoundedLimits,
    ConnectionProbe,
    CredentialBoundaryError,
    CredentialProvider,
    CredentialStatus,
    EvidenceClass,
    FilesystemMetadataRead,
    HostInventory,
    HostKeyScanner,
    InMemoryOperationLedger,
    LinuxCredentialMetadata,
    LinuxCredentialRegistry,
    LinuxInventorySnapshot,
    LinuxTarget,
    OperationStatus,
    ProcessResult,
    ResolvedCredential,
    SafeFileRead,
    ServiceMetadataRead,
)
from appcare.connectors.linux_ssh_transport import (
    HostKeyVerificationError,
    KnownHostsStore,
    LinuxSSHClient,
    OpenSshHostKeyScanner,
    verify_host_key,
)
from appcare.readiness import (
    ApplicationCapabilityRegistry,
    CapabilityStatus,
    SupportabilityEvaluator,
)

KEY_BLOB = b"fixture-host-key"
KEY_DATA = base64.b64encode(KEY_BLOB).decode()
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(KEY_BLOB).digest()).decode().rstrip("=")


def target(**changes: object) -> LinuxTarget:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "application_id": "application-a",
        "environment": "production",
        "host": "192.0.2.10",
        "expected_hostname": "app-a.internal",
        "ssh_port": 22,
        "expected_host_key_fingerprint": FINGERPRINT,
        "credential_reference": "vault://appcare/linux-a",
        "remote_user": "appcare",
        "approved_application_roots": ("/srv/app",),
        "approved_service_names": ("app.service",),
        "approved_database_identifiers": ("postgresql",),
        "target_reference": "target-a",
    }
    values.update(changes)
    return LinuxTarget(**cast(Any, values))


class FakeCredentials:
    def __init__(self, allowed: Mapping[tuple[str, str, str], ResolvedCredential]) -> None:
        self.allowed = dict(allowed)

    def resolve(self, current: LinuxTarget) -> ResolvedCredential:
        try:
            return self.allowed[
                (current.tenant_id, current.application_id, current.credential_reference)
            ]
        except KeyError as exc:
            raise CredentialBoundaryError("credential reference is unavailable") from exc


class FakeRunner:
    def __init__(self, responses: Mapping[str, ProcessResult]) -> None:
        self.responses = dict(responses)
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
        if argv[0] == "ssh-keyscan":
            return ProcessResult(0, b"192.0.2.10 ssh-ed25519 " + KEY_DATA.encode() + b"\n", b"")
        if argv[0] == "realpath":
            return ProcessResult(0, (argv[-1] + "\n").encode(), b"")
        if argv[0] == "stat" and argv[1] == "--format=%n:%F:%U:%G:%a:%s":
            return ProcessResult(
                0, (argv[-1] + ":directory:appcare:appcare:700:42\n").encode(), b""
            )
        return self.responses.get(argv[-1], ProcessResult(0, b"", b""))


def credential(
    tenant_id: str = "tenant-a",
    application_id: str = "application-a",
    reference: str = "vault://appcare/linux-a",
) -> tuple[LinuxCredentialMetadata, ResolvedCredential]:
    metadata = LinuxCredentialMetadata(
        credential_reference=reference,
        tenant_id=tenant_id,
        application_id=application_id,
    )
    return metadata, ResolvedCredential(reference, "/var/lib/securityola/appcare/credentials/key")


def client(
    tmp_path: Path,
    *,
    current: LinuxTarget | None = None,
    runner: FakeRunner | None = None,
    scanner: HostKeyScanner | None = None,
    credentials: CredentialProvider | None = None,
) -> tuple[LinuxSSHClient, FakeRunner]:
    current = current or target()
    fake_runner = runner or FakeRunner(
        {
            "true": ProcessResult(0, b"", b""),
            "hostname": ProcessResult(0, b"app-a.internal\n", b""),
            "-srm": ProcessResult(0, b"Linux 6.8.0 x86_64\n", b""),
            "/etc/os-release": ProcessResult(
                0,
                b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04"\n',
                b"",
            ),
        }
    )
    _, handle = credential(
        current.tenant_id,
        current.application_id,
        current.credential_reference,
    )
    provider = credentials or FakeCredentials(
        {(current.tenant_id, current.application_id, current.credential_reference): handle}
    )
    transport = LinuxSSHClient(
        current,
        credential_provider=provider,
        runner=fake_runner,
        known_hosts=KnownHostsStore(tmp_path / "known-hosts"),
        scanner=scanner,
        operation_ledger=InMemoryOperationLedger(),
    )
    return transport, fake_runner


def test_keyscan_ignores_comment_banners_before_parsing() -> None:
    class BannerRunner:
        def run(
            self,
            argv: tuple[str, ...],
            *,
            timeout_seconds: float,
            stdout_limit: int,
            stderr_limit: int,
        ) -> ProcessResult:
            del argv, timeout_seconds, stdout_limit, stderr_limit
            return ProcessResult(
                0,
                b"# 192.0.2.10:22 SSH-2.0-OpenSSH_9.9\n"
                b"192.0.2.10 ssh-ed25519 " + KEY_DATA.encode() + b"\n",
                b"",
            )

    scanner = OpenSshHostKeyScanner(BannerRunner())
    assert scanner.scan(
        target(),
        limits=BoundedLimits(max_records=1),
    ) == ("192.0.2.10 ssh-ed25519 " + KEY_DATA,)


def test_keyscan_keeps_malformed_non_comment_lines_rejected(tmp_path: Path) -> None:
    class MalformedRunner:
        def run(
            self,
            argv: tuple[str, ...],
            *,
            timeout_seconds: float,
            stdout_limit: int,
            stderr_limit: int,
        ) -> ProcessResult:
            del argv, timeout_seconds, stdout_limit, stderr_limit
            return ProcessResult(
                0,
                b"192.0.2.10:22 SSH-2.0-OpenSSH_9.9\n"
                b"192.0.2.10 ssh-ed25519 " + KEY_DATA.encode() + b"\n",
                b"",
            )

    with pytest.raises(HostKeyVerificationError):
        verify_host_key(
            target(),
            scanner=OpenSshHostKeyScanner(MalformedRunner()),
            store=KnownHostsStore(tmp_path / "known-hosts"),
            limits=BoundedLimits(),
        )


def test_keyscan_applies_record_limit_to_key_lines_after_comments() -> None:
    class TwoKeyRunner:
        def run(
            self,
            argv: tuple[str, ...],
            *,
            timeout_seconds: float,
            stdout_limit: int,
            stderr_limit: int,
        ) -> ProcessResult:
            del argv, timeout_seconds, stdout_limit, stderr_limit
            return ProcessResult(
                0,
                b"# banner\n"
                b"192.0.2.10 ssh-ed25519 " + KEY_DATA.encode() + b"\n"
                b"192.0.2.10 ssh-ed25519 " + base64.b64encode(b"second-key") + b"\n",
                b"",
            )

    with pytest.raises(HostKeyVerificationError):
        OpenSshHostKeyScanner(TwoKeyRunner()).scan(
            target(),
            limits=BoundedLimits(max_records=1),
        )


def test_connection_and_host_inventory_are_strict_and_scoped(tmp_path: Path) -> None:
    transport, runner = client(tmp_path)
    connection = transport.execute(ConnectionProbe("connect-1"))
    assert connection.status == OperationStatus.PASSED
    assert connection.evidence_class == EvidenceClass.FIXTURE
    inventory = transport.execute(HostInventory("inventory-1"))
    assert inventory.status == OperationStatus.PASSED
    assert {record.tenant_id for record in inventory.records} == {"tenant-a"}
    assert {record.application_id for record in inventory.records} == {"application-a"}
    assert all("StrictHostKeyChecking=no" not in item for call in runner.calls for item in call)
    assert not hasattr(transport, "run_shell")


def test_host_key_mismatch_halts_before_ssh(tmp_path: Path) -> None:
    class WrongScanner:
        def scan(self, current: LinuxTarget, *, limits: BoundedLimits) -> tuple[str, ...]:
            del current, limits
            wrong = base64.b64encode(b"wrong-host-key").decode()
            return (f"host ssh-ed25519 {wrong}",)

    transport, runner = client(tmp_path, scanner=WrongScanner())
    with pytest.raises(HostKeyVerificationError):
        transport.execute(ConnectionProbe("connect-1"))
    assert all(call[0] != "ssh" for call in runner.calls)


def test_changed_key_does_not_overwrite_target_scoped_known_hosts(tmp_path: Path) -> None:
    transport, _ = client(tmp_path)
    transport.execute(ConnectionProbe("connect-1"))

    class ChangedScanner:
        def scan(self, current: LinuxTarget, *, limits: BoundedLimits) -> tuple[str, ...]:
            del current, limits
            changed = base64.b64encode(b"changed-key").decode()
            return (f"host ssh-ed25519 {changed}",)

    changed_transport, runner = client(tmp_path, scanner=ChangedScanner())
    with pytest.raises(HostKeyVerificationError):
        changed_transport.execute(ConnectionProbe("connect-2"))
    assert all(call[0] != "ssh" for call in runner.calls)


def test_cross_tenant_credential_is_rejected_before_network(tmp_path: Path) -> None:
    current = target(tenant_id="tenant-b", target_reference="target-b")
    _, foreign_handle = credential()
    transport, runner = client(
        tmp_path,
        current=current,
        credentials=FakeCredentials(
            {("tenant-a", "application-a", "vault://appcare/linux-a"): foreign_handle}
        ),
    )
    with pytest.raises(CredentialBoundaryError):
        transport.execute(ConnectionProbe("connect-1"))
    assert runner.calls == []


@pytest.mark.parametrize(
    "process_result,expected",
    [
        (ProcessResult(None, b"", b"", timed_out=True), OperationStatus.TIMED_OUT),
        (ProcessResult(0, b"x" * 20, b"", output_limited=True), OperationStatus.OUTPUT_LIMITED),
        (ProcessResult(0, b"\xff", b""), OperationStatus.MALFORMED),
        (ProcessResult(None, b"", b"", disconnected=True), OperationStatus.DISCONNECTED),
    ],
)
def test_failure_modes_are_bounded_and_sanitized(
    tmp_path: Path,
    process_result: ProcessResult,
    expected: OperationStatus,
) -> None:
    runner = FakeRunner({"true": process_result})
    transport, _ = client(tmp_path, runner=runner)
    result = transport.execute(ConnectionProbe("connect-1"))
    assert result.status == expected
    assert result.records == ()


def test_safe_file_read_rejects_remote_symlink_escape(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            "/srv/app/config/settings.json": ProcessResult(0, b"regular file:42\n", b""),
        }
    )
    transport, _ = client(tmp_path, runner=runner)
    result = transport.execute(SafeFileRead("file-1", "/srv/app", "config/settings.json"))
    assert result.status in {OperationStatus.MALFORMED, OperationStatus.FAILED}


def test_approved_root_symlink_escape_is_rejected(tmp_path: Path) -> None:
    class EscapingRunner(FakeRunner):
        def run(
            self,
            argv: tuple[str, ...],
            *,
            timeout_seconds: float,
            stdout_limit: int,
            stderr_limit: int,
        ) -> ProcessResult:
            if argv[0] == "realpath":
                self.calls.append(argv)
                return ProcessResult(0, b"/outside/app\n", b"")
            return super().run(
                argv,
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
            )

    transport, runner = client(tmp_path, runner=EscapingRunner({}))
    result = transport.execute(FilesystemMetadataRead("root-1", "/srv/app"))
    assert result.status == OperationStatus.MALFORMED
    assert any(call[0] == "ssh" for call in runner.calls)


def test_unapproved_service_is_rejected(tmp_path: Path) -> None:
    transport, _ = client(tmp_path)
    with pytest.raises(ValueError):
        transport.execute(ServiceMetadataRead("service-1", "other.service"))


def test_spec013_receives_only_connect_and_inventory_evidence(tmp_path: Path) -> None:
    transport, _ = client(tmp_path)
    connection = transport.execute(ConnectionProbe("connect-1"))
    inventory = transport.execute(HostInventory("inventory-1"))
    snapshot = LinuxInventorySnapshot(
        target(),
        connection,
        inventory,
        connection.records + inventory.records,
    )
    evidence = snapshot.capability_evidence(stack_id="generic-linux")
    registry = ApplicationCapabilityRegistry(
        tenant_id="tenant-a",
        application_id="application-a",
        stack_id="generic-linux",
    )
    for item in evidence:
        registry.add(item)
    decision = SupportabilityEvaluator().evaluate(
        "tenant-a",
        "application-a",
        "generic-linux",
        registry.evidence(),
    )
    statuses = {item.capability: item.status for item in decision.capability_results}
    assert statuses["connect"] == CapabilityStatus.SUPPORTED
    assert statuses["inventory"] == CapabilityStatus.SUPPORTED
    assert statuses["deploy"] == CapabilityStatus.MISSING_CAPABILITY
    assert decision.authoritative is False


def test_fixture_client_cannot_be_relabelled_as_real_target(tmp_path: Path) -> None:
    transport, _ = client(tmp_path)
    result = transport.execute(ConnectionProbe("connect-1"))
    assert result.evidence_class == EvidenceClass.FIXTURE
    assert result.evidence_class.value != EvidenceClass.REAL_TARGET.value


def test_duplicate_operation_is_rejected_without_second_network_call(tmp_path: Path) -> None:
    transport, runner = client(tmp_path)
    first = transport.execute(ConnectionProbe("same-operation"))
    second = transport.execute(ConnectionProbe("same-operation"))
    assert first.status == OperationStatus.PASSED
    assert second.status == OperationStatus.REPLAYED
    assert sum(call[0] == "ssh" for call in runner.calls) == 1


def test_credential_registry_revoke_and_expiry_fail_closed() -> None:
    now = datetime(2026, 8, 28, tzinfo=UTC)
    metadata = LinuxCredentialMetadata(
        credential_reference="vault://appcare/linux-a",
        tenant_id="tenant-a",
        application_id="application-a",
        issued_at=now - timedelta(hours=1),
        expires_at=now,
    )
    assert metadata.status(now) == CredentialStatus.EXPIRED
    registry = LinuxCredentialRegistry()
    registry.register(metadata)
    assert (
        registry.get(
            tenant_id="tenant-a",
            application_id="application-a",
            credential_reference="vault://appcare/linux-a",
        ).status(now)
        == CredentialStatus.EXPIRED
    )
