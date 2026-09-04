from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import Thread
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from appcare.connectors.linux_ssh_contracts import (
    EvidenceClass,
    InventoryRecord,
    LinuxTarget,
    OperationKind,
    OperationStatus,
    RemoteExecutionResult,
    _live_snapshot_receipt_payload,
    _receipt_digest,
    _receipt_signature_message,
    live_snapshot_receipt_path,
)
from appcare.connectors.live_inventory_attestor import (
    AttestorError,
    AttestorPolicy,
    InMemoryTrustedOperationEvidenceStore,
    RootBinding,
    RootControlledLiveInventoryAttestor,
    TrustedOperationEvidence,
    UnixSocketAttestorServer,
)

KEY_BLOB = b"attestor-test-host-key"


def _mutate_target_application(payload: object) -> None:
    target = cast(dict[str, object], cast(dict[str, object], payload)["target"])
    target["application_id"] = "other-app"


def _mutate_connection_digest(payload: object) -> None:
    cast(dict[str, object], payload)["connection_evidence_digest"] = "0" * 64


def _mutate_transport_run(payload: object) -> None:
    cast(dict[str, object], payload)["transport_run_id"] = "other-run"


def _mutate_source_host(payload: object) -> None:
    source_binding = cast(dict[str, object], cast(dict[str, object], payload)["source_binding"])
    source_binding["host_identity"] = "wrong-host"


def _mutate_source_inode(payload: object) -> None:
    source_binding = cast(dict[str, object], cast(dict[str, object], payload)["source_binding"])
    roots = cast(list[dict[str, object]], source_binding["roots"])
    roots[0]["inode"] = 999


def _current_uid() -> int:
    return cast(Callable[[], int], os.getuid)()  # type: ignore[attr-defined]


def _current_gid() -> int:
    return cast(Callable[[], int], os.getgid)()  # type: ignore[attr-defined]


FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(KEY_BLOB).digest()).decode().rstrip("=")
NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


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
        "approved_database_identifiers": ("mariadb",),
        "target_reference": "target-a",
    }
    values.update(changes)
    return LinuxTarget(**cast(Any, values))


def _record(
    *,
    record_type: str,
    identity: str,
    source_reference: str,
    metadata: dict[str, object],
    observed_at: datetime = NOW,
) -> InventoryRecord:
    return InventoryRecord(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
        record_type=record_type,
        identity=identity,
        metadata=metadata,
        source_reference=source_reference,
        evidence_class=EvidenceClass.REAL_TARGET,
        observed_at=observed_at,
    )


def _fixture(
    observed_at: datetime = NOW,
) -> tuple[
    LinuxTarget,
    RootControlledLiveInventoryAttestor,
    dict[str, object],
    Ed25519PrivateKey,
]:
    current = target()
    host_record = _record(
        record_type="host_identity",
        identity=current.expected_hostname,
        source_reference="linux-ssh/host_inventory/hostname",
        metadata={"hostname": current.expected_hostname},
        observed_at=observed_at,
    )
    root_record = _record(
        record_type="filesystem",
        identity="/srv/app",
        source_reference="linux-ssh/filesystem_metadata_read/metadata",
        metadata={
            "file_type": "directory",
            "owner": "app",
            "group": "app",
            "mode": "755",
            "bytes": 0,
            "device": 8,
            "inode": 123,
        },
        observed_at=observed_at,
    )
    connection = RemoteExecutionResult(
        operation_id="run:connect",
        operation=OperationKind.CONNECTION_PROBE,
        tenant_id=current.tenant_id,
        application_id=current.application_id,
        target_reference=current.target_reference,
        status=OperationStatus.PASSED,
        reason_code="ok",
        evidence_class=EvidenceClass.REAL_TARGET,
        observed_at=observed_at,
    )
    inventory = RemoteExecutionResult(
        operation_id="run:inventory",
        operation=OperationKind.HOST_INVENTORY,
        tenant_id=current.tenant_id,
        application_id=current.application_id,
        target_reference=current.target_reference,
        status=OperationStatus.PASSED,
        reason_code="ok",
        records=(host_record, root_record),
        evidence_class=EvidenceClass.REAL_TARGET,
        observed_at=observed_at,
    )
    receipt_path = live_snapshot_receipt_path(current, inventory.operation_id).as_posix()
    payload = _live_snapshot_receipt_payload(
        current,
        connection,
        inventory,
        inventory.records,
        receipt_path=receipt_path,
    )
    digest = _receipt_digest(payload)
    payload["receipt_digest"] = digest
    message = _receipt_signature_message(payload, digest)
    trusted_connection = TrustedOperationEvidence(
        operation_id=connection.operation_id,
        operation=connection.operation,
        tenant_id=current.tenant_id,
        application_id=current.application_id,
        target_reference=current.target_reference,
        status=connection.status,
        evidence_digest=connection.evidence_digest,
        transport_run_id="run",
        record_evidence_digests=(),
        host_identity=current.expected_hostname,
        root_bindings=(),
        evidence_class=EvidenceClass.REAL_TARGET,
        observed_at=observed_at,
    )
    trusted_inventory = TrustedOperationEvidence(
        operation_id=inventory.operation_id,
        operation=inventory.operation,
        tenant_id=current.tenant_id,
        application_id=current.application_id,
        target_reference=current.target_reference,
        status=inventory.status,
        evidence_digest=inventory.evidence_digest,
        transport_run_id="run",
        record_evidence_digests=tuple(item.evidence_digest for item in inventory.records),
        host_identity=current.expected_hostname,
        root_bindings=(
            RootBinding(
                approved_root="/srv/app",
                device=8,
                inode=123,
                record_evidence_digest=root_record.evidence_digest,
            ),
        ),
        evidence_class=EvidenceClass.REAL_TARGET,
        observed_at=observed_at,
    )
    signer = Ed25519PrivateKey.generate()
    policy = AttestorPolicy(target=current, allowed_peer_uid=1001, allowed_peer_gid=1001)
    service = RootControlledLiveInventoryAttestor(
        policy=policy,
        evidence=InMemoryTrustedOperationEvidenceStore((trusted_connection, trusted_inventory)),
        signer=signer,
        clock=lambda: NOW,
    )
    return current, service, {"message": message, "payload": payload}, signer


def test_valid_receipt_is_signed_only_against_trusted_operation_evidence() -> None:
    _target, service, fixture, signer = _fixture()
    message = cast(bytes, fixture["message"])

    signature = service.attest(message)

    signer.public_key().verify(signature, message)


def test_arbitrary_message_is_not_signed() -> None:
    _target, service, _fixture_data, _signer = _fixture()

    with pytest.raises(AttestorError):
        service.attest(b'{"arbitrary":true}')


@pytest.mark.parametrize(
    "mutate",
    (
        _mutate_target_application,
        _mutate_connection_digest,
        _mutate_transport_run,
        _mutate_source_host,
        _mutate_source_inode,
    ),
)
def test_tampered_scope_digest_or_source_binding_is_rejected(mutate: Any) -> None:
    _target, service, fixture, _signer = _fixture()
    payload = cast(dict[str, object], fixture["payload"]).copy()
    payload["target"] = dict(cast(dict[str, object], payload["target"]))
    source_binding = cast(dict[str, object], payload["source_binding"])
    source_binding = dict(source_binding)
    payload["source_binding"] = source_binding
    roots = cast(list[dict[str, object]], source_binding["roots"])
    source_binding["roots"] = [dict(item) for item in roots]
    mutate(payload)
    payload.pop("receipt_digest")
    digest = _receipt_digest(payload)
    payload["receipt_digest"] = digest
    message = _receipt_signature_message(payload, digest)

    with pytest.raises(AttestorError):
        service.attest(message)


def test_replay_is_rejected() -> None:
    _target, service, fixture, _signer = _fixture()
    message = cast(bytes, fixture["message"])
    service.attest(message)

    with pytest.raises(AttestorError, match="replayed"):
        service.attest(message)


def test_stale_evidence_is_rejected() -> None:
    _target, service, fixture, _signer = _fixture(NOW - timedelta(hours=1))

    with pytest.raises(AttestorError, match="stale"):
        service.attest(cast(bytes, fixture["message"]))


def test_canonical_json_rejects_duplicate_keys_and_noncanonical_spacing() -> None:
    _target, service, _fixture_data, _signer = _fixture()

    for message in (
        b'{"schema_version":1,"schema_version":1}',
        b'{ "schema_version": 1 }',
    ):
        with pytest.raises(AttestorError):
            service.attest(message)


@pytest.mark.skipif(os.name != "posix", reason="Unix socket framing is POSIX-only")
def test_socket_protocol_requires_write_half_close_and_returns_signature() -> None:
    _target, service, fixture, signer = _fixture()
    server = UnixSocketAttestorServer(
        attestor=service,
        allowed_peer_uid=_current_uid(),
        allowed_peer_gid=_current_gid(),
    )
    client, peer = socket.socketpair()
    thread = Thread(target=server._handle, args=(peer,))
    thread.start()
    try:
        message = cast(bytes, fixture["message"])
        client.sendall(struct.pack("!I", len(message)) + message)
        client.shutdown(socket.SHUT_WR)
        length = struct.unpack("!I", _read_exact(client, 4))[0]
        signature = _read_exact(client, length)
        signer.public_key().verify(signature, message)
        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        client.close()
        peer.close()


@pytest.mark.skipif(os.name != "posix", reason="Unix socket framing is POSIX-only")
def test_socket_protocol_rejects_trailing_bytes() -> None:
    _target, service, fixture, _signer = _fixture()
    server = UnixSocketAttestorServer(
        attestor=service,
        allowed_peer_uid=_current_uid(),
        allowed_peer_gid=_current_gid(),
    )
    client, peer = socket.socketpair()
    thread = Thread(target=server._handle, args=(peer,))
    thread.start()
    try:
        message = cast(bytes, fixture["message"])
        client.sendall(struct.pack("!I", len(message)) + message + b"trailing")
        client.shutdown(socket.SHUT_WR)
        assert struct.unpack("!I", _read_exact(client, 4))[0] == 0
        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        client.close()
        peer.close()


def _read_exact(channel: socket.socket, length: int) -> bytes:
    content = bytearray()
    while len(content) < length:
        chunk = channel.recv(length - len(content))
        if not chunk:
            raise AssertionError("socket frame ended early")
        content.extend(chunk)
    return bytes(content)
