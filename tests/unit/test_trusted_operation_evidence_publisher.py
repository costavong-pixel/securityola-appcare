from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from appcare.connectors.linux_ssh_contracts import (
    EvidenceClass,
    InventoryRecord,
    LinuxInventorySnapshot,
    LinuxTarget,
    OperationKind,
    OperationStatus,
    RemoteExecutionResult,
)
from appcare.connectors.live_inventory_attestor import (
    ATTESTOR_MAX_EVIDENCE_BYTES,
    AttestorError,
    TrustedOperationEvidencePublisher,
)

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(b"host-key").digest()).decode().rstrip(
    "="
)


def _target(**changes: object) -> LinuxTarget:
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
    source: str,
    record_type: str,
    identity: str,
    metadata: dict[str, object],
    evidence_class: EvidenceClass = EvidenceClass.REAL_TARGET,
) -> InventoryRecord:
    return InventoryRecord(
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
        record_type=record_type,
        identity=identity,
        metadata=metadata,
        source_reference=source,
        evidence_class=evidence_class,
        observed_at=NOW,
    )


def _snapshot(
    *,
    evidence_class: EvidenceClass = EvidenceClass.REAL_TARGET,
    connection_operation_id: str = "run-1:connect",
    inventory_operation_id: str = "run-1:inventory",
    records: tuple[InventoryRecord, ...] | None = None,
    inventory_status: OperationStatus = OperationStatus.PASSED,
) -> LinuxInventorySnapshot:
    target = _target()
    records = records or (
        _record(
            source="linux-ssh/host_inventory/hostname",
            record_type="host_identity",
            identity=target.expected_hostname,
            metadata={"hostname": target.expected_hostname},
            evidence_class=evidence_class,
        ),
        _record(
            source="linux-ssh/host_inventory/kernel",
            record_type="kernel",
            identity="kernel",
            metadata={"release": "6.1.0"},
            evidence_class=evidence_class,
        ),
        _record(
            source="linux-ssh/host_inventory/os_release",
            record_type="operating_system",
            identity="id",
            metadata={"id": "debian"},
            evidence_class=evidence_class,
        ),
        _record(
            source="linux-ssh/host_inventory/os_release",
            record_type="operating_system",
            identity="version_id",
            metadata={"version_id": "13"},
            evidence_class=evidence_class,
        ),
        _record(
            source="linux-ssh/application_root_verification/resolved_root",
            record_type="filesystem_root",
            identity="/srv/app",
            metadata={"resolved": True},
            evidence_class=evidence_class,
        ),
        _record(
            source="linux-ssh/application_root_verification/root",
            record_type="filesystem",
            identity="/srv/app",
            metadata={"file_type": "directory", "owner": "app", "group": "app", "mode": "755"},
            evidence_class=evidence_class,
        ),
        _record(
            source="linux-ssh/filesystem_metadata_read/resolved_root",
            record_type="filesystem_root",
            identity="/srv/app",
            metadata={"resolved": True},
            evidence_class=evidence_class,
        ),
        _record(
            source="linux-ssh/filesystem_metadata_read/metadata",
            record_type="filesystem",
            identity="/srv/app",
            metadata={
                "file_type": "directory",
                "owner": "app",
                "group": "app",
                "mode": "755",
                "bytes": 0,
                "device": 8,
                "inode": 123,
            },
            evidence_class=evidence_class,
        ),
    )
    connection = RemoteExecutionResult(
        operation_id=connection_operation_id,
        operation=OperationKind.CONNECTION_PROBE,
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        target_reference=target.target_reference,
        status=OperationStatus.PASSED,
        reason_code="ok",
        evidence_class=evidence_class,
        observed_at=NOW,
    )
    inventory = RemoteExecutionResult(
        operation_id=inventory_operation_id,
        operation=OperationKind.HOST_INVENTORY,
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        target_reference=target.target_reference,
        status=inventory_status,
        reason_code="ok" if inventory_status == OperationStatus.PASSED else "inventory_partial",
        records=records,
        evidence_class=evidence_class,
        observed_at=NOW,
    )
    return LinuxInventorySnapshot(target, connection, inventory, records)


def _read(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_publisher_writes_canonical_transport_derived_operations(tmp_path: Path) -> None:
    path = tmp_path / "operation-evidence.json"
    operations = TrustedOperationEvidencePublisher(path).publish(_snapshot())

    assert [item.operation for item in operations] == [
        OperationKind.CONNECTION_PROBE,
        OperationKind.HOST_INVENTORY,
    ]
    payload = _read(path)
    assert payload["schema_version"] == 1
    assert len(cast(list[object], payload["operations"])) == 2
    assert path.read_bytes() == json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "snapshot",
    [
        _snapshot(evidence_class=EvidenceClass.FIXTURE),
        _snapshot(evidence_class=EvidenceClass.REFERENCE),
        _snapshot(inventory_status=OperationStatus.PARTIAL),
        _snapshot(
            connection_operation_id="wrong:connect",
            inventory_operation_id="run-1:inventory",
        ),
        _snapshot(
            records=tuple(
                replace(
                    record,
                    metadata={**record.metadata, "device": -1}
                    if record.source_reference.endswith("/metadata")
                    else dict(record.metadata),
                )
                for record in _snapshot().records
            )
        ),
        _snapshot(
            records=tuple(
                replace(record, application_id="other-app")
                if record.record_type == "kernel"
                else record
                for record in _snapshot().records
            )
        ),
        _snapshot(
            records=tuple(
                replace(record, identity="/srv/other")
                if record.source_reference.endswith("/filesystem_metadata_read/metadata")
                else record
                for record in _snapshot().records
            )
        ),
    ],
)
def test_publisher_rejects_untrusted_or_incomplete_inputs(
    tmp_path: Path, snapshot: LinuxInventorySnapshot
) -> None:
    with pytest.raises(AttestorError):
        TrustedOperationEvidencePublisher(tmp_path / "operation-evidence.json").publish(snapshot)


def test_publisher_rejects_scope_and_host_spoofing(tmp_path: Path) -> None:
    original = _snapshot()
    spoofed_host = tuple(
        replace(record, identity="wrong.internal", metadata={"hostname": "wrong.internal"})
        if record.record_type == "host_identity"
        else record
        for record in original.records
    )
    spoofed = replace(
        original,
        inventory=replace(original.inventory, records=spoofed_host),
        records=spoofed_host,
    )
    with pytest.raises(AttestorError):
        TrustedOperationEvidencePublisher(tmp_path / "operation-evidence.json").publish(spoofed)


def test_duplicate_operation_is_rejected_without_replacing_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "operation-evidence.json"
    publisher = TrustedOperationEvidencePublisher(path)
    publisher.publish(_snapshot())
    before = path.read_bytes()

    with pytest.raises(AttestorError, match="duplicate"):
        publisher.publish(_snapshot())

    assert path.read_bytes() == before
    assert not tuple(tmp_path.glob(".operation-evidence.json.*.tmp"))


def test_publisher_rejects_symlink_and_unsafe_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "operation-evidence.json"
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    try:
        path.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(AttestorError):
        TrustedOperationEvidencePublisher(path).publish(_snapshot())

    path.unlink()
    path.write_bytes(b"{}")
    if os.name == "posix":
        path.chmod(0o644)
        with pytest.raises(AttestorError):
            TrustedOperationEvidencePublisher(path).publish(_snapshot())


def test_failed_atomic_publish_cleans_only_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "operation-evidence.json"

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("simulated rename failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(AttestorError):
        TrustedOperationEvidencePublisher(path).publish(_snapshot())
    assert not path.exists()
    assert not tuple(tmp_path.glob(".operation-evidence.json.*.tmp"))


def test_existing_evidence_size_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "operation-evidence.json"
    path.write_bytes(b"x" * (ATTESTOR_MAX_EVIDENCE_BYTES + 1))
    path.chmod(0o600)
    with pytest.raises(AttestorError):
        TrustedOperationEvidencePublisher(path).publish(_snapshot())
