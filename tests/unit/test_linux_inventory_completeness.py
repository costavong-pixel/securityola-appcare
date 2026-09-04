from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime

from appcare.connectors.linux_ssh_contracts import (
    EvidenceClass,
    InventoryRecord,
    LinuxInventorySnapshot,
    LinuxTarget,
    OperationKind,
    OperationStatus,
    RemoteExecutionResult,
    required_inventory_records_complete,
)
from appcare.readiness import ApplicationCapabilityRegistry, SupportabilityEvaluator

OBSERVED_AT = datetime(2026, 9, 2, tzinfo=UTC)


def _target() -> LinuxTarget:
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(b"fixture-key").digest()).decode()
    return LinuxTarget(
        tenant_id="tenant-a",
        application_id="application-a",
        environment="staging",
        host="192.0.2.10",
        expected_hostname="app-a.internal",
        ssh_port=22,
        expected_host_key_fingerprint=fingerprint.rstrip("="),
        credential_reference="vault://appcare/linux-a",
        remote_user="appcare",
        approved_application_roots=("/srv/app", "/srv/shared"),
        approved_service_names=("app.service",),
        approved_database_identifiers=("postgresql",),
        target_reference="target-a",
    )


def _record(
    target: LinuxTarget,
    operation: OperationKind,
    step: str,
    record_type: str,
    identity: str,
    metadata: dict[str, object],
) -> InventoryRecord:
    return InventoryRecord(
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        target_reference=target.target_reference,
        record_type=record_type,
        identity=identity,
        metadata=metadata,
        source_reference=f"linux-ssh/{operation.value}/{step}",
        evidence_class=EvidenceClass.FIXTURE,
        observed_at=OBSERVED_AT,
    )


def _complete_records(target: LinuxTarget) -> list[InventoryRecord]:
    records = [
        _record(
            target,
            OperationKind.HOST_INVENTORY,
            "hostname",
            "host_identity",
            target.expected_hostname,
            {"hostname": target.expected_hostname},
        ),
        _record(
            target,
            OperationKind.HOST_INVENTORY,
            "kernel",
            "kernel",
            "kernel",
            {"release": "Linux 6.8.0 x86_64"},
        ),
        _record(
            target,
            OperationKind.HOST_INVENTORY,
            "os_release",
            "operating_system",
            "id",
            {"id": "ubuntu"},
        ),
        _record(
            target,
            OperationKind.HOST_INVENTORY,
            "os_release",
            "operating_system",
            "version_id",
            {"version_id": "24.04"},
        ),
    ]
    for root in target.approved_application_roots:
        records.extend(
            (
                _record(
                    target,
                    OperationKind.APPLICATION_ROOT_VERIFICATION,
                    "resolved_root",
                    "filesystem_root",
                    root,
                    {"resolved": True},
                ),
                _record(
                    target,
                    OperationKind.APPLICATION_ROOT_VERIFICATION,
                    "root",
                    "filesystem",
                    root,
                    {
                        "file_type": "directory",
                        "owner": "appcare",
                        "group": "appcare",
                        "mode": "755",
                    },
                ),
                _record(
                    target,
                    OperationKind.FILESYSTEM_METADATA_READ,
                    "resolved_root",
                    "filesystem_root",
                    root,
                    {"resolved": True},
                ),
                _record(
                    target,
                    OperationKind.FILESYSTEM_METADATA_READ,
                    "metadata",
                    "filesystem",
                    root,
                    {
                        "file_type": "directory",
                        "owner": "appcare",
                        "group": "appcare",
                        "mode": "755",
                        "bytes": 42,
                        "device": 8,
                        "inode": 123,
                    },
                ),
            )
        )
    return records


def _result(
    target: LinuxTarget,
    operation: OperationKind,
    operation_id: str,
    records: list[InventoryRecord],
    status: OperationStatus = OperationStatus.PASSED,
) -> RemoteExecutionResult:
    return RemoteExecutionResult(
        operation_id=operation_id,
        operation=operation,
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        target_reference=target.target_reference,
        status=status,
        reason_code="ok"
        if status == OperationStatus.PASSED
        else "inventory_required_observation_failed",
        records=tuple(records),
        evidence_class=EvidenceClass.FIXTURE,
        observed_at=OBSERVED_AT,
    )


def _snapshot(
    records: list[InventoryRecord],
    *,
    inventory_status: OperationStatus = OperationStatus.PASSED,
) -> LinuxInventorySnapshot:
    target = _target()
    connection = _result(target, OperationKind.CONNECTION_PROBE, "connect", [])
    inventory = _result(
        target,
        OperationKind.HOST_INVENTORY,
        "inventory",
        records,
        inventory_status,
    )
    return LinuxInventorySnapshot(target, connection, inventory, tuple(records))


def test_all_required_observations_allow_inventory_support() -> None:
    target = _target()
    records = _complete_records(target)
    snapshot = _snapshot(records)

    assert required_inventory_records_complete(target, records)
    assert snapshot.complete
    statuses = {
        item.capability: item.status.value
        for item in snapshot.capability_evidence(stack_id="generic-linux")
    }
    assert statuses["inventory"] == "supported"


def test_missing_hostname_fails_closed_even_when_operation_passed() -> None:
    target = _target()
    records = [
        record
        for record in _complete_records(target)
        if record.source_reference != "linux-ssh/host_inventory/hostname"
    ]
    snapshot = _snapshot(records)

    assert snapshot.inventory.passed
    assert not snapshot.complete
    assert snapshot.capability_evidence(stack_id="generic-linux")[1].status.value == "unsupported"


def test_missing_required_os_result_fails_closed_even_when_operation_passed() -> None:
    target = _target()
    records = [record for record in _complete_records(target) if record.identity != "version_id"]

    assert not required_inventory_records_complete(target, records)
    assert not _snapshot(records).complete


def test_missing_approved_root_observation_fails_closed() -> None:
    target = _target()
    missing_root = target.approved_application_roots[-1]
    records = [
        record
        for record in _complete_records(target)
        if not (
            record.source_reference == "linux-ssh/application_root_verification/root"
            and record.identity == missing_root
        )
    ]

    assert not required_inventory_records_complete(target, records)


def test_optional_observations_can_be_unavailable_without_blocking_required_inventory() -> None:
    target = _target()
    records = _complete_records(target)

    assert required_inventory_records_complete(target, records)
    assert _snapshot(records).complete


def test_malformed_required_observation_fails_closed() -> None:
    target = _target()
    records = _complete_records(target)
    index = next(
        index
        for index, record in enumerate(records)
        if record.source_reference == "linux-ssh/filesystem_metadata_read/metadata"
    )
    records[index] = replace(records[index], metadata={})

    assert not required_inventory_records_complete(target, records)


def test_duplicate_required_evidence_fails_closed() -> None:
    target = _target()
    records = _complete_records(target)
    hostname = next(
        record
        for record in records
        if record.source_reference == "linux-ssh/host_inventory/hostname"
    )

    assert not required_inventory_records_complete(target, [*records, hostname])


def test_fixture_evidence_cannot_promote_real_target_readiness() -> None:
    target = _target()
    snapshot = _snapshot(_complete_records(target))
    evidence = snapshot.capability_evidence(stack_id="generic-linux")
    registry = ApplicationCapabilityRegistry(
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        stack_id="generic-linux",
    )
    for item in evidence:
        registry.add(item)

    decision = SupportabilityEvaluator().evaluate(
        target.tenant_id,
        target.application_id,
        "generic-linux",
        registry.evidence(),
    )
    assert all(item.evidence_class == EvidenceClass.FIXTURE for item in evidence)
    assert decision.authoritative is False


def test_caller_passed_inventory_status_cannot_bypass_completeness() -> None:
    target = _target()
    records = [
        record
        for record in _complete_records(target)
        if record.source_reference != "linux-ssh/host_inventory/hostname"
    ]
    snapshot = _snapshot(records, inventory_status=OperationStatus.PASSED)

    assert snapshot.inventory.passed
    assert snapshot.capability_evidence(stack_id="generic-linux")[1].status.value == "unsupported"


def test_inventory_result_records_must_match_snapshot_records() -> None:
    target = _target()
    records = _complete_records(target)
    connection = _result(target, OperationKind.CONNECTION_PROBE, "connect", [])
    inventory = _result(target, OperationKind.HOST_INVENTORY, "inventory", records[:-1])
    snapshot = LinuxInventorySnapshot(target, connection, inventory, tuple(records))

    assert not snapshot.complete
    assert snapshot.capability_evidence(stack_id="generic-linux")[1].status.value == "unsupported"


def test_inventory_evidence_class_must_match_normalized_records() -> None:
    target = _target()
    records = _complete_records(target)
    connection = _result(target, OperationKind.CONNECTION_PROBE, "connect", [])
    inventory = replace(
        _result(target, OperationKind.HOST_INVENTORY, "inventory", records),
        evidence_class=EvidenceClass.REAL_TARGET,
    )
    snapshot = LinuxInventorySnapshot(target, connection, inventory, tuple(records))

    assert not snapshot.complete
    assert snapshot.capability_evidence(stack_id="generic-linux")[1].status.value == "unsupported"


def test_non_mapping_required_metadata_fails_closed() -> None:
    target = _target()
    records = _complete_records(target)
    object.__setattr__(records[0], "metadata", None)

    assert not required_inventory_records_complete(target, records)


def test_connection_and_inventory_evidence_classes_must_match() -> None:
    target = _target()
    records = _complete_records(target)
    connection = replace(
        _result(target, OperationKind.CONNECTION_PROBE, "connect", []),
        evidence_class=EvidenceClass.REAL_TARGET,
    )
    inventory = _result(target, OperationKind.HOST_INVENTORY, "inventory", records)
    snapshot = LinuxInventorySnapshot(target, connection, inventory, tuple(records))

    assert not snapshot.complete
    assert snapshot.capability_evidence(stack_id="generic-linux")[0].status.value == "unsupported"


def test_inventory_result_operation_type_is_checked_before_supportability() -> None:
    target = _target()
    records = _complete_records(target)
    connection = _result(target, OperationKind.CONNECTION_PROBE, "connect", [])
    inventory = _result(target, OperationKind.CONNECTION_PROBE, "inventory", records)
    snapshot = LinuxInventorySnapshot(target, connection, inventory, tuple(records))

    assert not snapshot.complete
    assert snapshot.capability_evidence(stack_id="generic-linux")[1].status.value == "unsupported"
