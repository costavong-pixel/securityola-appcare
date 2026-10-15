from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
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
    SqliteOperationLedger,
)
from appcare.connectors.live_inventory_attestor import TrustedOperationEvidence
from appcare.connectors.transport_evidence_broker import (
    TransportEvidenceBrokerError,
    TrustedOperationEvidenceBroker,
)
from appcare.readiness.contracts import ReadinessValidationError

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
KEY = b"broker-host-key"
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(KEY).digest()).decode().rstrip("=")


@pytest.fixture(name="tmp_path")
def _trusted_tmp_path() -> Iterator[Path]:
    """Keep evidence tests below a non-world-writable checkout ancestry."""

    with tempfile.TemporaryDirectory(
        prefix=".appcare-evidence-test-",
        dir=Path.cwd(),
    ) as directory:
        path = Path(directory)
        if os.name == "posix":
            path.chmod(0o700)
        yield path


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
    target: LinuxTarget, source: str, record_type: str, identity: str, metadata: dict[str, object]
) -> InventoryRecord:
    return InventoryRecord(
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        target_reference=target.target_reference,
        record_type=record_type,
        identity=identity,
        metadata=metadata,
        source_reference=source,
        evidence_class=EvidenceClass.REAL_TARGET,
        observed_at=NOW,
    )


def _snapshot(target: LinuxTarget | None = None) -> LinuxInventorySnapshot:
    target = target or _target()
    records = (
        _record(
            target,
            "linux-ssh/host_inventory/hostname",
            "host_identity",
            target.expected_hostname,
            {"hostname": target.expected_hostname},
        ),
        _record(
            target,
            "linux-ssh/host_inventory/kernel",
            "kernel",
            "kernel",
            {"release": "Linux 6.8.0 x86_64"},
        ),
        _record(
            target,
            "linux-ssh/host_inventory/os_release",
            "operating_system",
            "id",
            {"id": "debian"},
        ),
        _record(
            target,
            "linux-ssh/host_inventory/os_release",
            "operating_system",
            "version_id",
            {"version_id": "13"},
        ),
        _record(
            target,
            "linux-ssh/application_root_verification/resolved_root",
            "filesystem_root",
            "/srv/app",
            {"resolved": True},
        ),
        _record(
            target,
            "linux-ssh/application_root_verification/root",
            "filesystem",
            "/srv/app",
            {"file_type": "directory", "owner": "appcare", "group": "appcare", "mode": "755"},
        ),
        _record(
            target,
            "linux-ssh/filesystem_metadata_read/resolved_root",
            "filesystem_root",
            "/srv/app",
            {"resolved": True},
        ),
        _record(
            target,
            "linux-ssh/filesystem_metadata_read/metadata",
            "filesystem",
            "/srv/app",
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
    connection = RemoteExecutionResult(
        operation_id="run-1:connect",
        operation=OperationKind.CONNECTION_PROBE,
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        target_reference=target.target_reference,
        status=OperationStatus.PASSED,
        reason_code="ok",
        evidence_class=EvidenceClass.REAL_TARGET,
        observed_at=NOW,
    )
    inventory = RemoteExecutionResult(
        operation_id="run-1:inventory",
        operation=OperationKind.HOST_INVENTORY,
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        target_reference=target.target_reference,
        status=OperationStatus.PASSED,
        reason_code="ok",
        records=records,
        evidence_class=EvidenceClass.REAL_TARGET,
        observed_at=NOW,
    )
    return LinuxInventorySnapshot(target, connection, inventory, records)


def _broker(
    tmp_path: Path, snapshot: LinuxInventorySnapshot | None = None
) -> tuple[TrustedOperationEvidenceBroker, LinuxInventorySnapshot]:
    snapshot = snapshot or _snapshot()
    broker = TrustedOperationEvidenceBroker(
        snapshot.target,
        operation_ledger=SqliteOperationLedger(tmp_path / "operation-ledger.db"),
        evidence_path=tmp_path / "operation-evidence.json",
    )
    broker._mark_transport_result(snapshot.connection)
    broker._mark_transport_result(snapshot.inventory)
    return broker, snapshot


def test_only_transport_sealed_real_results_can_publish(tmp_path: Path) -> None:
    broker, snapshot = _broker(tmp_path)
    published = broker.publish(snapshot)

    assert [item.evidence_class for item in published] == [
        EvidenceClass.REAL_TARGET,
        EvidenceClass.REAL_TARGET,
    ]
    payload = json.loads((tmp_path / "operation-evidence.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert len(payload["operations"]) == 2
    assert "stdout" not in json.dumps(payload)
    assert "secret" not in json.dumps(payload).casefold()


@pytest.mark.parametrize("evidence_class", list(EvidenceClass))
def test_caller_supplied_evidence_class_cannot_promote_results(
    tmp_path: Path, evidence_class: EvidenceClass
) -> None:
    snapshot = _snapshot()
    connection = replace(snapshot.connection, evidence_class=evidence_class)
    inventory = replace(snapshot.inventory, evidence_class=evidence_class)
    snapshot = LinuxInventorySnapshot(snapshot.target, connection, inventory, snapshot.records)
    broker, _ = _broker(tmp_path, snapshot)
    # _broker only seals the replacement objects, so remove the seal to model
    # caller-created evidence rather than a transport result.
    object.__setattr__(connection, "_transport_authority", None)
    object.__setattr__(inventory, "_transport_authority", None)

    with pytest.raises(TransportEvidenceBrokerError, match="transport-authorized"):
        broker.publish(snapshot)


def test_foreign_scope_wrong_hostname_and_run_mismatch_fail_closed(tmp_path: Path) -> None:
    broker, snapshot = _broker(tmp_path)
    foreign = replace(snapshot.inventory, tenant_id="tenant-b")
    object.__setattr__(foreign, "_transport_authority", broker._authority)
    with pytest.raises(ReadinessValidationError, match="crosses target scope"):
        LinuxInventorySnapshot(snapshot.target, snapshot.connection, foreign, snapshot.records)

    wrong_host = list(snapshot.records)
    wrong_host[0] = replace(
        wrong_host[0], identity="wrong.internal", metadata={"hostname": "wrong.internal"}
    )
    wrong_inventory = replace(snapshot.inventory, records=tuple(wrong_host))
    object.__setattr__(wrong_inventory, "_transport_authority", broker._authority)
    with pytest.raises(TransportEvidenceBrokerError):
        broker.publish(
            LinuxInventorySnapshot(
                snapshot.target, snapshot.connection, wrong_inventory, tuple(wrong_host)
            )
        )

    mismatched = replace(snapshot.inventory, operation_id="different:inventory")
    object.__setattr__(mismatched, "_transport_authority", broker._authority)
    with pytest.raises(TransportEvidenceBrokerError, match="run binding"):
        broker.publish(
            LinuxInventorySnapshot(
                snapshot.target, snapshot.connection, mismatched, snapshot.records
            )
        )


def test_partial_missing_and_unverified_root_inventory_is_rejected(tmp_path: Path) -> None:
    broker, snapshot = _broker(tmp_path)
    missing = tuple(
        record
        for record in snapshot.records
        if record.identity != snapshot.target.expected_hostname
    )
    inventory = replace(snapshot.inventory, records=missing)
    object.__setattr__(inventory, "_transport_authority", broker._authority)
    with pytest.raises(TransportEvidenceBrokerError, match="incomplete"):
        broker.publish(
            LinuxInventorySnapshot(snapshot.target, snapshot.connection, inventory, missing)
        )

    unverified = tuple(
        replace(record, metadata={**record.metadata, "device": None})
        if record.source_reference == "linux-ssh/filesystem_metadata_read/metadata"
        else record
        for record in snapshot.records
    )
    inventory = replace(snapshot.inventory, records=unverified)
    object.__setattr__(inventory, "_transport_authority", broker._authority)
    with pytest.raises(TransportEvidenceBrokerError):
        broker.publish(
            LinuxInventorySnapshot(snapshot.target, snapshot.connection, inventory, unverified)
        )


def test_replay_is_rejected_and_file_is_canonical_and_atomic(tmp_path: Path) -> None:
    broker, snapshot = _broker(tmp_path)
    broker.publish(snapshot)
    with pytest.raises(TransportEvidenceBrokerError, match="replayed"):
        broker.publish(snapshot)

    path = tmp_path / "operation-evidence.json"
    raw = path.read_bytes()
    assert (
        raw
        == json.dumps(
            json.loads(raw), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )
    assert not tuple(tmp_path.glob(".operation-evidence.json.tmp-*"))
    if os.name == "posix":
        assert os.stat(path).st_mode & 0o077 == 0


def test_symlink_unsafe_mode_and_size_boundaries_fail_closed(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("symlink and mode defenses require POSIX filesystem semantics")
    symlink_path = tmp_path / "symlink-evidence.json"
    outside = tmp_path / "outside.json"
    outside.write_text("outside", encoding="utf-8")
    symlink_path.symlink_to(outside)
    with pytest.raises(TransportEvidenceBrokerError, match="parent|unsafe|symlink"):
        broker, snapshot = _broker(tmp_path, _snapshot())
        broker._path = symlink_path
        broker.publish(snapshot)

    if os.name == "posix":
        unsafe_parent = tmp_path / "unsafe"
        unsafe_parent.mkdir()
        unsafe_parent.chmod(0o777)
        with pytest.raises(TransportEvidenceBrokerError, match="parent"):
            TrustedOperationEvidenceBroker(
                _target(),
                operation_ledger=SqliteOperationLedger(tmp_path / "unsafe-ledger.db"),
                evidence_path=unsafe_parent / "evidence.json",
            )

    bounded_root = tmp_path / "bounded"
    bounded_root.mkdir()
    broker, snapshot = _broker(bounded_root)
    bounded = TrustedOperationEvidenceBroker(
        snapshot.target,
        operation_ledger=SqliteOperationLedger(tmp_path / "bounded-ledger.db"),
        evidence_path=tmp_path / "bounded-evidence.json",
        max_bytes=1024,
    )
    bounded._mark_transport_result(snapshot.connection)
    bounded._mark_transport_result(snapshot.inventory)
    with pytest.raises(TransportEvidenceBrokerError, match="large"):
        bounded.publish(snapshot)


def test_concurrent_publication_has_one_winner(tmp_path: Path) -> None:
    broker, snapshot = _broker(tmp_path)

    def publish() -> object:
        try:
            return broker.publish(snapshot)
        except TransportEvidenceBrokerError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _: publish(), range(2)))
    assert sum(isinstance(item, tuple) for item in results) == 1
    assert sum(isinstance(item, TransportEvidenceBrokerError) for item in results) == 1


def test_published_schema_matches_attestor_evidence_contract(tmp_path: Path) -> None:
    broker, snapshot = _broker(tmp_path)
    broker.publish(snapshot)

    payload = json.loads((tmp_path / "operation-evidence.json").read_text(encoding="utf-8"))
    operations = payload["operations"]
    parsed = tuple(TrustedOperationEvidence.from_mapping(item) for item in operations)

    assert any(
        item.target_reference == "target-a" and item.operation_id == "run-1:inventory"
        for item in parsed
    )
