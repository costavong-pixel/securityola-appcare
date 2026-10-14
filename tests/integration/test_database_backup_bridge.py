from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from appcare.backups.paths import BackupFilesystemBoundary
from appcare.connectors.linux_ssh_contracts import LinuxTarget
from appcare.database import (
    ApplicationDatabaseBackupBridge,
    ApplicationDatabaseBackupContext,
    DatabaseBrokerResult,
    DatabaseCredentialReference,
    DatabaseIdentityAttestation,
    DatabaseIdentityAttestationError,
    DatabaseKind,
    DatabaseOperationKind,
    DatabaseOperationLedger,
    DatabaseOperationStatus,
    DatabaseRestoreError,
    DatabaseRestoreTarget,
    DatabaseTarget,
    MariaDBAdapter,
)
from appcare.revision.contracts import (
    BaselineEntry,
    BaselinePolicy,
    CapturedApplicationRevision,
    FilesystemBaseline,
)

STAMP = datetime(2026, 8, 29, tzinfo=UTC)
HOST_KEY = b"p05-bridge-host-key"
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(HOST_KEY).digest()).decode().rstrip("=")


def _target(**changes: object) -> DatabaseTarget:
    tenant_id = cast(str, changes.pop("tenant_id", "tenant-a"))
    application_id = cast(str, changes.pop("application_id", "application-a"))
    linux = LinuxTarget(
        tenant_id=tenant_id,
        application_id=application_id,
        environment="staging",
        host="127.0.0.1",
        expected_hostname="reference-a.internal",
        ssh_port=22,
        expected_host_key_fingerprint=FINGERPRINT,
        credential_reference="vault://appcare/linux-a",
        remote_user="appcare",
        approved_application_roots=("/srv/app",),
        approved_service_names=("app.service",),
        approved_database_identifiers=("primary-db", "appdb"),
        target_reference="linux-target-a",
    )
    credential = DatabaseCredentialReference(
        reference="vault://appcare/database-a",
        tenant_id=tenant_id,
        application_id=application_id,
        issued_at=STAMP,
    )
    values: dict[str, object] = {
        "stack_id": "linux-reference",
        "engine_family": DatabaseKind.MARIADB_MYSQL,
        "database_identifier": "primary-db",
        "logical_database_name": "appdb",
        "credential": credential,
        "transport_evidence_reference": "inventory/reference-a",
        "target_reference": "database://reference-a",
        "database_user": "appcare",
        "database_host": "127.0.0.1",
        "database_port": 3306,
    }
    values.update(changes)
    return DatabaseTarget.from_linux_target(
        linux,
        **cast(Any, values),
    )


def _context(tmp_path: Path, **identity_changes: object) -> ApplicationDatabaseBackupContext:
    target = _target()
    root = tmp_path / "application"
    baseline = FilesystemBaseline(
        root=root.as_posix(),
        entries=(BaselineEntry(".", "directory", 0, 0o700, 0, 0),),
        policy=BaselinePolicy(),
    )
    metadata = {
        "stack_id": target.stack_id,
        "engine_family": target.engine_family.value,
        "database_identifier": target.database_identifier,
        "logical_database_name": target.logical_database_name,
        "database_version": "10.11.8-MariaDB",
        "db_auth_fingerprint": hashlib.sha256(
            target.credential.reference.encode("utf-8")
        ).hexdigest(),
        "identity_evidence_reference": "inventory/database-a",
    }
    revision = CapturedApplicationRevision.from_filesystem_baseline(
        baseline,
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        target_reference=target.transport.target_reference,
        host_identity=target.transport.host,
        captured_at=STAMP,
        database_metadata=metadata,
        evidence_reference="revision://linux-target-a/baseline-a",
        baseline_id="baseline-a",
    )
    identity_values: dict[str, object] = {
        "tenant_id": target.tenant_id,
        "application_id": target.application_id,
        "stack_id": target.stack_id,
        "target_reference": target.target_reference,
        "engine_family": target.engine_family,
        "database_identifier": target.database_identifier,
        "logical_database_name": target.logical_database_name,
        "database_version": "10.11.8-MariaDB",
        "credential_reference": target.credential.reference,
        "baseline_id": revision.baseline_id,
        "baseline_digest": revision.baseline_digest,
        "manifest_digest": revision.manifest_digest,
        "evidence_reference": "inventory/database-a",
    }
    identity_values.update(identity_changes)
    return ApplicationDatabaseBackupContext(
        revision=revision,
        target=target,
        identity=DatabaseIdentityAttestation(**cast(Any, identity_values)),
    )


class _DumpBroker:
    def __init__(self, *, status: DatabaseOperationStatus = DatabaseOperationStatus.PASSED) -> None:
        self.status = status
        self.calls: list[object] = []

    def run(
        self,
        operation: object,
        *,
        target: DatabaseTarget,
        output_path: Path | None = None,
        cancel_event: object | None = None,
    ) -> DatabaseBrokerResult:
        del target, cancel_event
        self.calls.append(operation)
        if output_path is not None and self.status is DatabaseOperationStatus.PASSED:
            output_path.write_bytes(b"CREATE TABLE demo (id INT);\n")
            payload = output_path.read_bytes()
            return DatabaseBrokerResult(
                operation_id=operation.operation_id,
                operation=DatabaseOperationKind.LOGICAL_DUMP,
                status=self.status,
                reason_code="ok",
                template_id="mysql.dump.logical.v1",
                artifact_path=output_path,
                artifact_size_bytes=len(payload),
                artifact_sha256=hashlib.sha256(payload).hexdigest(),
            )
        return DatabaseBrokerResult(
            operation_id=operation.operation_id,
            operation=DatabaseOperationKind.LOGICAL_DUMP,
            status=self.status,
            reason_code=self.status.value,
            template_id="mysql.dump.logical.v1",
        )


def _bridge(
    tmp_path: Path, *, broker: _DumpBroker | None = None
) -> tuple[ApplicationDatabaseBackupBridge, _DumpBroker]:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "backup-boundary")
    active_broker = broker or _DumpBroker()
    adapter = MariaDBAdapter(
        broker=active_broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
    )
    return ApplicationDatabaseBackupBridge(adapter), active_broker


def test_bridge_binds_dump_to_revision_and_canonical_artifact_path(tmp_path: Path) -> None:
    context = _context(tmp_path)
    bridge, broker = _bridge(tmp_path)

    result = bridge.dump(
        context,
        backup_id="bridge-backup",
        idempotency_key="bridge-operation",
        job_id="bridge-job",
        now=STAMP,
    )

    assert result.passed
    assert result.artifact is not None
    assert result.artifact.artifact_path == (
        result.artifact.filesystem.staging_path("bridge-job") / "database.sql"
    )
    assert result.artifact.manifest.target_reference == context.target.target_reference
    assert result.artifact.manifest.source_revision == context.revision.baseline_digest
    assert result.artifact.manifest.application_artifact_digest == context.revision.baseline_digest
    assert len(broker.calls) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant_id": "tenant-other"},
        {"application_id": "application-other"},
        {"target_reference": "database://other"},
        {"engine_family": DatabaseKind.POSTGRESQL},
        {"database_identifier": "other-db"},
        {"logical_database_name": "other-db"},
        {"database_version": "11.0.0"},
        {"baseline_digest": "c" * 64},
        {"manifest_digest": "d" * 64},
        {"credential_reference": "vault://appcare/database-b"},
    ],
)
def test_bridge_rejects_identity_and_revision_mismatches(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    context = _context(tmp_path, **changes)
    bridge, broker = _bridge(tmp_path)

    with pytest.raises(DatabaseIdentityAttestationError):
        bridge.dump(
            context,
            backup_id="bridge-backup",
            idempotency_key="bridge-operation",
            job_id="bridge-job",
        )
    assert broker.calls == []


def test_bridge_rejects_secret_shaped_identity_reference() -> None:
    with pytest.raises(ValueError):
        DatabaseIdentityAttestation(
            tenant_id="tenant-a",
            application_id="application-a",
            stack_id="linux-reference",
            target_reference="database://reference-a",
            engine_family=DatabaseKind.MARIADB_MYSQL,
            database_identifier="primary-db",
            logical_database_name="appdb",
            database_version="10.11.8-MariaDB",
            credential_reference="vault://appcare/password=secret",
            baseline_id="baseline-a",
            baseline_digest="a" * 64,
            manifest_digest="b" * 64,
            evidence_reference="inventory/database-a",
        )


def test_bridge_rejects_command_injection_before_adapter_execution(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _context(tmp_path, database_identifier="appdb;DROP TABLE users")


def test_bridge_preserves_idempotency_binding_to_revision(tmp_path: Path) -> None:
    context = _context(tmp_path)
    bridge, broker = _bridge(tmp_path)
    first = bridge.dump(
        context,
        backup_id="bridge-backup",
        idempotency_key="bridge-operation",
        job_id="bridge-job",
        now=STAMP,
    )
    replay = bridge.dump(
        context,
        backup_id="bridge-backup",
        idempotency_key="bridge-operation",
        job_id="bridge-job",
        now=STAMP,
    )

    assert first.passed
    assert replay.passed
    assert replay.artifact == first.artifact
    assert len(broker.calls) == 1


def test_bridge_cleans_partial_timeout_output(tmp_path: Path) -> None:
    broker = _DumpBroker(status=DatabaseOperationStatus.TIMED_OUT)
    bridge, _ = _bridge(tmp_path, broker=broker)
    result = bridge.dump(
        _context(tmp_path),
        backup_id="bridge-timeout",
        idempotency_key="bridge-timeout-operation",
        job_id="bridge-timeout-job",
    )

    assert not result.passed
    assert result.status is DatabaseOperationStatus.TIMED_OUT
    assert not bridge.adapter.filesystem.staging_path("bridge-timeout-job").exists()


def test_restore_target_contract_rejects_production() -> None:
    with pytest.raises(DatabaseRestoreError, match="production"):
        DatabaseRestoreTarget(
            tenant_id="tenant-a",
            application_id="application-a",
            stack_id="linux-reference",
            environment="production",
            engine_family=DatabaseKind.MARIADB_MYSQL,
            isolated_target_reference="restore://production",
            restore_database_name="appdb_restore",
            transport=_target().transport,
            credential=_target().credential,
            cleanup_owner_reference="job://restore-cleanup",
            verification_profile="database-verify-v1",
            approved_database_identifiers=("appdb_restore",),
        )
