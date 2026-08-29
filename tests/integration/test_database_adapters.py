from __future__ import annotations

import base64
import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from appcare.backups.models import RecoveryEvidence, VaultReceipt
from appcare.backups.paths import BackupFilesystemBoundary
from appcare.connectors.linux_ssh_contracts import LinuxTarget
from appcare.database import (
    DatabaseBrokerResult,
    DatabaseCredentialReference,
    DatabaseDumpArtifact,
    DatabaseDumpFormat,
    DatabaseDumpRequest,
    DatabaseKind,
    DatabaseManifest,
    DatabaseOperationKind,
    DatabaseOperationStatus,
    DatabaseRestoreError,
    DatabaseRestoreRequest,
    DatabaseRestoreTarget,
    DatabaseTarget,
    DatabaseVerifyRequest,
    InMemoryDatabaseRestoreTargetRegistry,
    MariaDBAdapter,
    ResolvedDatabaseCredential,
    SqlAlchemyDatabaseOperationLedger,
    SqlAlchemyDatabaseRestoreTargetRegistry,
    register_database_capability_evidence,
)
from appcare.db import Database
from appcare.models import (
    Application,
    CapabilityEvidenceRecord,
    DatabaseOperationRecord,
    Tenant,
    new_id,
)
from appcare.readiness import (
    ApplicationCapabilityRegistry,
    CapabilityStatus,
    CoordinatorApproval,
)
from appcare.readiness.persistence import SqlAlchemyReadinessStore

STAMP = datetime(2026, 8, 29, tzinfo=UTC)
HOST_KEY = b"spec-015-host-key"
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(HOST_KEY).digest()).decode().rstrip("=")
SOURCE_REVISION = "a" * 40
APPLICATION_DIGEST = "b" * 64


def _database_auth_material() -> str:
    return "-".join(("test", "only", "database", "value"))


def _linux_target(**changes: object) -> LinuxTarget:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "application_id": "application-a",
        "environment": "staging",
        "host": "127.0.0.1",
        "expected_hostname": "reference-a.internal",
        "ssh_port": 22,
        "expected_host_key_fingerprint": FINGERPRINT,
        "credential_reference": "vault://appcare/linux-a",
        "remote_user": "appcare",
        "approved_application_roots": ("/srv/app",),
        "approved_service_names": ("app.service",),
        "approved_database_identifiers": ("primary-db", "appdb"),
        "target_reference": "linux-target-a",
    }
    values.update(changes)
    return LinuxTarget(**cast(Any, values))


def _credential(
    *, tenant_id: str = "tenant-a", application_id: str = "application-a"
) -> tuple[DatabaseCredentialReference, ResolvedDatabaseCredential]:
    reference = DatabaseCredentialReference(
        reference="vault://appcare/database-a",
        tenant_id=tenant_id,
        application_id=application_id,
        issued_at=STAMP,
    )
    resolved_fields = {"reference": reference.reference, "username": "appcare"}
    resolved_fields["secret"] = _database_auth_material()
    resolved = ResolvedDatabaseCredential(**resolved_fields)
    return reference, resolved


def _database_target(**changes: object) -> DatabaseTarget:
    tenant_id = cast(str, changes.get("tenant_id", "tenant-a"))
    application_id = cast(str, changes.get("application_id", "application-a"))
    credential, _ = _credential(tenant_id=tenant_id, application_id=application_id)
    values: dict[str, object] = {
        "stack_id": "linux-reference",
        "engine_family": DatabaseKind.MARIADB_MYSQL,
        "database_identifier": "primary-db",
        "logical_database_name": "appdb",
        "credential": credential,
        "transport_evidence_reference": "inventory/reference-a",
        "target_reference": "reference://database-a",
        "database_user": "appcare",
        "database_host": "127.0.0.1",
        "database_port": 3306,
    }
    values.update(
        {key: value for key, value in changes.items() if key not in {"tenant_id", "application_id"}}
    )
    return DatabaseTarget.from_linux_target(
        _linux_target(tenant_id=tenant_id, application_id=application_id),
        **cast(Any, values),
    )


def _restore_target(source: DatabaseTarget, **changes: object) -> DatabaseRestoreTarget:
    values: dict[str, object] = {
        "tenant_id": source.tenant_id,
        "application_id": source.application_id,
        "stack_id": source.stack_id,
        "environment": "test",
        "engine_family": source.engine_family,
        "isolated_target_reference": "reference://restore-a",
        "restore_database_name": "appdb_restore",
        "transport": source.transport,
        "credential": source.credential,
        "cleanup_owner_reference": "job://restore-a",
        "verification_profile": "database-verify-v1",
        "approved_database_identifiers": ("appdb_restore",),
        "database_user": source.database_user,
        "database_host": source.database_host,
        "database_port": source.database_port,
    }
    values.update(changes)
    return DatabaseRestoreTarget(**cast(Any, values))


class FakeBroker:
    def __init__(
        self,
        payload: bytes = b"-- synthetic dump\nCREATE TABLE demo (id INT);\n",
    ) -> None:
        self.payload = payload
        self.operations: list[object] = []

    def run(
        self,
        operation: object,
        *,
        target: DatabaseTarget,
        output_path: Path | None = None,
        cancel_event: object | None = None,
    ) -> DatabaseBrokerResult:
        del cancel_event
        self.operations.append(operation)
        if isinstance(operation, DatabaseDumpRequest):
            assert output_path is not None
            output_path.write_bytes(self.payload)
            digest = hashlib.sha256(self.payload).hexdigest()
            return DatabaseBrokerResult(
                operation_id=operation.operation_id,
                operation=DatabaseOperationKind.LOGICAL_DUMP,
                status=DatabaseOperationStatus.PASSED,
                reason_code="ok",
                template_id="mysql.dump.logical.v1",
                artifact_path=output_path,
                artifact_size_bytes=len(self.payload),
                artifact_sha256=digest,
            )
        if isinstance(operation, DatabaseRestoreRequest):
            return DatabaseBrokerResult(
                operation_id=operation.operation_id,
                operation=DatabaseOperationKind.LOGICAL_RESTORE,
                status=DatabaseOperationStatus.PASSED,
                reason_code="ok",
                template_id="mysql.restore.logical.v1",
            )
        if isinstance(operation, DatabaseVerifyRequest):
            restored_object_count = 0 if operation.require_empty else 1
            return DatabaseBrokerResult(
                operation_id=operation.operation_id,
                operation=(
                    DatabaseOperationKind.PRE_RESTORE_VERIFY
                    if operation.require_empty
                    else DatabaseOperationKind.POST_RESTORE_VERIFY
                ),
                status=DatabaseOperationStatus.PASSED,
                reason_code="ok",
                template_id=(
                    "mysql.verify.empty.v1"
                    if operation.require_empty
                    else "mysql.verify.restore.v1"
                ),
                observed_database_name=target.logical_database_name,
                restored_object_count=restored_object_count,
            )
        raise AssertionError("unexpected database operation")


def test_database_operation_ledger_survives_reopen(tmp_path: Path) -> None:
    database_path = tmp_path / "appcare.sqlite3"
    database = Database(f"sqlite+pysqlite:///{database_path.as_posix()}")
    database.initialize()
    ledger = SqlAlchemyDatabaseOperationLedger(database)
    digest = "a" * 64
    scope = "tenant-a:application-a:primary-db:staging"

    assert (
        ledger.claim(scope=scope, idempotency_key="operation-a", request_digest=digest)[0] == "new"
    )
    ledger.complete(
        scope=scope,
        idempotency_key="operation-a",
        outcome=SimpleNamespace(passed=True, artifact_digest="b" * 64),
    )
    database.dispose()

    reopened = Database(f"sqlite+pysqlite:///{database_path.as_posix()}")
    reopened.initialize()
    reopened_ledger = SqlAlchemyDatabaseOperationLedger(reopened)
    duplicate_claim, duplicate_prior = reopened_ledger.claim(
        scope=scope,
        idempotency_key="operation-a",
        request_digest=digest,
    )
    assert duplicate_claim == "duplicate"
    assert duplicate_prior == {
        "kind": "database_terminal_result",
        "status": "passed",
        "reason_code": "ok",
        "evidence_class": "fixture",
        "cleanup_status": "none",
    }
    assert (
        reopened_ledger.claim(
            scope=scope,
            idempotency_key="operation-a",
            request_digest="c" * 64,
        )[0]
        == "conflict"
    )
    reopened.dispose()


def test_database_capability_bridge_persists_through_existing_readiness_store(
    tmp_path: Path,
) -> None:
    database = Database("sqlite+pysqlite:///:memory:")
    database.initialize()
    with database.session_factory() as session:
        tenant = Tenant(name="Spec 015 Bridge Tenant")
        session.add(tenant)
        session.flush()
        application = Application(
            tenant_id=tenant.id,
            name="Spec 015 Bridge Application",
            repository_url="https://example.test/spec015-bridge",
            environment="development",
        )
        session.add(application)
        session.commit()
        tenant_id = tenant.id
        application_id = application.id

    source = _database_target(tenant_id=tenant_id, application_id=application_id)
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "spec015-bridge")
    broker = FakeBroker()
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=SqlAlchemyDatabaseOperationLedger(database),
    )
    dump = adapter.dump(
        DatabaseDumpRequest(
            target=source,
            backup_id="bridge-backup",
            idempotency_key="bridge-dump",
            job_id="bridge-job",
            source_revision=SOURCE_REVISION,
            application_artifact_digest=APPLICATION_DIGEST,
            requested_at=STAMP,
        )
    )
    assert dump.artifact is not None
    artifact = dump.artifact
    readback = RecoveryEvidence(
        backup_id=artifact.manifest.backup_id,
        status="verified",
        component_names=("database",),
        manifest_digest=artifact.manifest_digest,
        artifact_digest=artifact.artifact_digest,
        rpo_observed_seconds=1,
        rto_observed_seconds=1,
        controlled_test_only=True,
    )
    receipt = VaultReceipt(
        backup_id=artifact.manifest.backup_id,
        provider="filesystem",
        object_reference="memory://database/spec015-bridge",
        artifact_digest=artifact.artifact_digest,
        retained_until=STAMP,
    )
    registry = ApplicationCapabilityRegistry(
        tenant_id=tenant_id,
        application_id=application_id,
        stack_id=source.stack_id,
    )
    with database.session_factory() as session:
        evidence = register_database_capability_evidence(
            artifact,
            capability_registry=registry,
            evidence_ref="evidence/database-spec015-bridge",
            coordinator_approval=CoordinatorApproval.for_luna(
                artifact.evidence_digest,
                approved_at=STAMP,
            ),
            readback_evidence=readback,
            vault_receipt=receipt,
            readiness_store=SqlAlchemyReadinessStore(session),
            observed_at=STAMP,
        )
        session.commit()
        persisted = session.scalar(
            select(CapabilityEvidenceRecord).where(
                CapabilityEvidenceRecord.evidence_digest == evidence.evidence_digest
            )
        )

    assert evidence.status == CapabilityStatus.SUPPORTED
    assert registry.evidence() == (evidence,)
    assert persisted is not None
    assert persisted.status == CapabilityStatus.SUPPORTED.value
    assert persisted.evidence_digest == evidence.evidence_digest
    assert _database_auth_material() not in str(evidence.canonical_payload())
    database.dispose()


def test_restore_target_quarantine_survives_process_reopen(tmp_path: Path) -> None:
    database_path = tmp_path / "restore-targets.sqlite3"
    database = Database(f"sqlite+pysqlite:///{database_path.as_posix()}")
    database.initialize()
    source = _database_target()
    target = _restore_target(source)
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "restore-target-boundary")
    filesystem.ensure_data_dirs()
    job = filesystem.staging_path("registry-source")
    job.mkdir(parents=True)
    payload = b"CREATE TABLE demo (id INT);\n"
    artifact_path = job / "database.sql"
    artifact_path.write_bytes(payload)
    artifact = DatabaseDumpArtifact(
        manifest=DatabaseManifest(
            backup_id="backup-registry",
            tenant_id=source.tenant_id,
            application_id=source.application_id,
            stack_id=source.stack_id,
            target_reference=source.target_reference,
            transport_target_reference=source.transport.target_reference,
            engine_family=source.engine_family,
            database_identifier=source.database_identifier,
            logical_database_name=source.logical_database_name,
            dump_format=DatabaseDumpFormat.SQL,
            tool_profile=source.tool_profile,
            artifact_size_bytes=len(payload),
            artifact_sha256=hashlib.sha256(payload).hexdigest(),
            consistency=source.consistency,
            limitation_codes=("test_fixture",),
            created_at=STAMP,
        ),
        artifact_path=artifact_path,
        staging_job_id="registry-source",
        filesystem=filesystem,
    )
    registry = SqlAlchemyDatabaseRestoreTargetRegistry(database)
    registry.register(
        target,
        source_target_reference=source.target_reference,
        source_database_identifier=source.database_identifier,
        source_logical_database_name=source.logical_database_name,
    )
    assert registry.resolve(target, source_manifest=artifact.manifest) == target
    assert (
        registry.quarantine(
            target,
            source_manifest=artifact.manifest,
            cleanup_reference=target.cleanup_owner_reference,
            reason_code="restore_failed",
        )
        == target.cleanup_owner_reference
    )
    database.dispose()

    reopened = Database(f"sqlite+pysqlite:///{database_path.as_posix()}")
    reopened.initialize()
    reopened_registry = SqlAlchemyDatabaseRestoreTargetRegistry(reopened)
    with pytest.raises(DatabaseRestoreError, match="quarantined"):
        reopened_registry.resolve(target, source_manifest=artifact.manifest)
    reopened.dispose()


def test_database_operation_ledger_marks_unfinished_operations_for_recovery(tmp_path: Path) -> None:
    database = Database(f"sqlite+pysqlite:///{(tmp_path / 'recovery.sqlite3').as_posix()}")
    database.initialize()
    ledger = SqlAlchemyDatabaseOperationLedger(database)
    scope = "tenant-a:application-a:primary-db:staging"
    assert (
        ledger.claim(scope=scope, idempotency_key="operation-a", request_digest="a" * 64)[0]
        == "new"
    )
    ledger.mark_restart_recovery()
    assert (
        ledger.claim(scope=scope, idempotency_key="operation-a", request_digest="a" * 64)[0]
        == "recovery_required"
    )
    database.dispose()


def test_database_operation_ledger_resolves_unique_claim_race_from_committed_record(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite+pysqlite:///{(tmp_path / 'race.sqlite3').as_posix()}")
    database.initialize()
    scope = "tenant-a:application-a:primary-db:staging"
    digest = "a" * 64

    base_factory = sessionmaker(
        bind=database.engine,
        autoflush=False,
        expire_on_commit=False,
        class_=Session,
    )

    class RacingSession(Session):
        raced = False

        def flush(self, objects: Sequence[Any] | None = None) -> None:
            if not type(self).raced:
                type(self).raced = True
                competing = base_factory()
                try:
                    competing.add(
                        DatabaseOperationRecord(
                            id=new_id(),
                            tenant_id="tenant-a",
                            application_id="application-a",
                            scope=scope,
                            idempotency_key="operation-a",
                            request_digest=digest,
                            operation_kind="database",
                            status="running",
                        )
                    )
                    competing.commit()
                finally:
                    competing.close()
            super().flush(objects=objects)

    database.session_factory = sessionmaker(
        bind=database.engine,
        autoflush=False,
        expire_on_commit=False,
        class_=RacingSession,
    )
    ledger = SqlAlchemyDatabaseOperationLedger(database)

    claim, prior = ledger.claim(
        scope=scope,
        idempotency_key="operation-a",
        request_digest=digest,
    )
    assert (claim, prior) == ("recovery_required", None)
    database.dispose()


def test_database_operation_ledger_resolves_unique_claim_race_conflicts_deterministically(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite+pysqlite:///{(tmp_path / 'race-conflict.sqlite3').as_posix()}")
    database.initialize()
    scope = "tenant-a:application-a:primary-db:staging"
    winning_digest = "a" * 64
    losing_digest = "b" * 64

    base_factory = sessionmaker(
        bind=database.engine,
        autoflush=False,
        expire_on_commit=False,
        class_=Session,
    )

    class RacingSession(Session):
        raced = False

        def flush(self, objects: Sequence[Any] | None = None) -> None:
            if not type(self).raced:
                type(self).raced = True
                competing = base_factory()
                try:
                    competing.add(
                        DatabaseOperationRecord(
                            id=new_id(),
                            tenant_id="tenant-a",
                            application_id="application-a",
                            scope=scope,
                            idempotency_key="operation-a",
                            request_digest=winning_digest,
                            operation_kind="database",
                            status="running",
                        )
                    )
                    competing.commit()
                finally:
                    competing.close()
            super().flush(objects=objects)

    database.session_factory = sessionmaker(
        bind=database.engine,
        autoflush=False,
        expire_on_commit=False,
        class_=RacingSession,
    )
    ledger = SqlAlchemyDatabaseOperationLedger(database)

    claim, prior = ledger.claim(
        scope=scope,
        idempotency_key="operation-a",
        request_digest=losing_digest,
    )
    assert (claim, prior) == ("conflict", None)
    database.dispose()


def test_database_operation_ledger_resolves_active_scope_race_from_committed_record(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite+pysqlite:///{(tmp_path / 'active-race.sqlite3').as_posix()}")
    database.initialize()
    scope = "tenant-a:application-a:primary-db:staging"

    base_factory = sessionmaker(
        bind=database.engine,
        autoflush=False,
        expire_on_commit=False,
        class_=Session,
    )

    class RacingSession(Session):
        raced = False

        def flush(self, objects: Sequence[Any] | None = None) -> None:
            if not type(self).raced:
                type(self).raced = True
                competing = base_factory()
                try:
                    competing.add(
                        DatabaseOperationRecord(
                            id=new_id(),
                            tenant_id="tenant-a",
                            application_id="application-a",
                            scope=scope,
                            idempotency_key="operation-b",
                            request_digest="b" * 64,
                            operation_kind="database",
                            status="running",
                        )
                    )
                    competing.commit()
                finally:
                    competing.close()
            super().flush(objects=objects)

    database.session_factory = sessionmaker(
        bind=database.engine,
        autoflush=False,
        expire_on_commit=False,
        class_=RacingSession,
    )
    ledger = SqlAlchemyDatabaseOperationLedger(database)

    claim, prior = ledger.claim(
        scope=scope,
        idempotency_key="operation-a",
        request_digest="a" * 64,
    )
    assert (claim, prior) == ("active", None)
    database.dispose()


def test_database_operation_active_scope_constraint_blocks_second_active_row(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite+pysqlite:///{(tmp_path / 'active-constraint.sqlite3').as_posix()}")
    database.initialize()
    scope = "tenant-a:application-a:primary-db:staging"

    with database.session() as session:
        session.add(
            DatabaseOperationRecord(
                id=new_id(),
                tenant_id="tenant-a",
                application_id="application-a",
                scope=scope,
                idempotency_key="operation-a",
                request_digest="a" * 64,
                operation_kind="database",
                status="running",
            )
        )

    with pytest.raises(IntegrityError):
        with database.session() as session:
            session.add(
                DatabaseOperationRecord(
                    id=new_id(),
                    tenant_id="tenant-a",
                    application_id="application-a",
                    scope=scope,
                    idempotency_key="operation-b",
                    request_digest="b" * 64,
                    operation_kind="database",
                    status="pending",
                )
            )

    with database.session() as session:
        record = session.query(DatabaseOperationRecord).filter_by(scope=scope).one()
        record.status = "succeeded"

    with database.session() as session:
        session.add(
            DatabaseOperationRecord(
                id=new_id(),
                tenant_id="tenant-a",
                application_id="application-a",
                scope=scope,
                idempotency_key="operation-c",
                request_digest="c" * 64,
                operation_kind="database",
                status="running",
            )
        )

    database.dispose()


def test_durable_duplicate_dump_replays_stored_typed_outcome_without_broker_rerun(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite+pysqlite:///{(tmp_path / 'duplicate-dump.sqlite3').as_posix()}")
    database.initialize()
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "duplicate-dump-boundary")
    broker = FakeBroker()
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=SqlAlchemyDatabaseOperationLedger(database),
    )
    target = _database_target()
    request = DatabaseDumpRequest(
        target=target,
        backup_id="backup-a",
        idempotency_key="duplicate-dump-a",
        job_id="job-a",
        source_revision=SOURCE_REVISION,
        application_artifact_digest=APPLICATION_DIGEST,
        requested_at=STAMP,
    )
    first = adapter.dump(request)
    assert first.passed
    assert first.artifact is not None
    assert len(broker.operations) == 1

    database.dispose()
    reopened = Database(f"sqlite+pysqlite:///{(tmp_path / 'duplicate-dump.sqlite3').as_posix()}")
    reopened.initialize()
    replay_broker = FakeBroker(payload=b"SHOULD NOT RUN")
    replay_adapter = MariaDBAdapter(
        broker=replay_broker,
        filesystem=filesystem,
        ledger=SqlAlchemyDatabaseOperationLedger(reopened),
    )
    replay_request = DatabaseDumpRequest(
        target=target,
        backup_id="backup-a",
        idempotency_key="duplicate-dump-a",
        job_id="job-a",
        source_revision=SOURCE_REVISION,
        application_artifact_digest=APPLICATION_DIGEST,
        requested_at=STAMP + timedelta(seconds=1),
    )
    replayed = replay_adapter.dump(replay_request)
    assert replayed.passed
    assert replayed.artifact is not None
    assert replayed.artifact.manifest.digest == first.artifact.manifest.digest
    assert replay_broker.operations == []
    reopened.dispose()


def test_durable_duplicate_restore_replays_stored_typed_outcome_without_broker_rerun(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite+pysqlite:///{(tmp_path / 'duplicate-restore.sqlite3').as_posix()}")
    database.initialize()
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "duplicate-restore-boundary")
    broker = FakeBroker()
    target = _database_target()
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=SqlAlchemyDatabaseOperationLedger(database),
    )
    dump = adapter.dump(
        DatabaseDumpRequest(
            target=target,
            backup_id="backup-a",
            idempotency_key="duplicate-restore-dump-a",
            job_id="job-dump-a",
            source_revision=SOURCE_REVISION,
            application_artifact_digest=APPLICATION_DIGEST,
            requested_at=STAMP,
        )
    )
    assert dump.artifact is not None

    restore_target = _restore_target(target)
    registry = InMemoryDatabaseRestoreTargetRegistry()
    registry.register(
        restore_target,
        source_target_reference=target.target_reference,
        source_database_identifier=target.database_identifier,
        source_logical_database_name=target.logical_database_name,
    )
    restore_adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=SqlAlchemyDatabaseOperationLedger(database),
        restore_target_registry=registry,
    )
    request = DatabaseRestoreRequest(
        artifact=dump.artifact,
        target=restore_target,
        idempotency_key="duplicate-restore-a",
        requested_at=STAMP,
    )
    first = restore_adapter.restore(request)
    assert first.passed
    assert len(broker.operations) == 4

    database.dispose()
    reopened = Database(f"sqlite+pysqlite:///{(tmp_path / 'duplicate-restore.sqlite3').as_posix()}")
    reopened.initialize()
    replay_broker = FakeBroker(payload=b"SHOULD NOT RUN")
    replay_adapter = MariaDBAdapter(
        broker=replay_broker,
        filesystem=filesystem,
        ledger=SqlAlchemyDatabaseOperationLedger(reopened),
        restore_target_registry=registry,
    )
    replay_request = DatabaseRestoreRequest(
        artifact=dump.artifact,
        target=restore_target,
        idempotency_key="duplicate-restore-a",
        requested_at=STAMP + timedelta(seconds=1),
    )
    replayed = replay_adapter.restore(replay_request)
    assert replayed.passed
    assert replayed.verification is not None
    assert replayed.verification.observed_database_name == restore_target.restore_database_name
    assert replay_broker.operations == []
    reopened.dispose()
