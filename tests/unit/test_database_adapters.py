from __future__ import annotations

import base64
import hashlib
import io
import subprocess
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import appcare.database.broker as database_broker_module
from appcare.backups.models import RecoveryEvidence, VaultReceipt
from appcare.backups.paths import BackupFilesystemBoundary
from appcare.connectors.linux_ssh_contracts import LinuxTarget
from appcare.database import (
    DatabaseArtifactError,
    DatabaseBrokerResult,
    DatabaseCleanupStatus,
    DatabaseCommand,
    DatabaseCommandRegistry,
    DatabaseCredentialReference,
    DatabaseDumpArtifact,
    DatabaseDumpFormat,
    DatabaseDumpRequest,
    DatabaseKind,
    DatabaseLimits,
    DatabaseManifest,
    DatabaseOperationKind,
    DatabaseOperationLedger,
    DatabaseOperationRejected,
    DatabaseOperationStatus,
    DatabaseProbe,
    DatabaseRestoreError,
    DatabaseRestoreRequest,
    DatabaseRestoreTarget,
    DatabaseTarget,
    DatabaseTargetError,
    DatabaseVerifyRequest,
    InMemoryDatabaseCredentialProvider,
    InMemoryDatabaseRestoreTargetRegistry,
    MariaDBAdapter,
    ResolvedDatabaseCredential,
    database_artifact_component,
    database_capability_evidence,
    register_database_capability_evidence,
    validate_database_name,
    validate_mariadb_restore_artifact,
)
from appcare.database.broker import SubprocessDatabaseBroker
from appcare.readiness import (
    ApplicationCapabilityRegistry,
    CapabilityStatus,
    CoordinatorApproval,
    EvidenceClass,
    ReadinessValidationError,
)

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


def _credential() -> tuple[DatabaseCredentialReference, ResolvedDatabaseCredential]:
    reference = DatabaseCredentialReference(
        reference="vault://appcare/database-a",
        tenant_id="tenant-a",
        application_id="application-a",
        issued_at=STAMP,
    )
    resolved_fields = {"reference": reference.reference, "username": "appcare"}
    resolved_fields["secret"] = _database_auth_material()
    resolved = ResolvedDatabaseCredential(**resolved_fields)
    return reference, resolved


def _database_target(**changes: object) -> DatabaseTarget:
    credential, _ = _credential()
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
    values.update(changes)
    return DatabaseTarget.from_linux_target(_linux_target(), **cast(Any, values))


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
        *,
        restore_status: DatabaseOperationStatus = DatabaseOperationStatus.PASSED,
        restore_reason: str = "ok",
        verify_status: DatabaseOperationStatus = DatabaseOperationStatus.PASSED,
        verify_reason: str = "ok",
        verify_database_name: str | None = None,
        verify_object_count: int | None = None,
        precheck_object_count: int | None = None,
        cleanup_result: str | bool | None = None,
    ) -> None:
        self.payload = payload
        self.restore_status = restore_status
        self.restore_reason = restore_reason
        self.verify_status = verify_status
        self.verify_reason = verify_reason
        self.verify_database_name = verify_database_name
        self.verify_object_count = verify_object_count
        self.precheck_object_count = precheck_object_count
        self.cleanup_result = cleanup_result
        self.operations: list[object] = []
        self.targets: list[DatabaseTarget] = []
        self.reported_digest: str | None = None
        self.cleanup_targets: list[DatabaseRestoreTarget] = []

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
        self.targets.append(target)
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
                artifact_sha256=self.reported_digest or digest,
            )
        if isinstance(operation, DatabaseRestoreRequest):
            return DatabaseBrokerResult(
                operation_id=operation.operation_id,
                operation=DatabaseOperationKind.LOGICAL_RESTORE,
                status=self.restore_status,
                reason_code=self.restore_reason,
                template_id="mysql.restore.logical.v1",
            )
        if isinstance(operation, DatabaseVerifyRequest):
            restored_object_count = (
                self.precheck_object_count if operation.require_empty else self.verify_object_count
            )
            if restored_object_count is None:
                restored_object_count = (
                    0 if operation.require_empty else len(operation.expected_object_names) or 1
                )
            return DatabaseBrokerResult(
                operation_id=operation.operation_id,
                operation=(
                    DatabaseOperationKind.PRE_RESTORE_VERIFY
                    if operation.require_empty
                    else DatabaseOperationKind.POST_RESTORE_VERIFY
                ),
                status=self.verify_status,
                reason_code=self.verify_reason,
                template_id=(
                    "mysql.verify.empty.v1"
                    if operation.require_empty
                    else "mysql.verify.restore.v1"
                ),
                observed_database_name=(
                    target.logical_database_name
                    if operation.require_empty
                    else self.verify_database_name or target.logical_database_name
                ),
                restored_object_count=restored_object_count,
            )
        raise AssertionError("unexpected database operation")

    def cleanup_restore_target(self, *, target: DatabaseRestoreTarget) -> str | bool | None:
        self.cleanup_targets.append(target)
        return self.cleanup_result


class FakePipe:
    def __init__(self, payload: bytes) -> None:
        self._stream = io.BytesIO(payload)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)


class FakeProcess:
    def __init__(
        self,
        *,
        stdout_bytes: bytes = b"",
        stderr_bytes: bytes = b"",
        returncode: int = 0,
        running: bool = False,
    ) -> None:
        self.stdout = FakePipe(stdout_bytes)
        self.stderr = FakePipe(stderr_bytes)
        self.returncode = returncode
        self._running = running
        self.kill_count = 0
        self.pid = 4242

    def poll(self) -> int | None:
        if self._running:
            return None
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode

    def kill(self) -> None:
        self.kill_count += 1
        self._running = False
        self.returncode = -9


class CapturingPopenFactory:
    def __init__(self, process: FakeProcess) -> None:
        self.process = process
        self.argv: tuple[str, ...] | None = None
        self.env: dict[str, str] | None = None
        self.credential_path: Path | None = None
        self.credential_snapshot = ""

    def __call__(self, argv: tuple[str, ...], **kwargs: object) -> FakeProcess:
        self.argv = tuple(argv)
        self.env = dict(cast(dict[str, str], kwargs["env"]))
        defaults_file = next(
            (
                value.split("=", 1)[1]
                for value in self.argv
                if value.startswith("--defaults-extra-file=")
            ),
            None,
        )
        credential_location = defaults_file or self.env.get("PGPASSFILE")
        assert credential_location is not None
        self.credential_path = Path(credential_location)
        self.credential_snapshot = self.credential_path.read_text(encoding="utf-8")
        return self.process


def _typed_popen_factory(factory: CapturingPopenFactory) -> Callable[..., subprocess.Popen[bytes]]:
    return cast(Callable[..., subprocess.Popen[bytes]], factory)


class CapturingEvidenceSink:
    def __init__(self) -> None:
        self.items: list[object] = []

    def save_capability_evidence(self, evidence: object) -> object:
        self.items.append(evidence)
        return evidence


def _dump_request(target: DatabaseTarget, *, job_id: str = "job-a") -> DatabaseDumpRequest:
    return DatabaseDumpRequest(
        target=target,
        backup_id="backup-a",
        idempotency_key=f"dump-{job_id}",
        job_id=job_id,
        source_revision=SOURCE_REVISION,
        application_artifact_digest=APPLICATION_DIGEST,
        requested_at=STAMP,
    )


def _dump_artifact(
    filesystem: BackupFilesystemBoundary,
    source: DatabaseTarget,
    *,
    job_id: str = "job-source",
    payload: bytes = b"-- synthetic dump\nCREATE TABLE demo (id INT);\n",
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE,
) -> DatabaseDumpArtifact:
    filesystem.ensure_data_dirs()
    job = filesystem.staging_path(job_id)
    job.mkdir(parents=True)
    dump_path = job / "database.sql"
    dump_path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    manifest = DatabaseManifest(
        backup_id="backup-a",
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
        artifact_sha256=digest,
        consistency=source.consistency,
        limitation_codes=("test_fixture",),
        created_at=STAMP,
        source_revision=SOURCE_REVISION,
        application_artifact_digest=APPLICATION_DIGEST,
        evidence_class=evidence_class,
    )
    return DatabaseDumpArtifact(
        manifest=manifest,
        artifact_path=dump_path,
        staging_job_id=job_id,
        filesystem=filesystem,
        evidence_class=evidence_class,
    )


def test_target_binds_database_identity_to_linux_inventory() -> None:
    target = _database_target()
    assert target.database_identifier in target.approved_database_identifiers
    assert target.logical_database_name in target.approved_database_identifiers
    with pytest.raises(DatabaseTargetError):
        _database_target(database_identifier="unlisted", logical_database_name="unlisted")
    with pytest.raises(DatabaseTargetError):
        _database_target(database_host="192.0.2.55")


@pytest.mark.parametrize("value", ["", "../db", "/db", "db;drop", "db name", "db\\name"])
def test_database_names_are_fail_closed(value: str) -> None:
    with pytest.raises(DatabaseTargetError):
        validate_database_name(value)


def test_commands_are_closed_and_mariadb_dump_cannot_select_database_on_restore(
    tmp_path: Path,
) -> None:
    target = _database_target()
    request = _dump_request(target)
    registry = DatabaseCommandRegistry()
    output = Path("C:/appcare/staging/job-a/database.sql")
    dump = registry.build_dump(request, output_path=output)
    assert "--databases" not in dump.argv
    assert dump.argv[-2] == "appdb"
    assert dump.argv[-1].startswith("--result-file=")
    assert all(_database_auth_material() not in value for value in dump.argv)
    with pytest.raises(DatabaseOperationRejected):
        DatabaseCommand(
            operation_id="op-a",
            operation=DatabaseOperationKind.LOGICAL_DUMP,
            template_id="mysql.dump.logical.v1",
            argv=("mysql", "--execute=SELECT 1; DROP TABLE demo"),
        )
    verify = registry.build_verify(
        DatabaseVerifyRequest(
            artifact=_dump_artifact(BackupFilesystemBoundary.for_test(tmp_path / "verify"), target),
            target=_restore_target(target),
            idempotency_key="verify-a",
            expected_object_names=("demo",),
            requested_at=STAMP,
        ),
        artifact_path=output,
    )
    assert (
        "--execute=SELECT DATABASE(), (SELECT COUNT(*) FROM information_schema.tables"
        in (verify.argv[-1])
    )
    assert "'demo'" in verify.argv[-1]


def test_restore_commands_use_stdin_and_pre_restore_verification_is_distinct(
    tmp_path: Path,
) -> None:
    target = _database_target(engine_family=DatabaseKind.POSTGRESQL)
    restore_target = _restore_target(target)
    artifact = _dump_artifact(
        BackupFilesystemBoundary.for_test(tmp_path / "postgres-commands"),
        target,
        payload=b"PGDMP synthetic",
    )
    artifact = DatabaseDumpArtifact(
        manifest=DatabaseManifest(
            backup_id=artifact.manifest.backup_id,
            tenant_id=artifact.manifest.tenant_id,
            application_id=artifact.manifest.application_id,
            stack_id=artifact.manifest.stack_id,
            target_reference=artifact.manifest.target_reference,
            transport_target_reference=artifact.manifest.transport_target_reference,
            engine_family=DatabaseKind.POSTGRESQL,
            database_identifier=artifact.manifest.database_identifier,
            logical_database_name=artifact.manifest.logical_database_name,
            dump_format=DatabaseDumpFormat.POSTGRES_CUSTOM,
            tool_profile="postgresql-custom-v1",
            artifact_size_bytes=artifact.manifest.artifact_size_bytes,
            artifact_sha256=artifact.manifest.artifact_sha256,
            consistency=artifact.manifest.consistency,
            limitation_codes=artifact.manifest.limitation_codes,
            created_at=artifact.manifest.created_at,
            evidence_class=artifact.evidence_class,
        ),
        artifact_path=artifact.artifact_path,
        staging_job_id=artifact.staging_job_id,
        filesystem=artifact.filesystem,
        evidence_class=artifact.evidence_class,
    )
    registry = DatabaseCommandRegistry()
    restore = registry.build_restore(
        DatabaseRestoreRequest(
            artifact=artifact,
            target=restore_target,
            idempotency_key="postgres-restore",
            requested_at=STAMP,
        ),
        artifact_path=artifact.artifact_path,
    )
    assert restore.uses_stdin_artifact
    assert str(artifact.artifact_path) not in restore.argv

    precheck = registry.build_verify(
        DatabaseVerifyRequest(
            artifact=artifact,
            target=restore_target,
            idempotency_key="postgres-precheck",
            require_empty=True,
            requested_at=STAMP,
        ),
        artifact_path=artifact.artifact_path,
    )
    assert precheck.operation == DatabaseOperationKind.PRE_RESTORE_VERIFY
    assert precheck.template_id == "postgres.verify.empty.v1"
    assert "relname IN" not in precheck.argv[-1]


def test_mysql_pre_restore_verification_uses_tabular_output_shape(
    tmp_path: Path,
) -> None:
    target = _database_target()
    artifact = _dump_artifact(BackupFilesystemBoundary.for_test(tmp_path / "mysql-verify"), target)
    command = DatabaseCommandRegistry().build_verify(
        DatabaseVerifyRequest(
            artifact=artifact,
            target=_restore_target(target),
            idempotency_key="mysql-precheck-shape",
            require_empty=True,
            requested_at=STAMP,
        ),
        artifact_path=artifact.artifact_path,
    )

    assert SubprocessDatabaseBroker._parse_verification_output(
        command,
        b"appdb_restore\t0\n",
    ) == ("appdb_restore", 0)


@pytest.mark.parametrize(
    ("engine_family", "port"),
    (
        (DatabaseKind.MARIADB_MYSQL, 3306),
        (DatabaseKind.POSTGRESQL, 5432),
    ),
)
def test_subprocess_broker_keeps_credential_material_out_of_argv_env_and_errors(
    tmp_path: Path,
    engine_family: DatabaseKind,
    port: int,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / f"broker-{engine_family.value}")
    credential, resolved = _credential()
    provider = InMemoryDatabaseCredentialProvider({credential.reference: resolved})
    target = _database_target(engine_family=engine_family, database_port=port)
    process = FakeProcess(stderr_bytes=b"password=redacted")
    factory = CapturingPopenFactory(process)
    broker = SubprocessDatabaseBroker(
        provider,
        filesystem=filesystem,
        popen_factory=_typed_popen_factory(factory),
    )

    result = broker.run(DatabaseProbe("probe-auth-boundary"), target=target)

    assert factory.argv is not None
    assert factory.env is not None
    assert factory.credential_path is not None
    auth_material = _database_auth_material()
    assert auth_material in factory.credential_snapshot
    assert auth_material not in " ".join(factory.argv)
    assert all(auth_material not in value for value in factory.env.values())
    assert auth_material not in result.sanitized_stderr
    assert result.sanitized_stderr == "credential-shaped-output-redacted"
    assert not factory.credential_path.exists()
    assert not factory.credential_path.parent.exists()


def test_subprocess_broker_cancels_probe_without_leaking_credentials(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "broker-cancel")
    credential, resolved = _credential()
    provider = InMemoryDatabaseCredentialProvider({credential.reference: resolved})
    process = FakeProcess(running=True)
    factory = CapturingPopenFactory(process)
    broker = SubprocessDatabaseBroker(
        provider,
        filesystem=filesystem,
        popen_factory=_typed_popen_factory(factory),
    )
    cancel_event = threading.Event()
    cancel_event.set()

    result = broker.run(
        DatabaseProbe("probe-cancel"),
        target=_database_target(),
        cancel_event=cancel_event,
    )

    assert result.status == DatabaseOperationStatus.CANCELLED
    assert result.reason_code == "operation_cancelled"
    assert process.kill_count == 1
    assert result.sanitized_stderr == ""
    assert factory.credential_path is not None
    assert not factory.credential_path.exists()


def test_subprocess_broker_times_out_probe_and_kills_process(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "broker-timeout")
    credential, resolved = _credential()
    provider = InMemoryDatabaseCredentialProvider({credential.reference: resolved})
    process = FakeProcess(running=True)
    factory = CapturingPopenFactory(process)
    broker = SubprocessDatabaseBroker(
        provider,
        filesystem=filesystem,
        popen_factory=_typed_popen_factory(factory),
    )
    target = _database_target(limits=DatabaseLimits(probe_timeout_seconds=0.5))

    result = broker.run(DatabaseProbe("probe-timeout"), target=target)

    assert result.status == DatabaseOperationStatus.TIMED_OUT
    assert result.reason_code == "operation_timed_out"
    assert result.timed_out is True
    assert process.kill_count == 1
    assert factory.credential_path is not None
    assert not factory.credential_path.exists()


def test_subprocess_broker_enforces_bounded_stderr_output(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "broker-output-limit")
    credential, resolved = _credential()
    provider = InMemoryDatabaseCredentialProvider({credential.reference: resolved})
    process = FakeProcess(stderr_bytes=b"x" * 33, running=True)
    factory = CapturingPopenFactory(process)
    broker = SubprocessDatabaseBroker(
        provider,
        filesystem=filesystem,
        popen_factory=_typed_popen_factory(factory),
    )
    target = _database_target(limits=DatabaseLimits(max_stderr_bytes=32))

    result = broker.run(DatabaseProbe("probe-output-limit"), target=target)

    assert result.status == DatabaseOperationStatus.OUTPUT_LIMITED
    assert result.reason_code == "output_limit_exceeded"
    assert result.output_limited is True
    assert process.kill_count == 1


def test_subprocess_broker_classifies_credential_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "broker-cleanup-failure")
    credential, resolved = _credential()
    provider = InMemoryDatabaseCredentialProvider({credential.reference: resolved})
    process = FakeProcess()
    factory = CapturingPopenFactory(process)
    broker = SubprocessDatabaseBroker(
        provider,
        filesystem=filesystem,
        popen_factory=_typed_popen_factory(factory),
    )
    original_remove = database_broker_module._safe_remove

    def fail_credential_dir_once(path: Path) -> bool:
        if factory.credential_path is not None and path == factory.credential_path.parent:
            return False
        return original_remove(path)

    monkeypatch.setattr(database_broker_module, "_safe_remove", fail_credential_dir_once)

    result = broker.run(DatabaseProbe("probe-cleanup-failure"), target=_database_target())

    assert result.status == DatabaseOperationStatus.FAILED
    assert result.reason_code == "credential_cleanup_failed"
    assert result.sanitized_stderr == "credential-cleanup-failed"
    assert factory.credential_path is not None
    original_remove(factory.credential_path.parent)


def test_dump_is_checksum_and_manifest_bound(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "boundary")
    broker = FakeBroker()
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
    )
    result = adapter.dump(_dump_request(_database_target()))
    assert result.passed
    assert result.artifact is not None
    assert result.artifact.manifest.source_revision == SOURCE_REVISION
    assert result.artifact.manifest.application_artifact_digest == APPLICATION_DIGEST
    assert result.artifact.artifact_path.exists()


def test_dump_rejects_broker_checksum_mismatch_and_cleans_disposable_output(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "mismatch")
    broker = FakeBroker()
    broker.reported_digest = "c" * 64
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
    )
    result = adapter.dump(_dump_request(_database_target(), job_id="job-mismatch"))
    assert result.passed is False
    assert result.reason_code == "dump_artifact_invalid"
    assert not filesystem.staging_path("job-mismatch").exists()


def test_dump_rejects_unsafe_mariadb_artifact_before_manifest_seal(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "unsafe-dump")
    broker = FakeBroker(payload=b"CREATE OR REPLACE PROCEDURE p() SELECT 1;\n")
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
    )

    result = adapter.dump(_dump_request(_database_target(), job_id="job-unsafe"))

    assert result.passed is False
    assert result.reason_code == "dump_artifact_unsafe"
    assert not filesystem.staging_path("job-unsafe").exists()


def test_restore_requires_registered_isolated_target_and_preserves_source_artifact(
    tmp_path: Path,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "restore")
    source = _database_target()
    payload = b"-- synthetic dump\nCREATE TABLE demo (id INT);\n"
    artifact = _dump_artifact(filesystem, source, payload=payload)
    dump_path = artifact.artifact_path
    restore_target = _restore_target(source)
    request = DatabaseRestoreRequest(
        artifact=artifact,
        target=restore_target,
        idempotency_key="restore-a",
        requested_at=STAMP,
    )
    broker = FakeBroker(payload)
    unregistered = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
    )
    blocked = unregistered.restore(request)
    assert blocked.passed is False
    assert blocked.reason_code == "restore_target_unavailable"
    assert dump_path.exists()
    assert broker.operations == []

    registry = InMemoryDatabaseRestoreTargetRegistry()
    registry.register(
        restore_target,
        source_target_reference=source.target_reference,
        source_database_identifier=source.database_identifier,
        source_logical_database_name=source.logical_database_name,
    )
    accepted_broker = FakeBroker(payload)
    adapter = MariaDBAdapter(
        broker=accepted_broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
        restore_target_registry=registry,
    )
    accepted = adapter.restore(request)
    assert accepted.passed
    assert dump_path.exists()
    assert accepted.verification is not None
    assert accepted.verification.observed_database_name == restore_target.restore_database_name
    assert accepted.verification.restored_object_count == 1
    assert [type(item) for item in accepted_broker.operations] == [
        DatabaseVerifyRequest,
        DatabaseRestoreRequest,
        DatabaseVerifyRequest,
    ]
    assert accepted_broker.targets[0].target_reference == "reference://restore-a:database"


@pytest.mark.parametrize(
    "payload",
    [
        "USE original_database;\n",
        "/*!40101 USE original_database */;\n",
        "USE/**/original_database;\n",
        "/* padding */ CREATE/**/DATABASE escaped;\n",
        "/*!50003 GRANT ALL PRIVILEGES ON *.* TO bad_actor */;\n",
        "CREATE DEFINER=`bad`@`%` PROCEDURE p() SELECT 1;\n",
        "CREATE OR REPLACE PROCEDURE p() SELECT 1;\n",
        "CREATE DEFINER = `bad`@`%` FUNCTION f() RETURNS INT RETURN 1;\n",
        "CREATE DEFINER = `bad`@`%` VIEW v AS SELECT 1;\n",
        "CREATE SQL SECURITY DEFINER VIEW v AS SELECT 1;\n",
        "CREATE DEFI/**/NER = `bad`@`%` VIEW v AS SELECT 1;\n",
        "CREATE FUNCTION f() RETURNS INT RETURN 1;\n",
        "CREATE TRIGGER t BEFORE INSERT ON demo FOR EACH ROW SET @x=1;\n",
        "/*!50000 CREATE/**/DATABASE escaped */;\n",
    ],
)
def test_mariadb_restore_rejects_database_context_directives_before_broker(
    tmp_path: Path,
    payload: str,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "hostile")
    filesystem.ensure_data_dirs()
    job = filesystem.staging_path("job-hostile")
    job.mkdir(parents=True)
    artifact = job / "database.sql"
    artifact.write_text(payload, encoding="utf-8")
    with pytest.raises(DatabaseRestoreError):
        validate_mariadb_restore_artifact(artifact, expected_size=artifact.stat().st_size)


def test_mariadb_restore_rejects_ambiguous_executable_comment_and_unclosed_quote(
    tmp_path: Path,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "ambiguous-sql")
    filesystem.ensure_data_dirs()
    job = filesystem.staging_path("job-ambiguous")
    job.mkdir(parents=True)
    artifact = job / "database.sql"
    artifact.write_text(
        "/*!50000 SET x = /* hidden */ DROP DATABASE escaped */;\n",
        encoding="utf-8",
    )
    with pytest.raises(DatabaseRestoreError):
        validate_mariadb_restore_artifact(artifact, expected_size=artifact.stat().st_size)

    artifact.write_text("CREATE TABLE `demo;\n", encoding="utf-8")
    with pytest.raises(DatabaseArtifactError):
        validate_mariadb_restore_artifact(artifact, expected_size=artifact.stat().st_size)


def test_mariadb_restore_validation_ignores_keywords_inside_string_literals(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "benign")
    artifact = _dump_artifact(
        filesystem,
        _database_target(),
        payload=b"CREATE TABLE demo (id INT);\nINSERT INTO demo VALUES ('USE prod');\n",
    )
    validate_mariadb_restore_artifact(
        artifact.artifact_path,
        expected_size=artifact.artifact_path.stat().st_size,
    )


def test_restore_rejects_production_target_and_cross_scope_artifact(tmp_path: Path) -> None:
    source = _database_target()
    with pytest.raises(DatabaseRestoreError):
        _restore_target(source, environment="production")
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "component")
    filesystem.ensure_data_dirs()
    job = filesystem.staging_path("job-component")
    job.mkdir(parents=True)
    payload = b"CREATE TABLE demo (id INT);\n"
    path = job / "database.sql"
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    manifest = DatabaseManifest(
        backup_id="backup-component",
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
        artifact_sha256=digest,
        consistency=source.consistency,
        limitation_codes=(),
        created_at=STAMP,
    )
    component = database_artifact_component(
        DatabaseDumpArtifact(manifest, path, "job-component", filesystem=filesystem)
    )
    assert component.digest == digest


def test_in_memory_ledger_rejects_conflict_and_replay_after_restart() -> None:
    ledger = DatabaseOperationLedger()
    assert ledger.claim(
        scope="tenant-a:app-a:db:test", idempotency_key="op-a", request_digest="a"
    ) == (
        "new",
        None,
    )
    assert (
        ledger.claim(scope="tenant-a:app-a:db:test", idempotency_key="op-b", request_digest="b")[0]
        == "active"
    )
    ledger.complete(
        scope="tenant-a:app-a:db:test",
        idempotency_key="op-a",
        outcome={"passed": True},
    )
    assert (
        ledger.claim(scope="tenant-a:app-a:db:test", idempotency_key="op-a", request_digest="a")[0]
        == "duplicate"
    )
    assert (
        ledger.claim(scope="tenant-a:app-a:db:test", idempotency_key="op-a", request_digest="c")[0]
        == "conflict"
    )
    assert (
        ledger.claim(scope="tenant-a:app-a:db:test", idempotency_key="op-c", request_digest="c")[0]
        == "new"
    )


def test_restore_failure_records_quarantine_requirement_and_preserves_source_artifact(
    tmp_path: Path,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "restore-failure")
    source = _database_target()
    artifact = _dump_artifact(filesystem, source)
    restore_target = _restore_target(source)
    registry = InMemoryDatabaseRestoreTargetRegistry()
    registry.register(
        restore_target,
        source_target_reference=source.target_reference,
        source_database_identifier=source.database_identifier,
        source_logical_database_name=source.logical_database_name,
    )
    broker = FakeBroker(
        restore_status=DatabaseOperationStatus.FAILED,
        restore_reason="database_command_failed",
        cleanup_result=False,
    )
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
        restore_target_registry=registry,
    )
    result = adapter.restore(
        DatabaseRestoreRequest(
            artifact=artifact,
            target=restore_target,
            idempotency_key="restore-failure",
            requested_at=STAMP,
        )
    )
    assert result.passed is False
    assert result.reason_code == "database_command_failed"
    assert result.cleanup_status == DatabaseCleanupStatus.QUARANTINED
    assert result.cleanup_reference == restore_target.cleanup_owner_reference
    assert artifact.artifact_path.exists()
    assert broker.cleanup_targets == [restore_target]


def test_restore_verification_failure_runs_bounded_cleanup_when_available(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "restore-verify-failure")
    source = _database_target()
    artifact = _dump_artifact(filesystem, source)
    restore_target = _restore_target(source)
    registry = InMemoryDatabaseRestoreTargetRegistry()
    registry.register(
        restore_target,
        source_target_reference=source.target_reference,
        source_database_identifier=source.database_identifier,
        source_logical_database_name=source.logical_database_name,
    )
    broker = FakeBroker(verify_object_count=0, cleanup_result="job://restore-cleanup-a")
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
        restore_target_registry=registry,
    )
    result = adapter.restore(
        DatabaseRestoreRequest(
            artifact=artifact,
            target=restore_target,
            idempotency_key="restore-verify-failure",
            requested_at=STAMP,
        )
    )
    assert result.passed is False
    assert result.reason_code == "restore_objects_missing"
    assert result.verification is not None
    assert result.cleanup_status == DatabaseCleanupStatus.CLEANED
    assert result.cleanup_reference == "job://restore-cleanup-a"
    assert broker.cleanup_targets == [restore_target]
    assert artifact.artifact_path.exists()


def test_restore_verification_fails_closed_on_wrong_database_identity(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "restore-identity")
    source = _database_target()
    artifact = _dump_artifact(filesystem, source)
    restore_target = _restore_target(source)
    registry = InMemoryDatabaseRestoreTargetRegistry()
    registry.register(
        restore_target,
        source_target_reference=source.target_reference,
        source_database_identifier=source.database_identifier,
        source_logical_database_name=source.logical_database_name,
    )
    broker = FakeBroker(verify_database_name="wrong_restore_db", cleanup_result=True)
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
        restore_target_registry=registry,
    )
    result = adapter.restore(
        DatabaseRestoreRequest(
            artifact=artifact,
            target=restore_target,
            idempotency_key="restore-identity-failure",
            requested_at=STAMP,
        )
    )
    assert result.passed is False
    assert result.reason_code == "restore_identity_mismatch"
    assert result.cleanup_status == DatabaseCleanupStatus.CLEANED
    assert result.verification is not None
    assert result.verification.observed_database_name == "wrong_restore_db"


def test_restore_rejects_and_quarantines_a_preexisting_target(tmp_path: Path) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "restore-nonempty")
    source = _database_target()
    artifact = _dump_artifact(filesystem, source)
    restore_target = _restore_target(source)
    registry = InMemoryDatabaseRestoreTargetRegistry()
    registry.register(
        restore_target,
        source_target_reference=source.target_reference,
        source_database_identifier=source.database_identifier,
        source_logical_database_name=source.logical_database_name,
    )
    broker = FakeBroker(precheck_object_count=1)
    adapter = MariaDBAdapter(
        broker=broker,
        filesystem=filesystem,
        ledger=DatabaseOperationLedger(),
        restore_target_registry=registry,
    )

    result = adapter.restore(
        DatabaseRestoreRequest(
            artifact=artifact,
            target=restore_target,
            idempotency_key="restore-nonempty",
            requested_at=STAMP,
        )
    )

    assert result.reason_code == "restore_target_not_empty"
    assert result.cleanup_status == DatabaseCleanupStatus.QUARANTINED
    assert result.cleanup_reference == restore_target.cleanup_owner_reference
    assert [type(item) for item in broker.operations] == [DatabaseVerifyRequest]
    with pytest.raises(DatabaseRestoreError, match="quarantined"):
        registry.resolve(restore_target, source_manifest=artifact.manifest)


def test_database_capability_evidence_requires_verified_readback_and_receipt(
    tmp_path: Path,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "capability")
    source = _database_target()
    artifact = _dump_artifact(
        filesystem,
        source,
        evidence_class=EvidenceClass.CONTROLLED_LIVE_PROVIDER,
    )
    approval = CoordinatorApproval.for_luna(artifact.evidence_digest, approved_at=STAMP)
    blocked = database_capability_evidence(
        artifact,
        evidence_ref="evidence/database-backup-a",
        coordinator_approval=approval,
        readback_evidence=None,
        vault_receipt=None,
        observed_at=STAMP,
    )
    assert blocked.status == CapabilityStatus.BLOCKED_EXTERNAL

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
        object_reference="memory://database/backup-a",
        artifact_digest=artifact.artifact_digest,
        retained_until=STAMP,
    )
    supported = database_capability_evidence(
        artifact,
        evidence_ref="evidence/database-backup-a",
        coordinator_approval=approval,
        readback_evidence=readback,
        vault_receipt=receipt,
        observed_at=STAMP,
    )
    assert supported.status == CapabilityStatus.SUPPORTED
    assert supported.source_revision == SOURCE_REVISION
    assert supported.artifact_digest == APPLICATION_DIGEST

    unbound_artifact = replace(
        artifact,
        manifest=replace(
            artifact.manifest,
            source_revision=None,
            application_artifact_digest=None,
        ),
    )
    unbound = database_capability_evidence(
        unbound_artifact,
        evidence_ref="evidence/database-backup-a",
        coordinator_approval=CoordinatorApproval.for_luna(
            unbound_artifact.evidence_digest,
            approved_at=STAMP,
        ),
        readback_evidence=RecoveryEvidence(
            backup_id=unbound_artifact.manifest.backup_id,
            status="verified",
            component_names=("database",),
            manifest_digest=unbound_artifact.manifest_digest,
            artifact_digest=unbound_artifact.artifact_digest,
            rpo_observed_seconds=1,
            rto_observed_seconds=1,
            controlled_test_only=True,
        ),
        vault_receipt=VaultReceipt(
            backup_id=unbound_artifact.manifest.backup_id,
            provider="filesystem",
            object_reference="memory://database/backup-unbound",
            artifact_digest=unbound_artifact.artifact_digest,
            retained_until=STAMP,
        ),
        observed_at=STAMP,
    )
    assert unbound.status == CapabilityStatus.BLOCKED_EXTERNAL
    assert unbound.source_revision is None
    assert unbound.artifact_digest is None

    mismatched = database_capability_evidence(
        artifact,
        evidence_ref="evidence/database-backup-a",
        coordinator_approval=approval,
        readback_evidence=RecoveryEvidence(
            backup_id=artifact.manifest.backup_id,
            status="verified",
            component_names=("database",),
            manifest_digest="c" * 64,
            artifact_digest=artifact.artifact_digest,
            rpo_observed_seconds=1,
            rto_observed_seconds=1,
            controlled_test_only=True,
        ),
        vault_receipt=receipt,
        observed_at=STAMP,
    )
    assert mismatched.status == CapabilityStatus.BLOCKED_EXTERNAL

    assert (
        database_capability_evidence(
            artifact,
            evidence_ref="evidence/database-backup-a",
            coordinator_approval=approval,
            readback_evidence=RecoveryEvidence(
                backup_id="backup-other",
                status="verified",
                component_names=("database",),
                manifest_digest=artifact.manifest_digest,
                artifact_digest=artifact.artifact_digest,
                rpo_observed_seconds=1,
                rto_observed_seconds=1,
                controlled_test_only=True,
            ),
            vault_receipt=receipt,
            observed_at=STAMP,
        ).status
        == CapabilityStatus.BLOCKED_EXTERNAL
    )
    assert (
        database_capability_evidence(
            artifact,
            evidence_ref="evidence/database-backup-a",
            coordinator_approval=approval,
            readback_evidence=readback,
            vault_receipt=VaultReceipt(
                backup_id="backup-other",
                provider="filesystem",
                object_reference="memory://database/backup-other",
                artifact_digest=artifact.artifact_digest,
                retained_until=STAMP,
            ),
            observed_at=STAMP,
        ).status
        == CapabilityStatus.BLOCKED_EXTERNAL
    )


def test_database_capability_bridge_registers_and_persists_through_spec013(
    tmp_path: Path,
) -> None:
    filesystem = BackupFilesystemBoundary.for_test(tmp_path / "capability-bridge")
    source = _database_target()
    artifact = _dump_artifact(
        filesystem,
        source,
        evidence_class=EvidenceClass.CONTROLLED_LIVE_PROVIDER,
    )
    approval = CoordinatorApproval.for_luna(artifact.evidence_digest, approved_at=STAMP)
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
        object_reference="memory://database/bridge-a",
        artifact_digest=artifact.artifact_digest,
        retained_until=STAMP,
    )
    registry = ApplicationCapabilityRegistry(
        tenant_id=source.tenant_id,
        application_id=source.application_id,
        stack_id=source.stack_id,
    )
    sink = CapturingEvidenceSink()

    evidence = register_database_capability_evidence(
        artifact,
        capability_registry=registry,
        evidence_ref="evidence/database-bridge-a",
        coordinator_approval=approval,
        readback_evidence=readback,
        vault_receipt=receipt,
        readiness_store=sink,
        observed_at=STAMP,
    )

    assert evidence.status == CapabilityStatus.SUPPORTED
    assert registry.evidence() == (evidence,)
    assert sink.items == [evidence]
    assert _database_auth_material() not in str(evidence.canonical_payload())
    with pytest.raises(ReadinessValidationError, match="duplicated"):
        register_database_capability_evidence(
            artifact,
            capability_registry=registry,
            evidence_ref="evidence/database-bridge-a",
            coordinator_approval=approval,
            readback_evidence=readback,
            vault_receipt=receipt,
            readiness_store=sink,
            observed_at=STAMP,
        )

    wrong_scope = ApplicationCapabilityRegistry(
        tenant_id="tenant-b",
        application_id=source.application_id,
        stack_id=source.stack_id,
    )
    with pytest.raises(ReadinessValidationError, match="scope"):
        register_database_capability_evidence(
            artifact,
            capability_registry=wrong_scope,
            evidence_ref="evidence/database-bridge-b",
            coordinator_approval=approval,
            readback_evidence=readback,
            vault_receipt=receipt,
            observed_at=STAMP,
        )

    blocked_registry = ApplicationCapabilityRegistry(
        tenant_id=source.tenant_id,
        application_id=source.application_id,
        stack_id=source.stack_id,
    )
    blocked_sink = CapturingEvidenceSink()
    blocked = register_database_capability_evidence(
        artifact,
        capability_registry=blocked_registry,
        evidence_ref="evidence/database-bridge-blocked",
        coordinator_approval=None,
        readback_evidence=None,
        vault_receipt=None,
        readiness_store=blocked_sink,
        observed_at=STAMP,
    )
    assert blocked.status == CapabilityStatus.BLOCKED_EXTERNAL
    assert blocked_registry.evidence() == (blocked,)
    assert blocked_sink.items == [blocked]
