"""Provider-neutral orchestration for bounded logical database adapters."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from ..backups.paths import BackupFilesystemBoundary
from ..readiness.contracts import EvidenceClass, validate_evidence_reference
from .broker import (
    SubprocessDatabaseBroker,
    UnavailableDatabaseCredentialProvider,
    _file_digest,
    inspect_mariadb_restore_artifact,
)
from .contracts import (
    DatabaseArtifactError,
    DatabaseBoundaryError,
    DatabaseBrokerResult,
    DatabaseCleanupStatus,
    DatabaseCredentialError,
    DatabaseCredentialProvider,
    DatabaseDumpArtifact,
    DatabaseDumpFormat,
    DatabaseDumpRequest,
    DatabaseDumpResult,
    DatabaseExecutionBroker,
    DatabaseKind,
    DatabaseManifest,
    DatabaseOperationLedgerProtocol,
    DatabaseOperationRejected,
    DatabaseOperationStatus,
    DatabaseRestoreError,
    DatabaseRestoreEvidence,
    DatabaseRestoreRequest,
    DatabaseRestoreTarget,
    DatabaseRestoreTargetRegistry,
    DatabaseTarget,
    DatabaseVerificationResult,
    DatabaseVerifyRequest,
    validate_aware_timestamp,
    validate_database_artifact_path,
    validate_database_name,
    validate_scope_segment,
)


class LedgerClaim:
    NEW = "new"
    DUPLICATE = "duplicate"
    CONFLICT = "conflict"
    ACTIVE = "active"
    RECOVERY_REQUIRED = "recovery_required"


class UnavailableDatabaseRestoreTargetRegistry:
    """Default registry; restore is denied until isolation is registered."""

    def resolve(
        self,
        _requested: DatabaseRestoreTarget,
        *,
        source_manifest: DatabaseManifest,
    ) -> DatabaseRestoreTarget:
        del source_manifest
        raise DatabaseRestoreError("isolated restore target registry is unavailable")

    def quarantine(
        self,
        _requested: DatabaseRestoreTarget,
        *,
        source_manifest: DatabaseManifest,
        cleanup_reference: str,
        reason_code: str,
    ) -> str:
        del source_manifest, cleanup_reference, reason_code
        raise DatabaseRestoreError("isolated restore target registry is unavailable")


class InMemoryDatabaseRestoreTargetRegistry:
    """Reference/test registry; production must inject a durable control-plane registry."""

    def __init__(self) -> None:
        self._records: dict[
            tuple[str, str, str, str], tuple[DatabaseRestoreTarget, str, str, str]
        ] = {}
        self._quarantined: dict[tuple[str, str, str, str], str] = {}

    def register(
        self,
        target: DatabaseRestoreTarget,
        *,
        source_target_reference: str,
        source_database_identifier: str,
        source_logical_database_name: str,
    ) -> None:
        source_target_reference = validate_evidence_reference(source_target_reference)
        source_database_identifier = validate_database_name(
            source_database_identifier,
            field_name="source_database_identifier",
        )
        source_logical_database_name = validate_database_name(
            source_logical_database_name,
            field_name="source_logical_database_name",
        )
        if target.environment == "production":
            raise DatabaseRestoreError("production restore target cannot be registered")
        if target.restore_database_name in {
            source_database_identifier,
            source_logical_database_name,
        }:
            raise DatabaseRestoreError("restore target must differ from source database")
        key = (
            target.tenant_id,
            target.application_id,
            target.stack_id,
            target.isolated_target_reference,
        )
        if key in self._records:
            raise DatabaseRestoreError("isolated restore target is already registered")
        self._records[key] = (
            target,
            source_target_reference,
            source_database_identifier,
            source_logical_database_name,
        )

    def resolve(
        self,
        requested: DatabaseRestoreTarget,
        *,
        source_manifest: DatabaseManifest,
    ) -> DatabaseRestoreTarget:
        key = (
            requested.tenant_id,
            requested.application_id,
            requested.stack_id,
            requested.isolated_target_reference,
        )
        if key in self._quarantined:
            raise DatabaseRestoreError("isolated restore target is quarantined")
        try:
            registered, source_target_reference, source_database_identifier, source_logical_name = (
                self._records[key]
            )
        except KeyError as exc:
            raise DatabaseRestoreError("isolated restore target is not registered") from exc
        if (
            registered != requested
            or source_target_reference != source_manifest.target_reference
            or source_database_identifier != source_manifest.database_identifier
            or source_logical_name != source_manifest.logical_database_name
        ):
            raise DatabaseRestoreError("isolated restore target binding mismatch")
        return registered

    def quarantine(
        self,
        requested: DatabaseRestoreTarget,
        *,
        source_manifest: DatabaseManifest,
        cleanup_reference: str,
        reason_code: str,
    ) -> str:
        cleanup_reference = validate_evidence_reference(cleanup_reference)
        reason_code = validate_scope_segment(reason_code, field_name="reason_code")
        key = (
            requested.tenant_id,
            requested.application_id,
            requested.stack_id,
            requested.isolated_target_reference,
        )
        registered = self.resolve(requested, source_manifest=source_manifest)
        if registered != requested:
            raise DatabaseRestoreError("isolated restore target binding mismatch")
        self._quarantined[key] = reason_code
        return cleanup_reference


class DatabaseOperationLedger:
    """Thread-safe in-memory ledger with durable-ledger compatible semantics.

    Production callers are expected to provide the AppCare durable operation
    store.  This implementation is intentionally explicit and safe for tests:
    an unfinished entry is never silently replayed after a restart.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[tuple[str, str], tuple[str, object | None]] = {}
        self._active_scopes: set[str] = set()

    def claim(
        self, *, scope: str, idempotency_key: str, request_digest: str
    ) -> tuple[str, object | None]:
        key = (scope, idempotency_key)
        with self._lock:
            existing = self._entries.get(key)
            if existing is not None:
                previous_digest, outcome = existing
                if previous_digest != request_digest:
                    return LedgerClaim.CONFLICT, None
                if outcome is None:
                    return LedgerClaim.RECOVERY_REQUIRED, None
                return LedgerClaim.DUPLICATE, outcome
            if scope in self._active_scopes:
                return LedgerClaim.ACTIVE, None
            self._entries[key] = (request_digest, None)
            self._active_scopes.add(scope)
            return LedgerClaim.NEW, None

    def complete(self, *, scope: str, idempotency_key: str, outcome: object) -> None:
        key = (scope, idempotency_key)
        with self._lock:
            if key not in self._entries:
                raise RuntimeError("database ledger entry is missing")
            digest, _ = self._entries[key]
            self._entries[key] = (digest, outcome)
            self._active_scopes.discard(scope)

    def mark_restart_recovery(self) -> None:
        with self._lock:
            self._active_scopes = {
                scope
                for (scope, _idempotency_key), (_digest, outcome) in self._entries.items()
                if outcome is None
            }


class UnavailableDatabaseOperationLedger:
    """Default ledger; production operations fail closed without durability."""

    def claim(
        self, *, scope: str, idempotency_key: str, request_digest: str
    ) -> tuple[str, object | None]:
        del scope, idempotency_key, request_digest
        raise DatabaseOperationRejected("durable database operation ledger is unavailable")

    def complete(self, *, scope: str, idempotency_key: str, outcome: object) -> None:
        del scope, idempotency_key, outcome
        raise DatabaseOperationRejected("durable database operation ledger is unavailable")

    def mark_restart_recovery(self) -> None:
        raise DatabaseOperationRejected("durable database operation ledger is unavailable")


def _timestamp_or_none(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _credential_digest_payload(target: DatabaseTarget) -> dict[str, object]:
    credential = target.credential
    return {
        "reference": credential.reference,
        "tenant_id": credential.tenant_id,
        "application_id": credential.application_id,
        "version": credential.version,
        "status": credential.status.value,
        "issued_at": credential.issued_at.isoformat(),
        "expires_at": _timestamp_or_none(credential.expires_at),
        "revoked_at": _timestamp_or_none(credential.revoked_at),
    }


def _transport_digest_payload(target: DatabaseTarget) -> dict[str, object]:
    transport = target.transport
    return {
        "tenant_id": transport.tenant_id,
        "application_id": transport.application_id,
        "target_reference": transport.target_reference,
        "host": transport.host,
        "ssh_port": transport.ssh_port,
        "expected_host_key_fingerprint": transport.expected_host_key_fingerprint,
        "evidence_reference": transport.evidence_reference,
    }


def _target_digest_payload(target: DatabaseTarget) -> dict[str, object]:
    return {
        "tenant_id": target.tenant_id,
        "application_id": target.application_id,
        "stack_id": target.stack_id,
        "environment": target.environment,
        "engine_family": target.engine_family.value,
        "database_identifier": target.database_identifier,
        "logical_database_name": target.logical_database_name,
        "target_reference": target.target_reference,
        "approved_database_identifiers": list(target.approved_database_identifiers),
        "database_user": target.database_user,
        "database_host": target.database_host,
        "database_port": target.database_port,
        "tool_profile": target.tool_profile,
        "consistency": target.consistency.value,
        "limits": {
            "probe_timeout_seconds": target.limits.probe_timeout_seconds,
            "dump_timeout_seconds": target.limits.dump_timeout_seconds,
            "restore_timeout_seconds": target.limits.restore_timeout_seconds,
            "verify_timeout_seconds": target.limits.verify_timeout_seconds,
            "max_artifact_bytes": target.limits.max_artifact_bytes,
            "max_stderr_bytes": target.limits.max_stderr_bytes,
            "max_stdout_bytes": target.limits.max_stdout_bytes,
            "max_records": target.limits.max_records,
        },
        "transport": _transport_digest_payload(target),
        "credential": _credential_digest_payload(target),
    }


def _restore_target_digest_payload(target: DatabaseRestoreTarget) -> dict[str, object]:
    restore_database_target = DatabaseTarget(
        tenant_id=target.tenant_id,
        application_id=target.application_id,
        stack_id=target.stack_id,
        environment=target.environment,
        engine_family=target.engine_family,
        database_identifier=target.restore_database_name,
        logical_database_name=target.restore_database_name,
        transport=target.transport,
        credential=target.credential,
        target_reference=target.isolated_target_reference + ":database",
        approved_database_identifiers=target.approved_database_identifiers,
        database_user=target.database_user,
        database_host=target.database_host,
        database_port=target.database_port,
    )
    payload = _target_digest_payload(restore_database_target)
    payload.update(
        {
            "isolated_target_reference": target.isolated_target_reference,
            "restore_database_name": target.restore_database_name,
            "cleanup_owner_reference": target.cleanup_owner_reference,
            "verification_profile": target.verification_profile,
            "existing_authoritative_database": target.existing_authoritative_database,
        }
    )
    return payload


def _request_digest(request: DatabaseDumpRequest | DatabaseRestoreRequest) -> str:
    payload: dict[str, object] = {
        "operation": "dump" if isinstance(request, DatabaseDumpRequest) else "restore",
        "idempotency_key": request.idempotency_key,
    }
    if isinstance(request, DatabaseDumpRequest):
        payload.update(
            {
                "target": _target_digest_payload(request.target),
                "backup_id": request.backup_id,
                "job_id": request.job_id,
                "source_revision": request.source_revision,
                "application_artifact_digest": request.application_artifact_digest,
            }
        )
    else:
        payload.update(
            {
                "target": _restore_target_digest_payload(request.target),
                "backup_id": request.artifact.manifest.backup_id,
                "artifact_digest": request.artifact.artifact_digest,
                "manifest_digest": request.artifact.manifest_digest,
                "source_manifest": request.artifact.manifest.canonical_payload(),
                "staging_job_id": request.artifact.staging_job_id,
                "artifact_evidence_class": request.artifact.evidence_class.value,
            }
        )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _safe_cleanup_file(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except (FileNotFoundError, OSError):
        return
    if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        try:
            path.unlink()
        except OSError:
            return


def _manifest_from_payload(payload: Mapping[str, object]) -> DatabaseManifest:
    raw = dict(payload)
    created_at = raw.get("created_at")
    if not isinstance(created_at, str):
        raise DatabaseArtifactError("stored manifest timestamp is invalid")
    raw["created_at"] = datetime.fromisoformat(created_at)
    return DatabaseManifest(**cast(dict[str, Any], raw))


class LogicalDatabaseAdapter:
    """Shared typed dump/restore flow for MariaDB/MySQL and PostgreSQL."""

    engine_family: DatabaseKind
    dump_format: DatabaseDumpFormat
    output_filename: str

    def __init__(
        self,
        *,
        credential_provider: DatabaseCredentialProvider | None = None,
        broker: DatabaseExecutionBroker | None = None,
        filesystem: BackupFilesystemBoundary | None = None,
        ledger: DatabaseOperationLedgerProtocol | None = None,
        restore_target_registry: DatabaseRestoreTargetRegistry | None = None,
        evidence_class: EvidenceClass = EvidenceClass.FIXTURE,
    ) -> None:
        self.filesystem = filesystem or BackupFilesystemBoundary.canonical()
        if broker is None:
            provider = credential_provider or UnavailableDatabaseCredentialProvider()
            broker = SubprocessDatabaseBroker(provider, filesystem=self.filesystem)
        self.broker = broker
        self.ledger = ledger or UnavailableDatabaseOperationLedger()
        self.restore_target_registry = (
            restore_target_registry or UnavailableDatabaseRestoreTargetRegistry()
        )
        if not isinstance(evidence_class, EvidenceClass):
            raise DatabaseArtifactError("database evidence class is invalid")
        self.evidence_class = evidence_class

    def dump(
        self,
        request: DatabaseDumpRequest,
        *,
        now: datetime | None = None,
        cancel_event: object | None = None,
    ) -> DatabaseDumpResult:
        if request.target.engine_family != self.engine_family:
            raise DatabaseArtifactError("database adapter does not match target engine")
        observed_at = validate_aware_timestamp(now or datetime.now(UTC), field_name="now")
        scope = self._scope(request.target)
        fingerprint = _request_digest(request)
        claim, prior = self.ledger.claim(
            scope=scope,
            idempotency_key=request.idempotency_key,
            request_digest=fingerprint,
        )
        if claim == LedgerClaim.DUPLICATE:
            replayed = self._replay_dump_result(request, prior)
            if replayed is not None:
                return replayed
            return self._dump_failure(
                request,
                DatabaseOperationStatus.DUPLICATE,
                "duplicate_operation",
            )
        if claim == LedgerClaim.CONFLICT:
            return self._dump_failure(
                request, DatabaseOperationStatus.REJECTED, "idempotency_conflict"
            )
        if claim == LedgerClaim.ACTIVE:
            return self._dump_failure(
                request, DatabaseOperationStatus.BLOCKED, "concurrent_operation"
            )
        if claim == LedgerClaim.RECOVERY_REQUIRED:
            return self._dump_failure(
                request,
                DatabaseOperationStatus.RESTART_RECOVERY_REQUIRED,
                "restart_recovery_required",
            )

        job_path: Path | None = None
        output_path: Path | None = None
        try:
            self.filesystem.ensure_data_dirs()
            job_path = self.filesystem.staging_path(request.job_id)
            if job_path.exists() or job_path.is_symlink():
                raise DatabaseArtifactError("staging job already exists")
            job_path.mkdir(mode=0o700, parents=False, exist_ok=False)
            output_path = validate_database_artifact_path(
                job_path / self.output_filename,
                filesystem=self.filesystem,
                job_id=request.job_id,
                filename=self.output_filename,
            )
            broker_result = self.broker.run(
                request,
                target=request.target,
                output_path=output_path,
                cancel_event=cancel_event,
            )
            if not broker_result.passed:
                result = self._dump_failure(
                    request,
                    broker_result.status,
                    broker_result.reason_code,
                    broker=broker_result,
                )
                self.ledger.complete(
                    scope=scope, idempotency_key=request.idempotency_key, outcome=result
                )
                return result
            measured_size, measured_digest = _file_digest(
                output_path,
                limit=request.target.limits.max_artifact_bytes,
            )
            if (
                broker_result.artifact_path != output_path
                or broker_result.artifact_size_bytes != measured_size
                or broker_result.artifact_sha256 != measured_digest
            ):
                raise DatabaseArtifactError("broker artifact evidence does not match disk")
            if self.engine_family == DatabaseKind.MARIADB_MYSQL:
                # A dump that contains executable routine/event/trigger DDL or
                # unsafe context directives is not a restorable artifact for
                # this bounded adapter. Reject it before manifest creation so
                # a local dump cannot be mistaken for a verified recovery
                # point.
                inspect_mariadb_restore_artifact(
                    output_path,
                    expected_size=measured_size,
                )
            manifest = DatabaseManifest(
                backup_id=request.backup_id,
                tenant_id=request.target.tenant_id,
                application_id=request.target.application_id,
                stack_id=request.target.stack_id,
                target_reference=request.target.target_reference,
                transport_target_reference=request.target.transport.target_reference,
                engine_family=request.target.engine_family,
                database_identifier=request.target.database_identifier,
                logical_database_name=request.target.logical_database_name,
                dump_format=self.dump_format,
                tool_profile=request.target.tool_profile,
                artifact_size_bytes=measured_size,
                artifact_sha256=measured_digest,
                consistency=request.target.consistency,
                limitation_codes=self._limitations(request.target),
                created_at=observed_at,
                source_revision=request.source_revision,
                application_artifact_digest=request.application_artifact_digest,
                evidence_class=self.evidence_class,
            )
            artifact = DatabaseDumpArtifact(
                manifest=manifest,
                artifact_path=output_path,
                staging_job_id=request.job_id,
                filesystem=self.filesystem,
                evidence_class=self.evidence_class,
            )
            result = DatabaseDumpResult(
                request=request,
                status=DatabaseOperationStatus.PASSED,
                reason_code="ok",
                artifact=artifact,
                broker=broker_result,
                limitation_codes=manifest.limitation_codes,
                evidence_class=self.evidence_class,
            )
            self.ledger.complete(
                scope=scope, idempotency_key=request.idempotency_key, outcome=result
            )
            return result
        except DatabaseCredentialError:
            result = self._dump_failure(
                request, DatabaseOperationStatus.BLOCKED, "credential_unavailable"
            )
        except DatabaseRestoreError:
            result = self._dump_failure(
                request, DatabaseOperationStatus.FAILED, "dump_artifact_unsafe"
            )
        except (DatabaseArtifactError, OSError):
            result = self._dump_failure(
                request, DatabaseOperationStatus.FAILED, "dump_artifact_invalid"
            )
        except Exception:
            result = self._dump_failure(
                request, DatabaseOperationStatus.FAILED, "database_dump_failed"
            )
        if output_path is not None:
            _safe_cleanup_file(output_path)
        if job_path is not None:
            try:
                job_path.rmdir()
            except OSError:
                pass
        self.ledger.complete(scope=scope, idempotency_key=request.idempotency_key, outcome=result)
        return result

    def restore(
        self,
        request: DatabaseRestoreRequest,
        *,
        now: datetime | None = None,
        cancel_event: object | None = None,
    ) -> DatabaseRestoreEvidence:
        if request.target.engine_family != self.engine_family:
            raise DatabaseArtifactError("database adapter does not match restore engine")
        artifact = request.artifact
        if artifact.evidence_class != self.evidence_class:
            raise DatabaseArtifactError("restore artifact evidence class does not match adapter")
        if artifact.filesystem is None or artifact.filesystem != self.filesystem:
            raise DatabaseArtifactError("restore artifact crosses adapter filesystem boundary")
        scope = self._restore_scope(request.target)
        fingerprint = _request_digest(request)
        claim, prior = self.ledger.claim(
            scope=scope,
            idempotency_key=request.idempotency_key,
            request_digest=fingerprint,
        )
        if claim == LedgerClaim.DUPLICATE:
            replayed = self._replay_restore_evidence(request, prior)
            if replayed is not None:
                return replayed
            return self._restore_failure(
                request,
                "duplicate_operation",
                status=DatabaseOperationStatus.DUPLICATE,
            )
        if claim == LedgerClaim.CONFLICT:
            return self._restore_failure(request, "idempotency_conflict")
        if claim == LedgerClaim.ACTIVE:
            return self._restore_failure(request, "concurrent_restore")
        if claim == LedgerClaim.RECOVERY_REQUIRED:
            return self._restore_failure(
                request,
                "restart_recovery_required",
                status=DatabaseOperationStatus.RESTART_RECOVERY_REQUIRED,
            )
        registered_target: DatabaseRestoreTarget | None = None
        expected_objects: tuple[str, ...] = ()
        restore_attempted = False
        try:
            registered_target = self.restore_target_registry.resolve(
                request.target,
                source_manifest=artifact.manifest,
            )
            measured_size, measured_digest = _file_digest(
                artifact.artifact_path,
                limit=artifact.manifest.artifact_size_bytes,
            )
            if (
                measured_size != artifact.manifest.artifact_size_bytes
                or measured_digest != artifact.artifact_digest
            ):
                raise DatabaseArtifactError("restore artifact checksum mismatch")
            if artifact.manifest.engine_family != request.target.engine_family:
                raise DatabaseArtifactError("restore artifact engine mismatch")
            if request.target.engine_family == DatabaseKind.MARIADB_MYSQL:
                expected_objects = inspect_mariadb_restore_artifact(
                    artifact.artifact_path,
                    expected_size=artifact.manifest.artifact_size_bytes,
                )
            precheck_request = DatabaseVerifyRequest(
                artifact=artifact,
                target=request.target,
                idempotency_key=request.idempotency_key + ":precheck",
                operation_id=request.operation_id + ":precheck",
                require_empty=True,
            )
            precheck_result = self.broker.run(
                precheck_request,
                target=self._target_for_restore(registered_target, artifact),
                cancel_event=cancel_event,
            )
            if not precheck_result.passed:
                result = self._restore_failure(
                    request,
                    precheck_result.reason_code,
                    status=precheck_result.status,
                )
                self.ledger.complete(
                    scope=scope, idempotency_key=request.idempotency_key, outcome=result
                )
                return result
            if (
                precheck_result.observed_database_name != request.target.restore_database_name
                or precheck_result.restored_object_count != 0
            ):
                cleanup_status, cleanup_reference = self._quarantine_status(
                    registered_target,
                    artifact,
                    reason_code="restore_target_not_empty",
                )
                result = self._restore_failure(
                    request,
                    "restore_target_not_empty",
                    status=DatabaseOperationStatus.FAILED,
                    cleanup_status=cleanup_status,
                    cleanup_reference=cleanup_reference,
                )
                self.ledger.complete(
                    scope=scope, idempotency_key=request.idempotency_key, outcome=result
                )
                return result
            restore_result = self.broker.run(
                request,
                target=self._target_for_restore(registered_target, artifact),
                cancel_event=cancel_event,
            )
            restore_attempted = True
            if not restore_result.passed:
                cleanup_status, cleanup_reference = self._cleanup_status(
                    registered_target,
                    artifact,
                    restore_attempted=restore_attempted,
                )
                result = self._restore_failure(
                    request,
                    restore_result.reason_code,
                    status=restore_result.status,
                    cleanup_status=cleanup_status,
                    cleanup_reference=cleanup_reference,
                )
                self.ledger.complete(
                    scope=scope, idempotency_key=request.idempotency_key, outcome=result
                )
                return result
            verify_request = DatabaseVerifyRequest(
                artifact=artifact,
                target=request.target,
                idempotency_key=request.idempotency_key + ":verify",
                operation_id=request.operation_id + ":verify",
                expected_object_names=expected_objects,
            )
            verify_result = self.broker.run(
                verify_request,
                target=self._target_for_restore(registered_target, artifact),
                cancel_event=cancel_event,
            )
            verification = self._verification_result(
                request,
                verify_result,
                expected_objects=expected_objects,
            )
            status = DatabaseOperationStatus.PASSED if verification.passed else verification.status
            if not verification.passed:
                cleanup_status, cleanup_reference = self._cleanup_status(
                    registered_target,
                    artifact,
                    restore_attempted=restore_attempted,
                )
                result = self._restore_failure(
                    request,
                    verification.reason_code,
                    status=verification.status,
                    verification=verification,
                    cleanup_status=cleanup_status,
                    cleanup_reference=cleanup_reference,
                )
                self.ledger.complete(
                    scope=scope, idempotency_key=request.idempotency_key, outcome=result
                )
                return result
            result = DatabaseRestoreEvidence(
                request=request,
                status=status,
                reason_code="ok" if verification.passed else verify_result.reason_code,
                artifact_digest=artifact.artifact_digest,
                manifest_digest=artifact.manifest_digest,
                restored_digest=artifact.artifact_digest if verification.passed else None,
                verification=verification,
                evidence_class=self.evidence_class,
            )
        except (DatabaseCredentialError, DatabaseRestoreError) as exc:
            reason = (
                "credential_unavailable"
                if isinstance(exc, DatabaseCredentialError)
                else "restore_target_unavailable"
            )
            cleanup_status, cleanup_reference = self._cleanup_status(
                registered_target,
                artifact,
                restore_attempted=restore_attempted,
            )
            result = self._restore_failure(
                request,
                reason,
                cleanup_status=cleanup_status,
                cleanup_reference=cleanup_reference,
            )
        except (DatabaseArtifactError, OSError):
            cleanup_status, cleanup_reference = self._cleanup_status(
                registered_target,
                artifact,
                restore_attempted=restore_attempted,
            )
            result = self._restore_failure(
                request,
                "restore_artifact_invalid",
                cleanup_status=cleanup_status,
                cleanup_reference=cleanup_reference,
            )
        except Exception:
            cleanup_status, cleanup_reference = self._cleanup_status(
                registered_target,
                artifact,
                restore_attempted=restore_attempted,
            )
            result = self._restore_failure(
                request,
                "database_restore_failed",
                cleanup_status=cleanup_status,
                cleanup_reference=cleanup_reference,
            )
        self.ledger.complete(scope=scope, idempotency_key=request.idempotency_key, outcome=result)
        return result

    @staticmethod
    def _target_for_restore(
        target: DatabaseRestoreTarget, artifact: DatabaseDumpArtifact
    ) -> DatabaseTarget:
        return DatabaseTarget(
            tenant_id=target.tenant_id,
            application_id=target.application_id,
            stack_id=target.stack_id,
            environment=target.environment,
            engine_family=target.engine_family,
            database_identifier=artifact.manifest.database_identifier,
            logical_database_name=target.restore_database_name,
            transport=target.transport,
            credential=target.credential,
            target_reference=target.isolated_target_reference + ":database",
            approved_database_identifiers=tuple(
                sorted(
                    {
                        artifact.manifest.database_identifier,
                        target.restore_database_name,
                    }
                )
            ),
            database_user=target.database_user,
            database_host=target.database_host,
            database_port=target.database_port,
        )

    def _dump_failure(
        self,
        request: DatabaseDumpRequest,
        status: DatabaseOperationStatus,
        reason: str,
        *,
        broker: DatabaseBrokerResult | None = None,
    ) -> DatabaseDumpResult:
        return DatabaseDumpResult(
            request=request,
            status=status,
            reason_code=reason,
            broker=broker,
            evidence_class=self.evidence_class,
        )

    def _restore_failure(
        self,
        request: DatabaseRestoreRequest,
        reason: str,
        *,
        status: DatabaseOperationStatus = DatabaseOperationStatus.FAILED,
        verification: DatabaseVerificationResult | None = None,
        cleanup_status: DatabaseCleanupStatus = DatabaseCleanupStatus.NONE,
        cleanup_reference: str | None = None,
    ) -> DatabaseRestoreEvidence:
        artifact = request.artifact
        return DatabaseRestoreEvidence(
            request=request,
            status=status,
            reason_code=reason,
            artifact_digest=artifact.artifact_digest,
            manifest_digest=artifact.manifest_digest,
            restored_digest=None,
            verification=verification,
            cleanup_status=cleanup_status,
            cleanup_reference=cleanup_reference,
            evidence_class=self.evidence_class,
        )

    def _replay_dump_result(
        self,
        request: DatabaseDumpRequest,
        prior: object | None,
    ) -> DatabaseDumpResult | None:
        if isinstance(prior, DatabaseDumpResult):
            if prior.request != request or prior.evidence_class != self.evidence_class:
                return None
            if prior.artifact is not None and not self._artifact_matches_request(
                prior.artifact, request
            ):
                return None
            return prior
        if not isinstance(prior, Mapping):
            return None
        try:
            if prior.get("kind") != "database_dump_result":
                return None
            status = DatabaseOperationStatus(str(prior["status"]))
            reason_code = str(prior["reason_code"])
            evidence_class = EvidenceClass(str(prior["evidence_class"]))
            limitation_codes = tuple(str(item) for item in prior.get("limitation_codes", ()))
            artifact = None
            artifact_payload = prior.get("artifact")
            if isinstance(artifact_payload, Mapping):
                manifest_payload = artifact_payload.get("manifest")
                staging_job_id = artifact_payload.get("staging_job_id")
                if isinstance(manifest_payload, Mapping) and isinstance(staging_job_id, str):
                    artifact = DatabaseDumpArtifact(
                        manifest=_manifest_from_payload(manifest_payload),
                        artifact_path=self.filesystem.staging_path(staging_job_id)
                        / self.output_filename,
                        staging_job_id=staging_job_id,
                        filesystem=self.filesystem,
                        evidence_class=evidence_class,
                    )
            if artifact is not None and not self._artifact_matches_request(artifact, request):
                return None
            if evidence_class != self.evidence_class:
                return None
            if status == DatabaseOperationStatus.PASSED and artifact is None:
                return None
            return DatabaseDumpResult(
                request=request,
                status=status,
                reason_code=reason_code,
                artifact=artifact,
                limitation_codes=limitation_codes,
                evidence_class=evidence_class,
            )
        except (DatabaseBoundaryError, KeyError, TypeError, ValueError):
            return None

    def _replay_restore_evidence(
        self,
        request: DatabaseRestoreRequest,
        prior: object | None,
    ) -> DatabaseRestoreEvidence | None:
        if isinstance(prior, DatabaseRestoreEvidence):
            if prior.request != request or not self._restore_evidence_matches(prior, request):
                return None
            return prior
        if not isinstance(prior, Mapping):
            return None
        try:
            if prior.get("kind") != "database_restore_evidence":
                return None
            verification_payload = prior.get("verification")
            verification = None
            if isinstance(verification_payload, Mapping):
                verification = DatabaseVerificationResult(**dict(verification_payload))
            evidence_class = EvidenceClass(str(prior["evidence_class"]))
            replayed = DatabaseRestoreEvidence(
                request=request,
                status=DatabaseOperationStatus(str(prior["status"])),
                reason_code=str(prior["reason_code"]),
                artifact_digest=str(prior["artifact_digest"]),
                manifest_digest=str(prior["manifest_digest"]),
                restored_digest=(
                    None if prior.get("restored_digest") is None else str(prior["restored_digest"])
                ),
                verification=verification,
                cleanup_status=DatabaseCleanupStatus(str(prior["cleanup_status"])),
                cleanup_reference=(
                    None
                    if prior.get("cleanup_reference") is None
                    else str(prior["cleanup_reference"])
                ),
                evidence_class=evidence_class,
            )
            return replayed if self._restore_evidence_matches(replayed, request) else None
        except (DatabaseBoundaryError, KeyError, TypeError, ValueError):
            return None

    def _artifact_matches_request(
        self, artifact: DatabaseDumpArtifact, request: DatabaseDumpRequest
    ) -> bool:
        manifest = artifact.manifest
        if (
            artifact.evidence_class != self.evidence_class
            or manifest.backup_id != request.backup_id
            or manifest.tenant_id != request.target.tenant_id
            or manifest.application_id != request.target.application_id
            or manifest.stack_id != request.target.stack_id
            or manifest.target_reference != request.target.target_reference
            or manifest.transport_target_reference != request.target.transport.target_reference
            or manifest.engine_family != request.target.engine_family
            or manifest.database_identifier != request.target.database_identifier
            or manifest.logical_database_name != request.target.logical_database_name
            or manifest.source_revision != request.source_revision
            or manifest.application_artifact_digest != request.application_artifact_digest
        ):
            return False
        try:
            size, digest = _file_digest(
                artifact.artifact_path,
                limit=manifest.artifact_size_bytes,
            )
        except (DatabaseArtifactError, OSError):
            return False
        return size == manifest.artifact_size_bytes and digest == manifest.artifact_sha256

    def _restore_evidence_matches(
        self, evidence: DatabaseRestoreEvidence, request: DatabaseRestoreRequest
    ) -> bool:
        verification = evidence.verification
        return (
            evidence.evidence_class == self.evidence_class
            and evidence.artifact_digest == request.artifact.artifact_digest
            and evidence.manifest_digest == request.artifact.manifest_digest
            and (
                verification is None
                or (
                    verification.target_reference == request.target.isolated_target_reference
                    and verification.backup_id == request.artifact.manifest.backup_id
                    and verification.artifact_digest == request.artifact.artifact_digest
                    and verification.manifest_digest == request.artifact.manifest_digest
                )
            )
        )

    def _verification_result(
        self,
        request: DatabaseRestoreRequest,
        broker_result: DatabaseBrokerResult,
        *,
        expected_objects: tuple[str, ...],
    ) -> DatabaseVerificationResult:
        observed_database_name = broker_result.observed_database_name
        restored_object_count = broker_result.restored_object_count or 0
        status = broker_result.status
        reason_code = broker_result.reason_code
        if broker_result.passed:
            if observed_database_name != request.target.restore_database_name:
                status = DatabaseOperationStatus.FAILED
                reason_code = "restore_identity_mismatch"
            elif expected_objects:
                if restored_object_count != len(expected_objects):
                    status = DatabaseOperationStatus.FAILED
                    reason_code = "restore_objects_missing"
            elif restored_object_count < 1:
                status = DatabaseOperationStatus.FAILED
                reason_code = "restore_objects_missing"
        return DatabaseVerificationResult(
            operation_id=broker_result.operation_id,
            status=status,
            reason_code=reason_code,
            target_reference=request.target.isolated_target_reference,
            backup_id=request.artifact.manifest.backup_id,
            artifact_digest=request.artifact.artifact_digest,
            manifest_digest=request.artifact.manifest_digest,
            observed_database_name=observed_database_name,
            restored_object_count=restored_object_count,
            broker=broker_result,
        )

    def _cleanup_status(
        self,
        target: DatabaseRestoreTarget | None,
        artifact: DatabaseDumpArtifact,
        *,
        restore_attempted: bool,
    ) -> tuple[DatabaseCleanupStatus, str | None]:
        if not restore_attempted or target is None:
            return DatabaseCleanupStatus.NONE, None
        cleanup_reference = target.cleanup_owner_reference
        cleanup_callable = getattr(self.broker, "cleanup_restore_target", None)
        if not callable(cleanup_callable):
            return self._quarantine_status(target, artifact, reason_code="cleanup_unavailable")
        try:
            cleanup_result = cleanup_callable(target=target)
        except Exception:
            return self._quarantine_status(target, artifact, reason_code="cleanup_failed")
        if cleanup_result is True:
            return DatabaseCleanupStatus.CLEANED, cleanup_reference
        if isinstance(cleanup_result, str):
            try:
                cleanup_reference = validate_evidence_reference(cleanup_result)
            except DatabaseBoundaryError:
                return self._quarantine_status(target, artifact, reason_code="cleanup_failed")
            return DatabaseCleanupStatus.CLEANED, cleanup_reference
        return self._quarantine_status(target, artifact, reason_code="cleanup_failed")

    def _quarantine_status(
        self,
        target: DatabaseRestoreTarget | None,
        artifact: DatabaseDumpArtifact,
        *,
        reason_code: str,
    ) -> tuple[DatabaseCleanupStatus, str | None]:
        if target is None:
            return DatabaseCleanupStatus.REQUIRED, None
        cleanup_reference = target.cleanup_owner_reference
        quarantine_callable = getattr(self.restore_target_registry, "quarantine", None)
        if not callable(quarantine_callable):
            return DatabaseCleanupStatus.REQUIRED, cleanup_reference
        try:
            quarantine_reference = quarantine_callable(
                target,
                source_manifest=artifact.manifest,
                cleanup_reference=cleanup_reference,
                reason_code=reason_code,
            )
            return DatabaseCleanupStatus.QUARANTINED, validate_evidence_reference(
                quarantine_reference
            )
        except Exception:
            return DatabaseCleanupStatus.REQUIRED, cleanup_reference

    @staticmethod
    def _scope(target: DatabaseTarget) -> str:
        return ":".join(
            (
                target.tenant_id,
                target.application_id,
                target.database_identifier,
                target.environment,
            )
        )

    @staticmethod
    def _restore_scope(target: DatabaseRestoreTarget) -> str:
        return ":".join((target.tenant_id, target.application_id, target.isolated_target_reference))

    def _limitations(self, target: DatabaseTarget) -> tuple[str, ...]:
        if target.engine_family == DatabaseKind.MARIADB_MYSQL:
            return (
                "non_transactional_tables_unverified",
                "mixed_engine_consistency_unverified",
            )
        return (
            "roles_outside_scope",
            "tablespaces_outside_scope",
            "cluster_global_state_outside_scope",
        )


__all__ = [
    "DatabaseOperationLedger",
    "InMemoryDatabaseRestoreTargetRegistry",
    "LedgerClaim",
    "LogicalDatabaseAdapter",
    "UnavailableDatabaseOperationLedger",
    "UnavailableDatabaseRestoreTargetRegistry",
]
