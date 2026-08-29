"""SQLAlchemy-backed idempotency custody for Spec 015 database operations.

The in-memory ledger remains useful for deterministic unit tests, but it is
never the default for an AppCare adapter.  Production callers must inject this
ledger (or an equivalent durable implementation) backed by the AppCare
control-plane database.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..db import Database
from ..models import DatabaseOperationRecord, DatabaseRestoreTargetRecord, new_id
from ..readiness.contracts import validate_evidence_reference, validate_scope_segment
from .adapters import LedgerClaim, _restore_target_digest_payload
from .contracts import (
    DatabaseCleanupStatus,
    DatabaseDumpResult,
    DatabaseManifest,
    DatabaseOperationLedgerProtocol,
    DatabaseOperationRejected,
    DatabaseOperationStatus,
    DatabaseRestoreError,
    DatabaseRestoreEvidence,
    DatabaseRestoreTarget,
    DatabaseRestoreTargetRegistry,
    DatabaseVerificationResult,
    EvidenceClass,
    validate_database_name,
    validate_digest_hex,
    validate_idempotency_key,
)


def _restore_target_digest(target: DatabaseRestoreTarget) -> str:
    payload = _restore_target_digest_payload(target)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class SqlAlchemyDatabaseRestoreTargetRegistry(DatabaseRestoreTargetRegistry):
    """Durable registration and quarantine boundary for isolated restores."""

    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _identity(target: DatabaseRestoreTarget) -> dict[str, str]:
        return {
            "tenant_id": target.tenant_id,
            "application_id": target.application_id,
            "stack_id": target.stack_id,
            "isolated_target_reference": target.isolated_target_reference,
        }

    @staticmethod
    def _source_values(manifest: DatabaseManifest) -> dict[str, str]:
        return {
            "source_target_reference": manifest.target_reference,
            "source_database_identifier": manifest.database_identifier,
            "source_logical_database_name": manifest.logical_database_name,
        }

    @classmethod
    def _matches(
        cls,
        record: DatabaseRestoreTargetRecord,
        target: DatabaseRestoreTarget,
        source_manifest: DatabaseManifest,
    ) -> bool:
        source_values = cls._source_values(source_manifest)
        return (
            record.target_digest == _restore_target_digest(target)
            and record.source_target_reference == source_values["source_target_reference"]
            and record.source_database_identifier == source_values["source_database_identifier"]
            and record.source_logical_database_name == source_values["source_logical_database_name"]
        )

    def register(
        self,
        target: DatabaseRestoreTarget,
        *,
        source_target_reference: str,
        source_database_identifier: str,
        source_logical_database_name: str,
    ) -> None:
        # DatabaseRestoreTarget validates the target itself. These source
        # fields are validated again at the persistence boundary so an
        # untrusted manifest can never be stored as registration metadata.
        source_target_reference = validate_evidence_reference(source_target_reference)
        source_database_identifier = validate_database_name(
            source_database_identifier,
            field_name="source_database_identifier",
        )
        source_logical_database_name = validate_database_name(
            source_logical_database_name,
            field_name="source_logical_database_name",
        )
        if target.restore_database_name in {
            source_database_identifier,
            source_logical_database_name,
        }:
            raise DatabaseRestoreError("restore target must differ from source database")
        values = {
            **self._identity(target),
            "source_target_reference": source_target_reference,
            "source_database_identifier": source_database_identifier,
            "source_logical_database_name": source_logical_database_name,
            "target_digest": _restore_target_digest(target),
        }
        with self.database.session() as session:
            if (
                session.scalar(
                    select(DatabaseRestoreTargetRecord).where(
                        DatabaseRestoreTargetRecord.tenant_id == values["tenant_id"],
                        DatabaseRestoreTargetRecord.application_id == values["application_id"],
                        DatabaseRestoreTargetRecord.stack_id == values["stack_id"],
                        DatabaseRestoreTargetRecord.isolated_target_reference
                        == values["isolated_target_reference"],
                    )
                )
                is not None
            ):
                raise DatabaseRestoreError("isolated restore target is already registered")
            session.add(
                DatabaseRestoreTargetRecord(
                    id=new_id(),
                    **values,
                    status="active",
                )
            )
            try:
                session.flush()
            except IntegrityError as exc:
                raise DatabaseRestoreError(
                    "isolated restore target registration conflicted"
                ) from exc

    def resolve(
        self,
        requested: DatabaseRestoreTarget,
        *,
        source_manifest: DatabaseManifest,
    ) -> DatabaseRestoreTarget:
        identity = self._identity(requested)
        with self.database.session() as session:
            record = session.scalar(
                select(DatabaseRestoreTargetRecord).where(
                    DatabaseRestoreTargetRecord.tenant_id == identity["tenant_id"],
                    DatabaseRestoreTargetRecord.application_id == identity["application_id"],
                    DatabaseRestoreTargetRecord.stack_id == identity["stack_id"],
                    DatabaseRestoreTargetRecord.isolated_target_reference
                    == identity["isolated_target_reference"],
                )
            )
            if record is None:
                raise DatabaseRestoreError("isolated restore target is not registered")
            if record.status != "active":
                raise DatabaseRestoreError("isolated restore target is quarantined")
            if not self._matches(record, requested, source_manifest):
                raise DatabaseRestoreError("isolated restore target binding mismatch")
        return requested

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
        identity = self._identity(requested)
        with self.database.session() as session:
            record = session.scalar(
                select(DatabaseRestoreTargetRecord).where(
                    DatabaseRestoreTargetRecord.tenant_id == identity["tenant_id"],
                    DatabaseRestoreTargetRecord.application_id == identity["application_id"],
                    DatabaseRestoreTargetRecord.stack_id == identity["stack_id"],
                    DatabaseRestoreTargetRecord.isolated_target_reference
                    == identity["isolated_target_reference"],
                )
            )
            if record is None or record.status != "active":
                raise DatabaseRestoreError("isolated restore target is not active")
            if not self._matches(record, requested, source_manifest):
                raise DatabaseRestoreError("isolated restore target binding mismatch")
            record.status = "quarantined"
            record.quarantine_reason = reason_code
            record.cleanup_reference = cleanup_reference
        return cleanup_reference


class SqlAlchemyDatabaseOperationLedger(DatabaseOperationLedgerProtocol):
    """Persist claims and terminal outcomes in the AppCare database."""

    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _scope_identity(scope: str) -> tuple[str, str]:
        if not isinstance(scope, str) or not 1 <= len(scope) <= 500:
            raise DatabaseOperationRejected("database operation scope is invalid")
        parts = scope.split(":", 2)
        if len(parts) < 2:
            raise DatabaseOperationRejected("database operation scope is invalid")
        return (
            validate_scope_segment(parts[0], field_name="tenant_id"),
            validate_scope_segment(parts[1], field_name="application_id"),
        )

    def claim(
        self, *, scope: str, idempotency_key: str, request_digest: str
    ) -> tuple[str, object | None]:
        tenant_id, application_id = self._scope_identity(scope)
        idempotency_key = validate_idempotency_key(idempotency_key)
        request_digest = validate_digest_hex(request_digest, field_name="request_digest")

        with self.database.session() as session:
            existing = session.scalar(
                select(DatabaseOperationRecord).where(
                    DatabaseOperationRecord.scope == scope,
                    DatabaseOperationRecord.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                return self._decision_for_existing(existing, request_digest)
            active = session.scalar(
                select(DatabaseOperationRecord).where(
                    DatabaseOperationRecord.scope == scope,
                    DatabaseOperationRecord.status.in_(("pending", "running", "recovery_required")),
                )
            )
            if active is not None:
                return LedgerClaim.ACTIVE, None
            session.add(
                DatabaseOperationRecord(
                    id=new_id(),
                    tenant_id=tenant_id,
                    application_id=application_id,
                    scope=scope,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    operation_kind="database",
                    status="running",
                )
            )
            try:
                session.flush()
            except IntegrityError as exc:
                # The committed database row is authoritative for deterministic
                # replay and single-flight enforcement. If the race produced
                # either an exact idempotency record or another active scope
                # record, derive that outcome; otherwise fail closed.
                session.rollback()
                raced = session.scalar(
                    select(DatabaseOperationRecord).where(
                        DatabaseOperationRecord.scope == scope,
                        DatabaseOperationRecord.idempotency_key == idempotency_key,
                    )
                )
                if raced is not None:
                    return self._decision_for_existing(raced, request_digest)
                active = session.scalar(
                    select(DatabaseOperationRecord).where(
                        DatabaseOperationRecord.scope == scope,
                        DatabaseOperationRecord.status.in_(
                            ("pending", "running", "recovery_required")
                        ),
                    )
                )
                if active is not None:
                    return LedgerClaim.ACTIVE, None
                raise exc
        return LedgerClaim.NEW, None

    @staticmethod
    def _decision_for_existing(
        existing: DatabaseOperationRecord, request_digest: str
    ) -> tuple[str, object | None]:
        if existing.request_digest != request_digest:
            return LedgerClaim.CONFLICT, None
        if existing.status in {"succeeded", "failed"}:
            return LedgerClaim.DUPLICATE, existing.outcome_json
        return LedgerClaim.RECOVERY_REQUIRED, None

    @staticmethod
    def _serialize_verification(
        verification: DatabaseVerificationResult,
    ) -> dict[str, object]:
        return {
            "operation_id": verification.operation_id,
            "status": verification.status.value,
            "reason_code": verification.reason_code,
            "target_reference": verification.target_reference,
            "backup_id": verification.backup_id,
            "artifact_digest": verification.artifact_digest,
            "manifest_digest": verification.manifest_digest,
            "observed_database_name": verification.observed_database_name,
            "restored_object_count": verification.restored_object_count,
        }

    @classmethod
    def _serialize_outcome(cls, outcome: object) -> dict[str, object]:
        if isinstance(outcome, DatabaseDumpResult):
            artifact_payload: dict[str, object] | None = None
            if outcome.artifact is not None:
                artifact_payload = {
                    "staging_job_id": outcome.artifact.staging_job_id,
                    "manifest": outcome.artifact.manifest.canonical_payload(),
                }
            return {
                "kind": "database_dump_result",
                "status": outcome.status.value,
                "reason_code": outcome.reason_code,
                "evidence_class": outcome.evidence_class.value,
                "limitation_codes": list(outcome.limitation_codes),
                "artifact": artifact_payload,
            }
        if isinstance(outcome, DatabaseRestoreEvidence):
            return {
                "kind": "database_restore_evidence",
                "status": outcome.status.value,
                "reason_code": outcome.reason_code,
                "artifact_digest": outcome.artifact_digest,
                "manifest_digest": outcome.manifest_digest,
                "restored_digest": outcome.restored_digest,
                "cleanup_status": outcome.cleanup_status.value,
                "cleanup_reference": outcome.cleanup_reference,
                "evidence_class": outcome.evidence_class.value,
                "verification": (
                    None
                    if outcome.verification is None
                    else cls._serialize_verification(outcome.verification)
                ),
            }
        if hasattr(outcome, "passed"):
            passed = bool(getattr(outcome, "passed", False))
            reason = getattr(outcome, "reason_code", None)
            if not isinstance(reason, str) or not reason:
                reason = "ok" if passed else "database_operation_failed"
            return {
                "kind": "database_terminal_result",
                "status": (
                    DatabaseOperationStatus.PASSED.value
                    if passed
                    else DatabaseOperationStatus.FAILED.value
                ),
                "reason_code": reason,
                "evidence_class": EvidenceClass.FIXTURE.value,
                "cleanup_status": DatabaseCleanupStatus.NONE.value,
            }
        raise DatabaseOperationRejected("database outcome is not sanitizable")

    def complete(self, *, scope: str, idempotency_key: str, outcome: object) -> None:
        idempotency_key = validate_idempotency_key(idempotency_key)
        outcome_json = self._serialize_outcome(outcome)
        passed = bool(getattr(outcome, "passed", False))
        reason = getattr(outcome, "reason_code", None)
        if not isinstance(reason, str) or not reason:
            reason = "ok" if passed else "database_operation_failed"
        reason = validate_scope_segment(reason, field_name="outcome_reason")
        reference = getattr(outcome, "artifact_digest", None)
        if not isinstance(reference, str) or len(reference) != 64:
            reference = None
        with self.database.session() as session:
            record = session.scalar(
                select(DatabaseOperationRecord).where(
                    DatabaseOperationRecord.scope == scope,
                    DatabaseOperationRecord.idempotency_key == idempotency_key,
                )
            )
            if record is None:
                raise DatabaseOperationRejected("database operation record is missing")
            record.status = "succeeded" if passed else "failed"
            record.outcome_json = outcome_json
            record.result_reference = reference
            record.failure_code = None if passed else reason

    def mark_restart_recovery(self) -> None:
        with self.database.session() as session:
            records = session.scalars(
                select(DatabaseOperationRecord).where(
                    DatabaseOperationRecord.status.in_(("pending", "running")),
                )
            )
            for record in records:
                record.status = "recovery_required"


__all__ = ["SqlAlchemyDatabaseOperationLedger"]
