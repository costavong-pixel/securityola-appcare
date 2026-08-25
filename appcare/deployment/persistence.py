"""SQLAlchemy-backed BETA-07 intent, control, and evidence persistence."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    DeploymentControlRecord,
    DeploymentEvidenceRecord,
    DeploymentIntentRecord,
    DeploymentRevokedCredential,
)
from .contracts import (
    DeploymentApproval,
    DeploymentEvidence,
    DeploymentIntent,
    DuplicateDeploymentError,
    ProductionControlError,
    validate_opaque_reference,
)
from .state_machine import DeploymentRecord, DeploymentRecordStore

SessionFactory = Callable[[], Session]


def _intent_payload(intent: DeploymentIntent) -> dict[str, object]:
    return {
        "intent_id": intent.intent_id,
        "tenant_id": intent.tenant_id,
        "application_id": intent.application_id,
        "artifact_digest": intent.artifact_digest,
        "source_revision": intent.source_revision,
        "rollback_reference": intent.rollback_reference,
        "rollback_artifact_digest": intent.rollback_artifact_digest,
        "idempotency_key": intent.idempotency_key,
        "requested_by": intent.requested_by,
        "backup_evidence_ref": intent.backup_evidence_ref,
        "credential_ref": intent.credential_ref,
        "beta06_verified_live_preview": intent.beta06_verified_live_preview,
        "target_environment": intent.target_environment,
    }


def _approval_payload(approval: DeploymentApproval | None) -> dict[str, object] | None:
    if approval is None:
        return None
    return {
        "intent_id": approval.intent_id,
        "approval_id": approval.approval_id,
        "actor_ref": approval.actor_ref,
        "decision": approval.decision,
        "decision_ref": approval.decision_ref,
        "intent_digest": approval.intent_digest,
    }


def _record_payload(record: DeploymentRecord) -> dict[str, object]:
    return {
        "intent": _intent_payload(record.intent),
        "approval": _approval_payload(record.approval),
        "backup_verified": record.backup_verified,
        "status": record.status,
        "failure_code": record.failure_code,
        "deployment_ref": record.deployment_ref,
        "verification_passed": record.verification_passed,
        "rollback_ref": record.rollback_ref,
        "provider_target_environment": record.provider_target_environment,
        "provider_source_revision": record.provider_source_revision,
        "provider_artifact_digest": record.provider_artifact_digest,
        "verification_ref": record.verification_ref,
        "rollback_succeeded": record.rollback_succeeded,
        "rollback_failure_code": record.rollback_failure_code,
    }


def _evidence_payload(evidence: DeploymentEvidence) -> dict[str, str]:
    return {
        "event": evidence.event,
        "from_status": evidence.from_status,
        "to_status": evidence.to_status,
        "reason_code": evidence.reason_code,
        "digest": evidence.digest,
    }


def _text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ProductionControlError(f"persisted deployment field {key} is malformed")
    return value


def _record_from_row(
    row: DeploymentIntentRecord,
    evidence_rows: list[DeploymentEvidenceRecord],
) -> DeploymentRecord:
    raw_record = row.record_json
    raw_intent = raw_record.get("intent")
    if not isinstance(raw_intent, dict):
        raise ProductionControlError("persisted deployment intent is malformed")
    intent = DeploymentIntent(
        intent_id=_text(raw_intent, "intent_id"),
        tenant_id=_text(raw_intent, "tenant_id"),
        application_id=_text(raw_intent, "application_id"),
        artifact_digest=_text(raw_intent, "artifact_digest"),
        source_revision=_text(raw_intent, "source_revision"),
        rollback_reference=_text(raw_intent, "rollback_reference"),
        rollback_artifact_digest=_text(raw_intent, "rollback_artifact_digest"),
        idempotency_key=_text(raw_intent, "idempotency_key"),
        requested_by=_text(raw_intent, "requested_by"),
        backup_evidence_ref=_text(raw_intent, "backup_evidence_ref"),
        credential_ref=_text(raw_intent, "credential_ref"),
        beta06_verified_live_preview=cast(Any, _text(raw_intent, "beta06_verified_live_preview")),
        target_environment=cast(Any, _text(raw_intent, "target_environment")),
    )
    if intent.intent_digest != row.intent_digest:
        raise ProductionControlError("persisted deployment intent digest mismatch")
    if intent.tenant_id != row.tenant_id or intent.application_id != row.application_id:
        raise ProductionControlError("persisted deployment tenant or application mismatch")
    raw_approval = raw_record.get("approval")
    approval: DeploymentApproval | None = None
    if raw_approval is not None:
        if not isinstance(raw_approval, dict):
            raise ProductionControlError("persisted deployment approval is malformed")
        approval = DeploymentApproval(
            intent_id=_text(raw_approval, "intent_id"),
            approval_id=_text(raw_approval, "approval_id"),
            actor_ref=_text(raw_approval, "actor_ref"),
            decision=cast(Any, _text(raw_approval, "decision")),
            decision_ref=_text(raw_approval, "decision_ref"),
            intent_digest=_text(raw_approval, "intent_digest"),
        )
    evidence: list[DeploymentEvidence] = []
    for expected_sequence, evidence_row in enumerate(evidence_rows, start=1):
        if evidence_row.sequence != expected_sequence:
            raise ProductionControlError("deployment evidence sequence is not contiguous")
        if evidence_row.tenant_id != row.tenant_id or evidence_row.intent_id != row.intent_id:
            raise ProductionControlError("persisted deployment evidence scope mismatch")
        item = DeploymentEvidence(
            event=evidence_row.event,
            intent_id=evidence_row.intent_id,
            from_status=evidence_row.from_status,
            to_status=evidence_row.to_status,
            reason_code=evidence_row.reason_code,
            digest=evidence_row.digest,
        )
        if item.digest != evidence_row.digest:
            raise ProductionControlError("persisted deployment evidence digest mismatch")
        evidence.append(item)

    def optional_text(key: str) -> str | None:
        value = raw_record.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ProductionControlError(f"persisted deployment field {key} is malformed")
        return value

    def optional_bool(key: str) -> bool | None:
        value = raw_record.get(key)
        if value is None:
            return None
        if not isinstance(value, bool):
            raise ProductionControlError(f"persisted deployment field {key} is malformed")
        return value

    raw_backup_verified = raw_record.get("backup_verified")
    if not isinstance(raw_backup_verified, bool):
        raise ProductionControlError("persisted deployment field backup_verified is malformed")
    status = _text(raw_record, "status")
    if (
        row.status != status
        or row.backup_verified != raw_backup_verified
        or row.failure_code != raw_record.get("failure_code")
        or row.deployment_ref != raw_record.get("deployment_ref")
        or row.verification_passed != raw_record.get("verification_passed")
        or row.rollback_ref != raw_record.get("rollback_ref")
    ):
        raise ProductionControlError("persisted deployment state columns disagree")

    return DeploymentRecord(
        intent=intent,
        backup_verified=raw_backup_verified,
        status=cast(Any, status),
        failure_code=optional_text("failure_code"),
        deployment_ref=optional_text("deployment_ref"),
        verification_passed=optional_bool("verification_passed"),
        rollback_ref=optional_text("rollback_ref"),
        evidence=tuple(evidence),
        approval=approval,
        provider_target_environment=optional_text("provider_target_environment"),
        provider_source_revision=optional_text("provider_source_revision"),
        provider_artifact_digest=optional_text("provider_artifact_digest"),
        verification_ref=optional_text("verification_ref"),
        rollback_succeeded=optional_bool("rollback_succeeded"),
        rollback_failure_code=optional_text("rollback_failure_code"),
    )


class SqlAlchemyDeploymentStore(DeploymentRecordStore):
    """Tenant-scoped durable store with append-only transition evidence."""

    def __init__(self, session_factory: SessionFactory, *, tenant_id: str) -> None:
        self._session_factory = session_factory
        self._tenant_id = validate_opaque_reference(tenant_id, field_name="tenant_id")

    def _row_evidence(self, session: Session, intent_id: str) -> list[DeploymentEvidenceRecord]:
        return list(
            session.scalars(
                select(DeploymentEvidenceRecord)
                .where(
                    DeploymentEvidenceRecord.tenant_id == self._tenant_id,
                    DeploymentEvidenceRecord.intent_id == intent_id,
                )
                .order_by(DeploymentEvidenceRecord.sequence)
            ).all()
        )

    def _from_row(self, session: Session, row: DeploymentIntentRecord) -> DeploymentRecord:
        return _record_from_row(row, self._row_evidence(session, row.intent_id))

    def get(self, intent_id: str) -> DeploymentRecord | None:
        with self._session_factory() as session:
            row = session.scalar(
                select(DeploymentIntentRecord).where(
                    DeploymentIntentRecord.tenant_id == self._tenant_id,
                    DeploymentIntentRecord.intent_id == intent_id,
                )
            )
            return None if row is None else self._from_row(session, row)

    def get_by_idempotency(self, idempotency_key: str) -> DeploymentRecord | None:
        with self._session_factory() as session:
            row = session.scalar(
                select(DeploymentIntentRecord).where(
                    DeploymentIntentRecord.tenant_id == self._tenant_id,
                    DeploymentIntentRecord.idempotency_key == idempotency_key,
                )
            )
            return None if row is None else self._from_row(session, row)

    def records(self) -> tuple[DeploymentRecord, ...]:
        with self._session_factory() as session:
            rows = list(
                session.scalars(
                    select(DeploymentIntentRecord)
                    .where(DeploymentIntentRecord.tenant_id == self._tenant_id)
                    .order_by(DeploymentIntentRecord.created_at, DeploymentIntentRecord.intent_id)
                ).all()
            )
            return tuple(self._from_row(session, row) for row in rows)

    def save(self, record: DeploymentRecord) -> DeploymentRecord:
        if record.intent.tenant_id != self._tenant_id:
            raise ProductionControlError("deployment store tenant boundary was crossed")
        payload = _record_payload(record)
        with self._session_factory() as session:
            row = session.scalar(
                select(DeploymentIntentRecord).where(
                    DeploymentIntentRecord.tenant_id == self._tenant_id,
                    DeploymentIntentRecord.intent_id == record.intent.intent_id,
                )
            )
            if row is None:
                row = DeploymentIntentRecord(
                    tenant_id=self._tenant_id,
                    application_id=record.intent.application_id,
                    intent_id=record.intent.intent_id,
                    idempotency_key=record.intent.idempotency_key,
                    intent_digest=record.intent.intent_digest,
                    status=record.status,
                    backup_verified=record.backup_verified,
                    failure_code=record.failure_code,
                    deployment_ref=record.deployment_ref,
                    verification_passed=record.verification_passed,
                    rollback_ref=record.rollback_ref,
                    record_json=payload,
                )
                session.add(row)
                session.flush()
            else:
                if row.intent_digest != record.intent.intent_digest:
                    raise DuplicateDeploymentError("intent_id was reused for another intent")
                existing_rows = self._row_evidence(session, record.intent.intent_id)
                if len(record.evidence) < len(existing_rows):
                    raise ProductionControlError("deployment evidence cannot be removed")
                for sequence, (existing, candidate) in enumerate(
                    zip(existing_rows, record.evidence[: len(existing_rows)], strict=True),
                    start=1,
                ):
                    if existing.sequence != sequence or existing.digest != candidate.digest:
                        raise ProductionControlError("deployment evidence cannot be rewritten")
                row.status = record.status
                row.backup_verified = record.backup_verified
                row.failure_code = record.failure_code
                row.deployment_ref = record.deployment_ref
                row.verification_passed = record.verification_passed
                row.rollback_ref = record.rollback_ref
                row.record_json = payload

            existing_rows = self._row_evidence(session, record.intent.intent_id)
            for sequence, evidence in enumerate(record.evidence, start=1):
                if sequence <= len(existing_rows):
                    continue
                session.add(
                    DeploymentEvidenceRecord(
                        tenant_id=self._tenant_id,
                        intent_id=record.intent.intent_id,
                        sequence=sequence,
                        **_evidence_payload(evidence),
                    )
                )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise DuplicateDeploymentError(
                    "deployment persistence uniqueness conflict"
                ) from exc
        return record

    def emergency_stop(self, stop_ref: str) -> None:
        normalized = validate_opaque_reference(stop_ref, field_name="emergency_stop_ref")
        with self._session_factory() as session:
            row = session.scalar(
                select(DeploymentControlRecord).where(
                    DeploymentControlRecord.tenant_id == self._tenant_id
                )
            )
            if row is None:
                session.add(
                    DeploymentControlRecord(
                        tenant_id=self._tenant_id,
                        emergency_stopped=True,
                        emergency_stop_ref=normalized,
                    )
                )
            else:
                row.emergency_stopped = True
                row.emergency_stop_ref = normalized
            session.commit()

    def emergency_stop_active(self) -> bool:
        with self._session_factory() as session:
            row = session.scalar(
                select(DeploymentControlRecord).where(
                    DeploymentControlRecord.tenant_id == self._tenant_id
                )
            )
            return bool(row and row.emergency_stopped)

    def revoked_credentials(self) -> tuple[str, ...]:
        with self._session_factory() as session:
            return tuple(
                session.scalars(
                    select(DeploymentRevokedCredential.credential_ref)
                    .where(DeploymentRevokedCredential.tenant_id == self._tenant_id)
                    .order_by(DeploymentRevokedCredential.credential_ref)
                ).all()
            )

    def revoke_credential(self, credential_ref: str) -> None:
        normalized = validate_opaque_reference(credential_ref, field_name="credential_ref")
        with self._session_factory() as session:
            exists = session.scalar(
                select(DeploymentRevokedCredential).where(
                    DeploymentRevokedCredential.tenant_id == self._tenant_id,
                    DeploymentRevokedCredential.credential_ref == normalized,
                )
            )
            if exists is None:
                session.add(
                    DeploymentRevokedCredential(
                        tenant_id=self._tenant_id,
                        credential_ref=normalized,
                    )
                )
                try:
                    session.commit()
                except IntegrityError:
                    session.rollback()


__all__ = ["SqlAlchemyDeploymentStore"]

