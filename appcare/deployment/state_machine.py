"""Deterministic BETA-07 production deployment state machine."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Protocol

from .contracts import (
    DeploymentApproval,
    DeploymentEvidence,
    DeploymentIntent,
    DeploymentStatus,
    DuplicateDeploymentError,
    ProductionControlError,
    ProductionProvider,
    ProviderDeployment,
    live_preview_is_passed,
    validate_opaque_reference,
    validate_reason_code,
)


@dataclass(frozen=True, slots=True)
class DeploymentRecord:
    """Current state plus sanitized audit evidence for one immutable intent."""

    intent: DeploymentIntent
    backup_verified: bool
    status: DeploymentStatus
    failure_code: str | None = None
    deployment_ref: str | None = None
    verification_passed: bool | None = None
    rollback_ref: str | None = None
    evidence: tuple[DeploymentEvidence, ...] = ()
    approval: DeploymentApproval | None = None
    provider_target_environment: str | None = None
    provider_source_revision: str | None = None
    provider_artifact_digest: str | None = None
    verification_ref: str | None = None
    rollback_succeeded: bool | None = None
    rollback_failure_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if self.failure_code is not None:
            object.__setattr__(
                self,
                "failure_code",
                validate_reason_code(self.failure_code, field_name="failure_code"),
            )
        for name in ("deployment_ref", "rollback_ref"):
            value = getattr(self, name)
            if value is not None:
                validate_opaque_reference(value, field_name=name)
        for name in (
            "provider_target_environment",
            "provider_source_revision",
            "provider_artifact_digest",
            "verification_ref",
        ):
            value = getattr(self, name)
            if value is not None:
                validate_opaque_reference(value, field_name=name)
        if self.rollback_failure_code is not None:
            object.__setattr__(
                self,
                "rollback_failure_code",
                validate_reason_code(
                    self.rollback_failure_code,
                    field_name="rollback_failure_code",
                ),
            )
        for name in ("rollback_succeeded", "verification_passed"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, bool):
                raise ProductionControlError(f"{name} must be boolean when present")
        if self.approval is not None and (
            self.approval.intent_id != self.intent.intent_id
            or self.approval.intent_digest != self.intent.intent_digest
        ):
            raise ProductionControlError("approval is not bound to the deployment intent")


class DeploymentRecordStore(Protocol):
    """Durable store contract for intent state and authoritative evidence."""

    def get(self, intent_id: str) -> DeploymentRecord | None: ...

    def get_by_idempotency(self, idempotency_key: str) -> DeploymentRecord | None: ...

    def records(self) -> tuple[DeploymentRecord, ...]: ...

    def save(self, record: DeploymentRecord) -> DeploymentRecord: ...

    def emergency_stop(self, stop_ref: str) -> None: ...

    def emergency_stop_active(self) -> bool: ...

    def revoked_credentials(self) -> tuple[str, ...]: ...

    def revoke_credential(self, credential_ref: str) -> None: ...


@dataclass
class InMemoryDeploymentStore:
    """Explicit fixture store; production-shaped controllers should use the DB store."""

    _records: dict[str, DeploymentRecord] = field(default_factory=dict)
    _emergency_stop_ref: str | None = None
    _revoked: set[str] = field(default_factory=set)

    def get(self, intent_id: str) -> DeploymentRecord | None:
        return self._records.get(intent_id)

    def get_by_idempotency(self, idempotency_key: str) -> DeploymentRecord | None:
        return next(
            (
                record
                for record in self._records.values()
                if record.intent.idempotency_key == idempotency_key
            ),
            None,
        )

    def records(self) -> tuple[DeploymentRecord, ...]:
        return tuple(self._records.values())

    def save(self, record: DeploymentRecord) -> DeploymentRecord:
        existing = self._records.get(record.intent.intent_id)
        if existing is not None:
            if existing.intent.intent_digest != record.intent.intent_digest:
                raise DuplicateDeploymentError("intent_id was reused for another intent")
            if len(record.evidence) < len(existing.evidence) or tuple(
                record.evidence[: len(existing.evidence)]
            ) != existing.evidence:
                raise ProductionControlError("deployment evidence is not append-only")
        self._records[record.intent.intent_id] = record
        return record

    def emergency_stop(self, stop_ref: str) -> None:
        self._emergency_stop_ref = stop_ref

    def emergency_stop_active(self) -> bool:
        return self._emergency_stop_ref is not None

    def revoked_credentials(self) -> tuple[str, ...]:
        return tuple(sorted(self._revoked))

    def revoke_credential(self, credential_ref: str) -> None:
        self._revoked.add(credential_ref)


class CredentialRevocationRegistry:
    """Stores only opaque credential references, never credential material."""

    def __init__(self, initial: Iterable[str] = ()) -> None:
        self._revoked: set[str] = set(initial)

    def revoke(self, credential_ref: str) -> None:
        self._revoked.add(validate_opaque_reference(credential_ref, field_name="credential_ref"))

    def is_revoked(self, credential_ref: str) -> bool:
        return (
            validate_opaque_reference(credential_ref, field_name="credential_ref") in self._revoked
        )


class ProductionDeploymentController:
    """Fail-closed orchestration around an injected, non-networking provider fixture."""

    def __init__(
        self,
        provider: ProductionProvider,
        *,
        revocations: CredentialRevocationRegistry | None = None,
        store: DeploymentRecordStore | None = None,
    ) -> None:
        self._provider = provider
        self._store = store or InMemoryDeploymentStore()
        self._revocations = revocations or CredentialRevocationRegistry(
            self._store.revoked_credentials()
        )
        self._records: dict[str, DeploymentRecord] = {
            record.intent.intent_id: record for record in self._store.records()
        }
        self._emergency_stopped = self._store.emergency_stop_active()

    def submit(self, intent: DeploymentIntent, *, backup_verified: bool) -> DeploymentRecord:
        """Register an intent, denying unsafe requests before any provider call."""

        if not isinstance(backup_verified, bool):
            raise ProductionControlError("backup_verified must be boolean")
        existing = self._store.get_by_idempotency(intent.idempotency_key)
        if existing is not None:
            if existing.intent.intent_digest != intent.intent_digest:
                raise DuplicateDeploymentError("idempotency key was reused for another intent")
            self._records[existing.intent.intent_id] = existing
            return existing
        existing = self._store.get(intent.intent_id)
        if existing is not None:
            if existing.intent.intent_digest != intent.intent_digest:
                raise DuplicateDeploymentError("intent_id was reused for another intent")
            self._records[existing.intent.intent_id] = existing
            return existing

        record = DeploymentRecord(
            intent=intent,
            backup_verified=backup_verified,
            status="approval_pending",
        )
        self._save(record)

        if self._emergency_stopped:
            return self._save(
                self._transition(
                    record, "emergency_stopped", "emergency_stop_active", "emergency_stop_active"
                )
            )
        if not live_preview_is_passed(intent.beta06_verified_live_preview):
            return self._save(
                self._transition(
                    record,
                    "denied",
                    "beta06_live_preview_required",
                    "beta06_live_preview_required",
                )
            )
        if not backup_verified:
            return self._save(
                self._transition(record, "denied", "backup_gate_required", "backup_gate_required")
            )
        if self._revocations.is_revoked(intent.credential_ref):
            return self._save(
                self._transition(record, "denied", "credential_revoked", "credential_revoked")
            )
        return self._save(self._transition(record, "approval_pending", "intent_submitted"))

    def approve(self, intent_id: str, approval: DeploymentApproval) -> DeploymentRecord:
        record = self.get(intent_id)
        if record.status != "approval_pending":
            return record
        if (
            approval.intent_id != record.intent.intent_id
            or approval.intent_digest != record.intent.intent_digest
        ):
            return self._save(
                self._transition(
                    record,
                    "denied",
                    "approval_identity_mismatch",
                    "approval_identity_mismatch",
                )
            )
        if approval.decision == "rejected":
            return self._save(
                self._transition(record, "denied", "approval_rejected", "approval_rejected")
            )
        return self._save(
            self._transition(replace(record, approval=approval), "approved", "approval_accepted")
        )

    def emergency_stop(self, stop_ref: str) -> None:
        """Latch an emergency stop; there is no model or owner bypass."""

        normalized = validate_opaque_reference(
            stop_ref, field_name="emergency_stop_ref"
        )
        self._store.emergency_stop(normalized)
        self._emergency_stopped = True

    def revoke_credential(self, credential_ref: str) -> None:
        normalized = validate_opaque_reference(credential_ref, field_name="credential_ref")
        self._store.revoke_credential(normalized)
        self._revocations.revoke(normalized)

    def execute(self, intent_id: str) -> DeploymentRecord:
        """Deploy once, verify exact identity, and roll back on failed verification."""

        record = self.get(intent_id)
        if record.status in {
            "succeeded",
            "rolled_back",
            "rollback_failed",
            "denied",
            "emergency_stopped",
            "failed",
        }:
            return record
        if record.status in {"deploying", "verifying", "rolling_back"}:
            return self._save(
                self._transition(
                    record,
                    "failed",
                    "restart_recovery_required",
                    "restart_recovery_required",
                )
            )
        if record.status != "approved":
            return self._save(
                self._transition(record, "denied", "approval_required", "approval_required")
            )
        if self._emergency_stopped:
            return self._save(
                self._transition(
                    record, "emergency_stopped", "emergency_stop_active", "emergency_stop_active"
                )
            )
        if self._revocations.is_revoked(record.intent.credential_ref):
            return self._save(
                self._transition(record, "denied", "credential_revoked", "credential_revoked")
            )
        if not live_preview_is_passed(record.intent.beta06_verified_live_preview):
            return self._save(
                self._transition(
                    record,
                    "denied",
                    "beta06_live_preview_required",
                    "beta06_live_preview_required",
                )
            )

        record = self._save(self._transition(record, "deploying", "deployment_started"))
        try:
            deployment = self._provider.deploy(record.intent)
        except Exception:
            return self._save(
                self._transition(
                    record, "failed", "provider_deploy_failed", "provider_deploy_failed"
                )
            )
        record = self._save(
            replace(
                record,
                deployment_ref=deployment.deployment_ref,
                provider_target_environment=deployment.target_environment,
                provider_source_revision=deployment.source_revision,
                provider_artifact_digest=deployment.artifact_digest,
            )
        )

        identity_failure = self._identity_failure(record.intent, deployment)
        if identity_failure is not None:
            return self._rollback(record, deployment, identity_failure)

        record = self._save(self._transition(record, "verifying", "deployment_identity_verified"))
        try:
            verification = self._provider.verify(record.intent, deployment)
        except Exception:
            return self._rollback(record, deployment, "verification_provider_failed")
        record = self._save(replace(record, verification_ref=verification.verification_ref))
        if verification.deployment_ref != deployment.deployment_ref:
            return self._rollback(record, deployment, "verification_identity_mismatch")
        if not verification.passed:
            return self._rollback(
                record,
                deployment,
                verification.failure_code or "post_deploy_verification_failed",
            )
        return self._save(
            self._transition(
                replace(record, verification_passed=True),
                "succeeded",
                "post_deploy_verification_passed",
            )
        )

    def get(self, intent_id: str) -> DeploymentRecord:
        record = self._store.get(intent_id)
        if record is not None:
            self._records[intent_id] = record
            return record
        try:
            return self._records[intent_id]
        except KeyError as exc:
            raise ProductionControlError("deployment intent is unknown") from exc

    def records(self) -> tuple[DeploymentRecord, ...]:
        return self._store.records()

    def audit_log(self, intent_id: str) -> tuple[DeploymentEvidence, ...]:
        return self.get(intent_id).evidence

    @staticmethod
    def _identity_failure(intent: DeploymentIntent, deployment: ProviderDeployment) -> str | None:
        if deployment.target_environment != intent.target_environment:
            return "provider_target_mismatch"
        if deployment.source_revision != intent.source_revision:
            return "provider_revision_mismatch"
        if deployment.artifact_digest != intent.artifact_digest:
            return "provider_artifact_mismatch"
        return None

    def _rollback(
        self,
        record: DeploymentRecord,
        deployment: ProviderDeployment,
        failure_code: str,
    ) -> DeploymentRecord:
        record = self._save(self._transition(record, "rolling_back", failure_code, failure_code))
        try:
            rollback = self._provider.rollback(record.intent, deployment)
        except Exception:
            return self._save(
                self._transition(
                    replace(
                        record,
                        rollback_succeeded=False,
                        rollback_failure_code="rollback_failed",
                    ),
                    "rollback_failed",
                    "rollback_failed",
                    "rollback_failed",
                )
            )
        if (
            not rollback.succeeded
            or rollback.rollback_reference != record.intent.rollback_reference
        ):
            return self._save(
                self._transition(
                    replace(
                        record,
                        rollback_ref=rollback.rollback_ref,
                        rollback_succeeded=False,
                        rollback_failure_code=(
                            rollback.failure_code or "rollback_identity_or_execution_failed"
                        ),
                    ),
                    "rollback_failed",
                    "rollback_identity_or_execution_failed",
                    "rollback_identity_or_execution_failed",
                )
            )
        return self._save(
            replace(
                self._transition(
                    replace(record, rollback_succeeded=True, rollback_failure_code=None),
                    "rolled_back",
                    failure_code,
                    failure_code,
                ),
                rollback_ref=rollback.rollback_ref,
                verification_passed=False,
            )
        )

    def _transition(
        self,
        record: DeploymentRecord,
        status: DeploymentStatus,
        reason_code: str,
        failure_code: str | None = None,
    ) -> DeploymentRecord:
        evidence = DeploymentEvidence.create(
            event="deployment_transition",
            intent_id=record.intent.intent_id,
            from_status=record.status,
            to_status=status,
            reason_code=reason_code,
        )
        return replace(
            record,
            status=status,
            failure_code=failure_code,
            evidence=record.evidence + (evidence,),
        )

    def _save(self, record: DeploymentRecord) -> DeploymentRecord:
        saved = self._store.save(record)
        self._records[saved.intent.intent_id] = saved
        return saved


__all__ = [
    "CredentialRevocationRegistry",
    "DeploymentRecord",
    "DeploymentRecordStore",
    "InMemoryDeploymentStore",
    "ProductionDeploymentController",
]
