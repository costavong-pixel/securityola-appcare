"""Deterministic BETA-07 production deployment state machine."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .contracts import (
    DeploymentApproval,
    DeploymentEvidence,
    DeploymentIntent,
    DeploymentStatus,
    DuplicateDeploymentError,
    ProductionControlError,
    ProductionProvider,
    ProviderDeployment,
    validate_opaque_reference,
    validate_reason_code,
    live_preview_is_passed,
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if self.failure_code is not None:
            object.__setattr__(
                self, "failure_code", validate_reason_code(self.failure_code, field_name="failure_code")
            )
        for name in ("deployment_ref", "rollback_ref"):
            value = getattr(self, name)
            if value is not None:
                validate_opaque_reference(value, field_name=name)


class CredentialRevocationRegistry:
    """Stores only opaque credential references, never credential material."""

    def __init__(self) -> None:
        self._revoked: set[str] = set()

    def revoke(self, credential_ref: str) -> None:
        self._revoked.add(
            validate_opaque_reference(credential_ref, field_name="credential_ref")
        )

    def is_revoked(self, credential_ref: str) -> bool:
        return validate_opaque_reference(credential_ref, field_name="credential_ref") in self._revoked


class ProductionDeploymentController:
    """Fail-closed orchestration around an injected, non-networking provider fixture."""

    def __init__(
        self,
        provider: ProductionProvider,
        *,
        revocations: CredentialRevocationRegistry | None = None,
    ) -> None:
        self._provider = provider
        self._revocations = revocations or CredentialRevocationRegistry()
        self._records: dict[str, DeploymentRecord] = {}
        self._intent_by_key: dict[str, str] = {}
        self._emergency_stopped = False
        self._emergency_stop_ref: str | None = None

    def submit(self, intent: DeploymentIntent, *, backup_verified: bool) -> DeploymentRecord:
        """Register an intent, denying unsafe requests before any provider call."""

        if not isinstance(backup_verified, bool):
            raise ProductionControlError("backup_verified must be boolean")
        existing_id = self._intent_by_key.get(intent.idempotency_key)
        if existing_id is not None:
            existing = self._records[existing_id]
            if existing.intent.intent_digest != intent.intent_digest:
                raise DuplicateDeploymentError("idempotency key was reused for another intent")
            return existing
        if intent.intent_id in self._records:
            existing = self._records[intent.intent_id]
            if existing.intent.intent_digest != intent.intent_digest:
                raise DuplicateDeploymentError("intent_id was reused for another intent")
            return existing

        record = DeploymentRecord(
            intent=intent,
            backup_verified=backup_verified,
            status="approval_pending",
        )
        self._intent_by_key[intent.idempotency_key] = intent.intent_id
        self._records[intent.intent_id] = record

        if self._emergency_stopped:
            return self._save(
                self._transition(record, "emergency_stopped", "emergency_stop_active", "emergency_stop_active")
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
        return self._save(self._transition(record, "approved", "approval_accepted"))

    def emergency_stop(self, stop_ref: str) -> None:
        """Latch an emergency stop; there is no model or owner bypass."""

        self._emergency_stopped = True
        self._emergency_stop_ref = validate_opaque_reference(
            stop_ref, field_name="emergency_stop_ref"
        )

    def revoke_credential(self, credential_ref: str) -> None:
        self._revocations.revoke(credential_ref)

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
        if record.status != "approved":
            return self._save(
                self._transition(record, "denied", "approval_required", "approval_required")
            )
        if self._emergency_stopped:
            return self._save(
                self._transition(record, "emergency_stopped", "emergency_stop_active", "emergency_stop_active")
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
                self._transition(record, "failed", "provider_deploy_failed", "provider_deploy_failed")
            )
        record = self._save(replace(record, deployment_ref=deployment.deployment_ref))

        identity_failure = self._identity_failure(record.intent, deployment)
        if identity_failure is not None:
            return self._rollback(record, deployment, identity_failure)

        record = self._save(self._transition(record, "verifying", "deployment_identity_verified"))
        try:
            verification = self._provider.verify(record.intent, deployment)
        except Exception:
            return self._rollback(record, deployment, "verification_provider_failed")
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
        try:
            return self._records[intent_id]
        except KeyError as exc:
            raise ProductionControlError("deployment intent is unknown") from exc

    def records(self) -> tuple[DeploymentRecord, ...]:
        return tuple(self._records.values())

    def audit_log(self, intent_id: str) -> tuple[DeploymentEvidence, ...]:
        return self.get(intent_id).evidence

    @staticmethod
    def _identity_failure(
        intent: DeploymentIntent, deployment: ProviderDeployment
    ) -> str | None:
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
        record = self._save(
            self._transition(record, "rolling_back", failure_code, failure_code)
        )
        try:
            rollback = self._provider.rollback(record.intent, deployment)
        except Exception:
            return self._save(
                self._transition(record, "rollback_failed", "rollback_failed", "rollback_failed")
            )
        if (
            not rollback.succeeded
            or rollback.rollback_reference != record.intent.rollback_reference
        ):
            return self._save(
                self._transition(
                    record,
                    "rollback_failed",
                    "rollback_identity_or_execution_failed",
                    "rollback_identity_or_execution_failed",
                )
            )
        return self._save(
            replace(
                self._transition(record, "rolled_back", failure_code, failure_code),
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
        self._records[record.intent.intent_id] = record
        return record


__all__ = [
    "CredentialRevocationRegistry",
    "DeploymentRecord",
    "ProductionDeploymentController",
]
