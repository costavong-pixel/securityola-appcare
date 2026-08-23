"""BETA-07 production-control and failure-injection tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from appcare.deployment import (
    DeploymentApproval,
    DeploymentIntent,
    DuplicateDeploymentError,
    FixtureProductionProvider,
    ProductionControlError,
    ProductionDeploymentController,
)


def _intent(
    *,
    preview_status: str = "pass",
    idempotency_key: str = "idempotency-1",
    intent_id: str = "intent-1",
) -> DeploymentIntent:
    return DeploymentIntent(
        intent_id=intent_id,
        tenant_id="tenant-1",
        application_id="application-1",
        artifact_digest="a" * 64,
        source_revision="c" * 40,
        rollback_reference="d" * 40,
        rollback_artifact_digest="b" * 64,
        idempotency_key=idempotency_key,
        requested_by="owner-1",
        backup_evidence_ref="backup-evidence-1",
        credential_ref="vault://appcare/vercel-beta07",
        beta06_verified_live_preview=preview_status,
    )


def _approve(intent: DeploymentIntent) -> DeploymentApproval:
    return DeploymentApproval(
        intent_id=intent.intent_id,
        approval_id=f"approval-{intent.intent_id}",
        actor_ref="approver-1",
        decision="approved",
        decision_ref=f"decision-{intent.intent_id}",
        intent_digest=intent.intent_digest,
    )


def test_live_preview_interlock_denies_before_provider_call() -> None:
    provider = FixtureProductionProvider()
    controller = ProductionDeploymentController(provider)

    record = controller.submit(
        _intent(preview_status="blocked"),
        backup_verified=True,
    )

    assert record.status == "denied"
    assert record.failure_code == "beta06_live_preview_required"
    assert provider.deploy_calls == 0
    assert controller.audit_log(record.intent.intent_id)[-1].reason_code == (
        "beta06_live_preview_required"
    )


def test_backup_and_approval_gates_precede_one_successful_deployment() -> None:
    provider = FixtureProductionProvider()
    controller = ProductionDeploymentController(provider)
    missing_backup = controller.submit(_intent(intent_id="intent-no-backup"), backup_verified=False)
    assert missing_backup.status == "denied"
    assert missing_backup.failure_code == "backup_gate_required"

    intent = _intent(intent_id="intent-approved")
    pending = controller.submit(intent, backup_verified=True)
    assert pending.status == "approval_pending"
    approved = controller.approve(intent.intent_id, _approve(intent))
    assert approved.status == "approved"

    result = controller.execute(intent.intent_id)

    assert result.status == "succeeded"
    assert result.verification_passed is True
    assert provider.deploy_calls == 1
    assert provider.verify_calls == 1
    assert provider.rollback_calls == 0


def test_failed_verification_rolls_back_once_and_duplicate_execute_is_idempotent() -> None:
    provider = FixtureProductionProvider(verification_passed=False)
    controller = ProductionDeploymentController(provider)
    intent = _intent()
    controller.submit(intent, backup_verified=True)
    controller.approve(intent.intent_id, _approve(intent))

    first = controller.execute(intent.intent_id)
    second = controller.execute(intent.intent_id)

    assert first.status == "rolled_back"
    assert first.failure_code == "fixture_health_failed"
    assert first.rollback_ref is not None
    assert second == first
    assert provider.deploy_calls == 1
    assert provider.verify_calls == 1
    assert provider.rollback_calls == 1


def test_provider_target_and_artifact_identity_mismatch_rolls_back() -> None:
    provider = FixtureProductionProvider(target_environment="staging")
    controller = ProductionDeploymentController(provider)
    intent = _intent()
    controller.submit(intent, backup_verified=True)
    controller.approve(intent.intent_id, _approve(intent))

    result = controller.execute(intent.intent_id)

    assert result.status == "rolled_back"
    assert result.failure_code == "provider_target_mismatch"
    assert provider.rollback_calls == 1


def test_duplicate_idempotency_key_cannot_change_intent() -> None:
    provider = FixtureProductionProvider()
    controller = ProductionDeploymentController(provider)
    first = _intent()
    same = controller.submit(first, backup_verified=True)
    assert controller.submit(first, backup_verified=True) == same

    different = replace(first, intent_id="intent-2")
    with pytest.raises(DuplicateDeploymentError, match="idempotency"):
        controller.submit(different, backup_verified=True)


def test_revoked_credential_and_emergency_stop_deny_execution() -> None:
    intent = _intent()
    provider = FixtureProductionProvider()
    controller = ProductionDeploymentController(provider)
    controller.revoke_credential(intent.credential_ref)

    revoked = controller.submit(intent, backup_verified=True)

    assert revoked.status == "denied"
    assert revoked.failure_code == "credential_revoked"
    assert provider.deploy_calls == 0

    stopped_provider = FixtureProductionProvider()
    stopped = ProductionDeploymentController(stopped_provider)
    stopped.emergency_stop("emergency-stop-1")
    stopped_record = stopped.submit(_intent(intent_id="intent-stopped"), backup_verified=True)

    assert stopped_record.status == "emergency_stopped"
    assert stopped_record.failure_code == "emergency_stop_active"
    assert stopped_provider.deploy_calls == 0


def test_failed_rollback_is_terminal_and_never_retried() -> None:
    provider = FixtureProductionProvider(verification_passed=False, rollback_succeeds=False)
    controller = ProductionDeploymentController(provider)
    intent = _intent()
    controller.submit(intent, backup_verified=True)
    controller.approve(intent.intent_id, _approve(intent))

    first = controller.execute(intent.intent_id)
    second = controller.execute(intent.intent_id)

    assert first.status == "rollback_failed"
    assert first.failure_code == "rollback_identity_or_execution_failed"
    assert second == first
    assert provider.deploy_calls == 1
    assert provider.rollback_calls == 1


def test_intent_is_immutable_and_invalid_preview_status_is_rejected() -> None:
    intent = _intent()
    with pytest.raises(FrozenInstanceError):
        intent.source_revision = "e" * 40  # type: ignore[misc]

    with pytest.raises(ProductionControlError, match="preview"):
        _intent(preview_status="owner-approved")


def test_rejected_or_mismatched_approval_cannot_promote_intent() -> None:
    provider = FixtureProductionProvider()
    controller = ProductionDeploymentController(provider)
    intent = _intent()
    controller.submit(intent, backup_verified=True)

    wrong = replace(_approve(intent), intent_digest="f" * 64)
    rejected = controller.approve(intent.intent_id, wrong)

    assert rejected.status == "denied"
    assert rejected.failure_code == "approval_identity_mismatch"
    assert provider.deploy_calls == 0
