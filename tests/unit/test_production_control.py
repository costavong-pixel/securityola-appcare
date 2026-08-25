"""BETA-07 production-control and failure-injection tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from appcare.deployment import (
    DeploymentApproval,
    DeploymentIntent,
    DuplicateDeploymentError,
    FixtureProductionProvider,
    InMemoryPreproductionEvidenceStore,
    PreproductionEvidence,
    ProductionControlError,
    ProductionDeploymentController,
    SqlAlchemyDeploymentStore,
)
from tests.control_plane_helpers import create_application, issue_token, new_test_app, seed_user


def _intent(
    *,
    preproduction_status: str = "pass",
    idempotency_key: str = "idempotency-1",
    intent_id: str = "intent-1",
    tenant_id: str = "tenant-1",
    application_id: str = "application-1",
) -> DeploymentIntent:
    evidence = PreproductionEvidence.create(
        tenant_id=tenant_id,
        application_id=application_id,
        provider="securityola-vps",
        target_type="controlled-reference",
        source_revision="c" * 40,
        artifact_digest="a" * 64,
        environment_identity="appcare-staging-18567",
        deployment_reference=f"staging-deployment-{intent_id}",
        deployment_timestamp=datetime(2026, 8, 25, tzinfo=UTC),
        smoke_test_receipt=f"smoke-{intent_id}",
        security_test_receipt=f"security-{intent_id}",
        rollback_reference_receipt=f"rollback-{intent_id}",
        status=preproduction_status,  # type: ignore[arg-type]
    )
    return DeploymentIntent(
        intent_id=intent_id,
        tenant_id=tenant_id,
        application_id=application_id,
        artifact_digest="a" * 64,
        source_revision="c" * 40,
        rollback_reference="d" * 40,
        rollback_artifact_digest="b" * 64,
        idempotency_key=idempotency_key,
        requested_by="owner-1",
        backup_evidence_ref="backup-evidence-1",
        credential_ref="vault://appcare/vercel-beta07",
        preproduction_evidence_digest=evidence.authoritative_evidence_digest,
    )


def _preproduction_store(
    intent: DeploymentIntent, *, status: str = "pass"
) -> InMemoryPreproductionEvidenceStore:
    store = InMemoryPreproductionEvidenceStore()
    for candidate_status in (status, "pass", "fail", "unverified"):
        evidence = PreproductionEvidence.create(
            tenant_id=intent.tenant_id,
            application_id=intent.application_id,
            provider="securityola-vps",
            target_type="controlled-reference",
            source_revision=intent.source_revision,
            artifact_digest=intent.artifact_digest,
            environment_identity="appcare-staging-18567",
            deployment_reference=f"staging-deployment-{intent.intent_id}",
            deployment_timestamp=datetime(2026, 8, 25, tzinfo=UTC),
            smoke_test_receipt=f"smoke-{intent.intent_id}",
            security_test_receipt=f"security-{intent.intent_id}",
            rollback_reference_receipt=f"rollback-{intent.intent_id}",
            status=candidate_status,  # type: ignore[arg-type]
        )
        if evidence.authoritative_evidence_digest == intent.preproduction_evidence_digest:
            store.save(evidence)
            break
    return store


def _controller(
    provider: FixtureProductionProvider, intent: DeploymentIntent
) -> ProductionDeploymentController:
    return ProductionDeploymentController(
        provider,
        preproduction_store=_preproduction_store(intent),
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


def test_authoritative_preproduction_interlock_denies_before_provider_call() -> None:
    provider = FixtureProductionProvider()
    intent = _intent(preproduction_status="fail")
    controller = _controller(provider, intent)

    record = controller.submit(intent, backup_verified=True)

    assert record.status == "denied"
    assert record.failure_code == "verified_preproduction_environment_required"
    assert provider.deploy_calls == 0
    assert controller.audit_log(record.intent.intent_id)[-1].reason_code == (
        "verified_preproduction_environment_required"
    )


def test_backup_and_approval_gates_precede_one_successful_deployment() -> None:
    provider = FixtureProductionProvider()
    intent = _intent(intent_id="intent-approved", idempotency_key="idempotency-approved")
    controller = _controller(provider, intent)
    missing_backup = controller.submit(_intent(intent_id="intent-no-backup"), backup_verified=False)
    assert missing_backup.status == "denied"
    assert missing_backup.failure_code == "backup_gate_required"

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
    intent = _intent()
    controller = _controller(provider, intent)
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
    intent = _intent()
    controller = _controller(provider, intent)
    controller.submit(intent, backup_verified=True)
    controller.approve(intent.intent_id, _approve(intent))

    result = controller.execute(intent.intent_id)

    assert result.status == "rolled_back"
    assert result.failure_code == "provider_target_mismatch"
    assert provider.rollback_calls == 1


def test_duplicate_idempotency_key_cannot_change_intent() -> None:
    provider = FixtureProductionProvider()
    first = _intent()
    controller = _controller(provider, first)
    same = controller.submit(first, backup_verified=True)
    assert controller.submit(first, backup_verified=True) == same

    different = replace(first, intent_id="intent-2")
    with pytest.raises(DuplicateDeploymentError, match="idempotency"):
        controller.submit(different, backup_verified=True)


def test_revoked_credential_and_emergency_stop_deny_execution() -> None:
    intent = _intent()
    provider = FixtureProductionProvider()
    controller = _controller(provider, intent)
    controller.revoke_credential(intent.credential_ref)

    revoked = controller.submit(intent, backup_verified=True)

    assert revoked.status == "denied"
    assert revoked.failure_code == "credential_revoked"
    assert provider.deploy_calls == 0

    stopped_provider = FixtureProductionProvider()
    stopped_intent = _intent(intent_id="intent-stopped")
    stopped = _controller(stopped_provider, stopped_intent)
    stopped.emergency_stop("emergency-stop-1")
    stopped_record = stopped.submit(stopped_intent, backup_verified=True)

    assert stopped_record.status == "emergency_stopped"
    assert stopped_record.failure_code == "emergency_stop_active"
    assert stopped_provider.deploy_calls == 0


def test_failed_rollback_is_terminal_and_never_retried() -> None:
    provider = FixtureProductionProvider(verification_passed=False, rollback_succeeds=False)
    intent = _intent()
    controller = _controller(provider, intent)
    controller.submit(intent, backup_verified=True)
    controller.approve(intent.intent_id, _approve(intent))

    first = controller.execute(intent.intent_id)
    second = controller.execute(intent.intent_id)

    assert first.status == "rollback_failed"
    assert first.failure_code == "rollback_identity_or_execution_failed"
    assert second == first
    assert provider.deploy_calls == 1
    assert provider.rollback_calls == 1


def test_intent_is_immutable_and_invalid_preproduction_status_is_rejected() -> None:
    intent = _intent()
    with pytest.raises(FrozenInstanceError):
        intent.source_revision = "e" * 40  # type: ignore[misc]

    with pytest.raises(ProductionControlError, match="status"):
        _intent(preproduction_status="owner-approved")


def test_rejected_or_mismatched_approval_cannot_promote_intent() -> None:
    intent = _intent()
    provider = FixtureProductionProvider()
    controller = _controller(provider, intent)
    controller.submit(intent, backup_verified=True)

    wrong = replace(_approve(intent), intent_digest="f" * 64)
    rejected = controller.approve(intent.intent_id, wrong)

    assert rejected.status == "denied"
    assert rejected.failure_code == "approval_identity_mismatch"
    assert provider.deploy_calls == 0


def test_database_store_survives_restart_and_cannot_repeat_deployment(tmp_path: Path) -> None:
    app = new_test_app(f"sqlite+pysqlite:///{(tmp_path / 'appcare-state.db').as_posix()}")
    user = seed_user(app, "Durable deployment")
    with TestClient(app) as client:
        token = issue_token(client, user.email)
        application = create_application(client, token, "Durable deployment app")

    store = SqlAlchemyDeploymentStore(
        app.state.database.session_factory,
        tenant_id=user.tenant_id,
    )
    intent = _intent(tenant_id=user.tenant_id, application_id=str(application["id"]))
    provider = FixtureProductionProvider()
    preproduction_store = _preproduction_store(intent)
    controller = ProductionDeploymentController(
        provider,
        store=store,
        preproduction_store=preproduction_store,
    )
    controller.submit(intent, backup_verified=True)
    controller.approve(intent.intent_id, _approve(intent))
    completed = controller.execute(intent.intent_id)

    restarted_provider = FixtureProductionProvider()
    restarted = ProductionDeploymentController(
        restarted_provider,
        store=SqlAlchemyDeploymentStore(
            app.state.database.session_factory,
            tenant_id=user.tenant_id,
        ),
        preproduction_store=preproduction_store,
    )
    recovered = restarted.execute(intent.intent_id)

    assert completed.status == "succeeded"
    assert recovered == completed
    assert recovered.approval is not None
    assert recovered.provider_source_revision == intent.source_revision
    assert recovered.verification_ref == "fixture-verification-1"
    assert restarted_provider.deploy_calls == 0
    assert len(restarted.audit_log(intent.intent_id)) == len(completed.evidence)
