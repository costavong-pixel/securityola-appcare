"""Failure-injection and restart-boundary tests for BETA-05."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from langgraph.types import Command
from sqlalchemy import func, select

from appcare.db import Database
from appcare.deployment.preproduction import PreproductionEvidence
from appcare.models import AuditEvent, Tenant, WorkflowAction, WorkflowTransition
from appcare.workflows import (
    ActionResult,
    EvidenceItem,
    RetryableWorkflowError,
    ScanResult,
    WorkflowConfigurationError,
    WorkflowRuntime,
    WorkflowState,
    WorkflowStore,
    build_in_memory_checkpointer,
    build_workflow,
    initial_state,
    postgres_checkpointer,
    validate_checkpoint_state,
)


class RecordingAction:
    def __init__(self, *, fail_verification: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail_verification = fail_verification

    def execute(
        self, action_key: str, action_kind: str, state: Mapping[str, object]
    ) -> ActionResult:
        del state
        self.calls.append((action_key, action_kind))
        return ActionResult(
            result_reference=f"result-{action_kind}",
            verification_passed=(
                False if self.fail_verification and action_kind == "post_deploy_verify" else None
            ),
        )


class FailingAction:
    def __init__(self) -> None:
        self.calls = 0

    def execute(
        self, action_key: str, action_kind: str, state: Mapping[str, object]
    ) -> ActionResult:
        del action_key, action_kind, state
        self.calls += 1
        raise RetryableWorkflowError("provider_temporary")


class FailingScan:
    def scan(self, state: Mapping[str, object]) -> ScanResult:
        del state
        return ScanResult(failure_code="scanner_unavailable", retryable=True)


PREPRODUCTION = PreproductionEvidence.create(
    tenant_id="tenant-1",
    application_id="app-1",
    provider="securityola-vps",
    target_type="controlled-reference",
    source_revision="c" * 40,
    artifact_digest="a" * 64,
    environment_identity="appcare-staging-18567",
    deployment_reference="workflow-preproduction",
    deployment_timestamp=datetime(2026, 8, 25, tzinfo=UTC),
    smoke_test_receipt="workflow-smoke",
    security_test_receipt="workflow-security",
    rollback_reference_receipt="workflow-rollback",
)


class StaticPreproductionResolver:
    def resolve(self, state: Mapping[str, object]) -> PreproductionEvidence | None:
        if state.get("preproduction_evidence_ref") != PREPRODUCTION.authoritative_evidence_digest:
            return None
        return PREPRODUCTION


class PermissivePreproductionResolver:
    """A deliberately broad resolver used to test workflow-side binding."""

    def resolve(self, state: Mapping[str, object]) -> PreproductionEvidence:
        del state
        return PREPRODUCTION


def _database(tmp_path: Path) -> Database:
    database = Database(f"sqlite+pysqlite:///{(tmp_path / 'workflow.db').as_posix()}")
    database.initialize()
    with database.session() as session:
        session.add(Tenant(id="tenant-1", name="AppCare test tenant", status="active"))
    return database


def _state(workflow_id: str, **overrides: str | int) -> WorkflowState:
    return initial_state(
        workflow_id=workflow_id,
        tenant_id="tenant-1",
        application_id="app-1",
        job_id="job-1",
        target_environment=str(overrides.get("target_environment", "staging")),
        preproduction_evidence_ref=(
            None
            if "preproduction_evidence_ref" not in overrides
            else str(overrides["preproduction_evidence_ref"])
        ),
        source_revision=str(overrides.get("source_revision", PREPRODUCTION.source_revision)),
        artifact_digest=str(overrides.get("artifact_digest", PREPRODUCTION.artifact_digest)),
        risk_level=str(overrides.get("risk_level", "low")),
        backup_status=str(overrides.get("backup_status", "verified")),
        retry_budget=int(overrides.get("retry_budget", 3)),
    )


def test_workflow_completes_and_duplicate_action_delivery_is_idempotent(tmp_path: Path) -> None:
    database = _database(tmp_path)
    action = RecordingAction()
    store = WorkflowStore(database)
    graph = build_workflow(
        WorkflowRuntime(store, action_adapter=action), build_in_memory_checkpointer()
    )
    result = graph.invoke(
        _state("workflow-complete"), {"configurable": {"thread_id": "workflow-complete"}}
    )

    assert result["status"] == "completed"
    assert result["phase"] == "completed"
    assert len(action.calls) == 6
    first = store.run_action(
        tenant_id="tenant-1",
        workflow_id="workflow-complete",
        action_key="duplicate-action",
        action_kind="patch_test",
        state=result,
        adapter=action,
        max_attempts=3,
    )
    second = store.run_action(
        tenant_id="tenant-1",
        workflow_id="workflow-complete",
        action_key="duplicate-action",
        action_kind="patch_test",
        state=result,
        adapter=action,
        max_attempts=3,
    )
    assert first.result_reference == second.result_reference
    assert len(action.calls) == 7
    with database.session() as session:
        assert session.scalar(select(func.count()).select_from(WorkflowAction)) == 7
        assert session.scalar(select(func.count()).select_from(WorkflowTransition)) == 14
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 14


def test_high_risk_approval_survives_graph_recreation(tmp_path: Path) -> None:
    database = _database(tmp_path)
    action = RecordingAction()
    store = WorkflowStore(database)
    checkpointer = build_in_memory_checkpointer()
    runtime = WorkflowRuntime(
        store,
        action_adapter=action,
        preproduction_evidence_resolver=StaticPreproductionResolver(),
    )
    graph = build_workflow(runtime, checkpointer)
    config = {"configurable": {"thread_id": "workflow-approval"}}
    first = graph.invoke(
        _state(
            "workflow-approval",
            target_environment="production",
            risk_level="high",
            preproduction_evidence_ref=PREPRODUCTION.authoritative_evidence_digest,
        ),
        config,
    )
    assert len(first["__interrupt__"]) == 1
    assert not any(kind == "controlled_deploy" for _, kind in action.calls)

    restarted_graph = build_workflow(runtime, checkpointer)
    resumed = restarted_graph.invoke(
        Command(resume={"decision": "approved", "decision_ref": "owner-approval-1"}), config
    )
    assert resumed["status"] == "completed"
    assert sum(kind == "controlled_deploy" for _, kind in action.calls) == 1


def test_retry_budget_exhaustion_escalates_without_looping(tmp_path: Path) -> None:
    database = _database(tmp_path)
    action = FailingAction()
    graph = build_workflow(
        WorkflowRuntime(WorkflowStore(database), action_adapter=action),
        build_in_memory_checkpointer(),
    )
    result = graph.invoke(
        _state("workflow-retry", retry_budget=2),
        {"configurable": {"thread_id": "workflow-retry"}},
    )
    assert result["status"] == "escalated"
    assert result["failure_code"] == "retry_budget_exhausted"
    assert action.calls == 2


def test_failed_verification_routes_one_rollback(tmp_path: Path) -> None:
    database = _database(tmp_path)
    action = RecordingAction(fail_verification=True)
    graph = build_workflow(
        WorkflowRuntime(WorkflowStore(database), action_adapter=action),
        build_in_memory_checkpointer(),
    )
    result = graph.invoke(
        _state("workflow-rollback"),
        {"configurable": {"thread_id": "workflow-rollback"}},
    )
    assert result["status"] == "rolled_back"
    assert result["rollback_status"] == "completed"
    assert result["verification_passed"] is False
    assert result["failure_code"] is None
    assert sum(kind == "rollback" for _, kind in action.calls) == 1


def test_scanner_failure_is_not_a_finding(tmp_path: Path) -> None:
    database = _database(tmp_path)
    graph = build_workflow(
        WorkflowRuntime(WorkflowStore(database), scan_adapter=FailingScan()),
        build_in_memory_checkpointer(),
    )
    result = graph.invoke(
        _state("workflow-scan-failure"),
        {"configurable": {"thread_id": "workflow-scan-failure"}},
    )
    assert result["status"] == "escalated"
    assert result["scanner_failure_code"] == "scanner_unavailable"
    assert result["finding_refs"] == []
    assert result["failure_code"] == "scanner_failure:scanner_unavailable"


def test_postgres_checkpoint_boundary_rejects_sqlite_without_connecting() -> None:
    with pytest.raises(WorkflowConfigurationError, match="require PostgreSQL"):
        with postgres_checkpointer("sqlite+pysqlite:///:memory:"):
            raise AssertionError("unreachable")


def test_scan_evidence_contract_is_deterministic() -> None:
    digest = sha256(b"fixture").hexdigest()
    item = EvidenceItem(
        evidence_ref="scanner-fixture-1",
        kind="scan-summary",
        source="scanner-fixture",
        digest=digest,
        summary={"finding_count": 1},
    )
    result = ScanResult(evidence=(item,), finding_refs=("finding-1",))
    assert result.evidence[0].digest == digest
    assert result.failure_code is None


def test_checkpoint_rejects_secret_and_unsafe_references() -> None:
    state = _state("workflow-boundary")
    state["finding_refs"] = ["/var/www/api.securityola.com"]
    with pytest.raises(ValueError, match="outside the AppCare workflow boundary"):
        validate_checkpoint_state(state)

    state = _state("workflow-secret")
    state["ai_explanation_refs"] = ["Bearer abcdefghijklmnopqrst"]
    with pytest.raises(ValueError, match="credential-like"):
        validate_checkpoint_state(state)


def test_action_store_rejects_credential_like_state(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with pytest.raises(ValueError, match="credential-like"):
        WorkflowStore(database).run_action(
            tenant_id="tenant-1",
            workflow_id="workflow-secret",
            action_key="safe-action",
            action_kind="patch_test",
            state={"provider_token": "not-a-real-token"},
            adapter=RecordingAction(),
            max_attempts=1,
        )


def test_production_workflow_denies_without_authoritative_preproduction(tmp_path: Path) -> None:
    database = _database(tmp_path)
    action = RecordingAction()
    graph = build_workflow(
        WorkflowRuntime(WorkflowStore(database), action_adapter=action),
        build_in_memory_checkpointer(),
    )

    result = graph.invoke(
        _state("workflow-live-preview-blocked", target_environment="production"),
        {"configurable": {"thread_id": "workflow-live-preview-blocked"}},
    )

    assert result["status"] == "escalated"
    assert result["failure_code"] == "verified_preproduction_environment_required"
    assert not any(kind == "controlled_deploy" for _, kind in action.calls)


def test_production_workflow_requires_exact_preproduction_reference_and_artifact(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    action = RecordingAction()
    graph = build_workflow(
        WorkflowRuntime(
            WorkflowStore(database),
            action_adapter=action,
            preproduction_evidence_resolver=PermissivePreproductionResolver(),
        ),
        build_in_memory_checkpointer(),
    )

    missing_reference = graph.invoke(
        _state(
            "workflow-missing-preproduction-reference",
            target_environment="production",
        ),
        {"configurable": {"thread_id": "workflow-missing-preproduction-reference"}},
    )
    assert missing_reference["status"] == "escalated"
    assert missing_reference["failure_code"] == "verified_preproduction_environment_required"
    assert not any(kind == "controlled_deploy" for _, kind in action.calls)

    mismatched_artifact = graph.invoke(
        _state(
            "workflow-mismatched-preproduction-artifact",
            target_environment="production",
            preproduction_evidence_ref=PREPRODUCTION.authoritative_evidence_digest,
            artifact_digest="d" * 64,
        ),
        {"configurable": {"thread_id": "workflow-mismatched-preproduction-artifact"}},
    )
    assert mismatched_artifact["status"] == "escalated"
    assert mismatched_artifact["failure_code"] == "verified_preproduction_environment_required"
    assert not any(kind == "controlled_deploy" for _, kind in action.calls)
