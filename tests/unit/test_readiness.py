"""Spec 013 readiness, provenance, and fail-closed negative tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from appcare.readiness import (
    LUNA_COORDINATOR_REF,
    REQUIRED_SECURITY_GATE_IDS,
    CapabilityEvidence,
    CapabilityStatus,
    CoordinatorApproval,
    CoordinatorDecision,
    EvidenceClass,
    InMemoryReadinessDowngradeStore,
    LayeredReadinessDecision,
    ReadinessEvaluationError,
    ReadinessEvaluator,
    ReadinessEvidence,
    ReadinessLevel,
    ReadinessStatus,
    ReadinessTier,
    ReadinessValidationError,
    SecurityGateDecision,
    SupportabilityDecision,
    SupportabilityEvaluator,
    SupportabilityStatus,
    default_capability_registry,
    validate_evidence_reference,
    validate_scope_segment,
)

REVISION = "a" * 40
ARTIFACT = "b" * 64
STAMP = datetime(2026, 8, 27, tzinfo=UTC)
TENANT = "tenant-a"
APPLICATION = "application-a"
STACK = "linux-ssh"


def _capability_evidence(
    capability: str,
    *,
    status: CapabilityStatus = CapabilityStatus.SUPPORTED,
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE,
    tenant_id: str = TENANT,
    application_id: str = APPLICATION,
    source_revision: str | None = REVISION,
    artifact_digest: str | None = ARTIFACT,
) -> CapabilityEvidence:
    return CapabilityEvidence(
        tenant_id=tenant_id,
        application_id=application_id,
        stack_id=STACK,
        capability=capability,
        status=status,
        evidence_class=evidence_class,
        evidence_ref=f"capability-{capability}",
        observed_at=STAMP,
        source_revision=source_revision,
        artifact_digest=artifact_digest,
    )


def _all_capabilities() -> tuple[CapabilityEvidence, ...]:
    return tuple(
        _capability_evidence(name) for name in default_capability_registry().mandatory_capabilities
    )


def _supportability() -> SupportabilityDecision:
    evaluator = SupportabilityEvaluator()
    pending = evaluator.evaluate(
        TENANT,
        APPLICATION,
        STACK,
        _all_capabilities(),
        expected_source_revision=REVISION,
        expected_artifact_digest=ARTIFACT,
    )
    approval = SupportabilityEvaluator.approve(pending)
    return evaluator.evaluate(
        TENANT,
        APPLICATION,
        STACK,
        _all_capabilities(),
        expected_source_revision=REVISION,
        expected_artifact_digest=ARTIFACT,
        coordinator_approval=approval,
    )


def _layer_evidence(
    *,
    onboarding_class: EvidenceClass = EvidenceClass.REAL_TARGET,
    onboarding_passed: bool = True,
    source_revision: str | None = REVISION,
    artifact_digest: str | None = ARTIFACT,
) -> tuple[ReadinessEvidence, ...]:
    definitions = [
        (ReadinessTier.CORE, "core", EvidenceClass.FIXTURE),
        (ReadinessTier.STACK, "stack", EvidenceClass.FIXTURE),
        (ReadinessTier.CUSTOMER_ONBOARDING, "preproduction", onboarding_class),
        (ReadinessTier.PILOT, "production", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "verification", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "rollback", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "monitoring", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "alerting", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "reporting", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "restart_durability", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PILOT, "cost_measurement", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "sustained_operation", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "operator_workflow", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "customer_dashboard", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "offboarding", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "credential_rotation", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "cost_controls", EvidenceClass.REAL_TARGET),
        (ReadinessTier.PAID_SERVICE, "disaster_recovery", EvidenceClass.REAL_TARGET),
    ]
    return tuple(
        ReadinessEvidence(
            tenant_id=TENANT,
            application_id=APPLICATION,
            level=level,
            evidence_ref=f"readiness-{level.value}-{kind}",
            evidence_class=(
                onboarding_class if level == ReadinessTier.CUSTOMER_ONBOARDING else evidence_class
            ),
            passed=(onboarding_passed if level == ReadinessTier.CUSTOMER_ONBOARDING else True),
            observed_at=STAMP,
            source_revision=source_revision,
            artifact_digest=artifact_digest,
            kind=kind,
        )
        for level, kind, evidence_class in definitions
    )


def _levels(evidence: tuple[ReadinessEvidence, ...]) -> tuple[ReadinessLevel, ...]:
    grouped: dict[ReadinessTier, list[ReadinessEvidence]] = {}
    for item in evidence:
        grouped.setdefault(item.level, []).append(item)
    return tuple(
        ReadinessLevel(
            level=level,
            scope=APPLICATION,
            status=ReadinessStatus.READY,
            evidence_refs=tuple(item.evidence_ref for item in grouped[level]),
            evidence_classes=tuple(item.evidence_class for item in grouped[level]),
            evidence_kinds=tuple(item.kind for item in grouped[level]),
            evaluated_at=STAMP,
            evaluator="luna-review",
            exact_head=REVISION,
            artifact_digest=ARTIFACT,
            coordinator_decision=CoordinatorDecision.APPROVE,
        )
        for level in ReadinessTier
    )


def _security_gate() -> SecurityGateDecision:
    return SecurityGateDecision(
        release_candidate_sha=REVISION,
        gate_version="s01-s30",
        individual_gate_results={item: True for item in REQUIRED_SECURITY_GATE_IDS},
        security_findings_open=0,
        codex_security_refs=("codex-security-r14",),
        dependency_audit_ref="dependency-r14",
        secret_scan_ref="scan-r14",  # noqa: S106 - opaque non-secret receipt reference
        graphify_ref="graphify-r14",
        saveruflo_ref="saveruflo-r14",
        exact_head_ci_ref="ci-r14",
        real_target_security_ref="target-security-r14",
        known_limitations_ref="limitations-r14",
        coordinator_decision=CoordinatorDecision.APPROVE,
        decided_at=STAMP,
    )


def _full_decision(
    *,
    evidence: tuple[ReadinessEvidence, ...] | None = None,
    security_gate: SecurityGateDecision | None = None,
    with_security_gate: bool = True,
    approval: bool = True,
) -> LayeredReadinessDecision:
    layer_evidence = evidence or _layer_evidence()
    supportability = _supportability()
    levels = _levels(layer_evidence)
    evaluator = ReadinessEvaluator()
    gate = (
        security_gate
        if security_gate is not None
        else (_security_gate() if with_security_gate else None)
    )
    approval_object = None
    if approval:
        digest = evaluator.assessment_digest(
            levels,
            evidence=layer_evidence,
            supportability=supportability,
            security_gate=gate,
            candidate_sha=REVISION,
        )
        approval_object = CoordinatorApproval.for_luna(digest, approved_at=STAMP)
    return evaluator.evaluate(
        levels,
        tenant_id=TENANT,
        application_id=APPLICATION,
        stack_id=STACK,
        evidence=layer_evidence,
        supportability=supportability,
        security_gate=gate,
        candidate_sha=REVISION,
        coordinator_approval=approval_object,
        evaluated_at=STAMP,
    )


def test_capability_registry_is_complete_and_scope_bound() -> None:
    registry = default_capability_registry()
    assert len(registry.mandatory_capabilities) == 22
    scoped = registry
    assert scoped.contains("filesystem_backup")
    with pytest.raises(ReadinessValidationError):
        validate_scope_segment("../tenant", field_name="tenant_id")
    with pytest.raises(ReadinessValidationError):
        validate_scope_segment("wordpress/secret", field_name="application_id")
    with pytest.raises(ReadinessValidationError):
        validate_evidence_reference("/var/www/secret", field_name="evidence_ref")


def test_supportability_missing_capability_is_blocked_and_not_approvable() -> None:
    evaluator = SupportabilityEvaluator()
    pending = evaluator.evaluate(TENANT, APPLICATION, STACK, ())
    assert pending.status == SupportabilityStatus.UNSUPPORTED
    assert pending.coordinator_decision == CoordinatorDecision.BLOCKED
    assert pending.authoritative is False
    assert pending.blocking_capabilities
    with pytest.raises(ReadinessEvaluationError):
        SupportabilityEvaluator.approve(pending)


def test_supportability_rejects_cross_tenant_evidence() -> None:
    evidence = _all_capabilities()
    foreign = replace(evidence[0], tenant_id="tenant-b")
    with pytest.raises(ReadinessEvaluationError):
        SupportabilityEvaluator().evaluate(TENANT, APPLICATION, STACK, (foreign, *evidence[1:]))


def test_fixture_only_evidence_cannot_make_customer_onboarding_ready() -> None:
    evidence = _layer_evidence(onboarding_class=EvidenceClass.FIXTURE)
    decision = _full_decision(evidence=evidence)
    onboarding = decision.for_level(ReadinessTier.CUSTOMER_ONBOARDING)
    assert onboarding.status == ReadinessStatus.BLOCKED
    assert "READINESS_EVIDENCE_CLASS_INSUFFICIENT" in onboarding.reason_codes
    assert decision.authoritative is False


def test_worker_claimed_approval_does_not_authorize_readiness() -> None:
    decision = _full_decision(approval=False)
    assert decision.coordinator_decision == CoordinatorDecision.BLOCKED
    assert decision.authoritative is False
    assert all(item.status == ReadinessStatus.BLOCKED for item in decision.levels)


def test_missing_security_gate_blocks_customer_layers() -> None:
    decision = _full_decision(with_security_gate=False, approval=False)
    assert decision.for_level(ReadinessTier.CUSTOMER_ONBOARDING).status == ReadinessStatus.BLOCKED
    assert "PRE_BETA_SECURITY_GATE_REQUIRED" in decision.reason_codes


def test_stale_readiness_revision_is_rejected() -> None:
    evidence = _layer_evidence()
    stale = replace(
        evidence[0],
        source_revision="c" * 40,
        artifact_digest=ARTIFACT,
    )
    decision = _full_decision(evidence=(stale, *evidence[1:]))
    assert decision.for_level(ReadinessTier.CORE).status == ReadinessStatus.BLOCKED
    assert "STALE_READINESS_REVISION" in decision.reason_codes


def test_readiness_requires_matching_class_and_kind_metadata() -> None:
    evidence = _layer_evidence()
    levels = _levels(evidence)
    tampered = replace(
        levels[0],
        evidence_classes=(EvidenceClass.REAL_TARGET,),
        evidence_kinds=("wrong-kind",),
    )
    raw_levels = (tampered, *levels[1:])
    evaluator = ReadinessEvaluator()
    supportability = _supportability()
    gate = _security_gate()
    digest = evaluator.assessment_digest(
        raw_levels,
        evidence=evidence,
        supportability=supportability,
        security_gate=gate,
        candidate_sha=REVISION,
    )
    decision = evaluator.evaluate(
        raw_levels,
        tenant_id=TENANT,
        application_id=APPLICATION,
        stack_id=STACK,
        evidence=evidence,
        supportability=supportability,
        security_gate=gate,
        candidate_sha=REVISION,
        coordinator_approval=CoordinatorApproval.for_luna(digest, approved_at=STAMP),
    )
    assert decision.for_level(ReadinessTier.CORE).status == ReadinessStatus.BLOCKED


def test_readiness_level_requires_paired_exact_head_and_artifact() -> None:
    with pytest.raises(ReadinessValidationError):
        ReadinessLevel(
            level=ReadinessTier.CUSTOMER_ONBOARDING,
            scope=APPLICATION,
            status=ReadinessStatus.READY,
            evidence_refs=("preproduction",),
            evaluated_at=STAMP,
            evaluator="luna-review",
            exact_head=REVISION,
        )


def test_stale_level_revision_blocks_even_matching_evidence() -> None:
    evidence = _layer_evidence()
    levels = _levels(evidence)
    stale = replace(levels[2], exact_head="c" * 40)
    raw_levels = (levels[0], levels[1], stale, *levels[3:])
    evaluator = ReadinessEvaluator()
    supportability = _supportability()
    gate = _security_gate()
    digest = evaluator.assessment_digest(
        raw_levels,
        evidence=evidence,
        supportability=supportability,
        security_gate=gate,
        candidate_sha=REVISION,
    )
    decision = evaluator.evaluate(
        raw_levels,
        tenant_id=TENANT,
        application_id=APPLICATION,
        stack_id=STACK,
        evidence=evidence,
        supportability=supportability,
        security_gate=gate,
        candidate_sha=REVISION,
        coordinator_approval=CoordinatorApproval.for_luna(digest, approved_at=STAMP),
    )
    onboarding = decision.for_level(ReadinessTier.CUSTOMER_ONBOARDING)
    assert onboarding.status == ReadinessStatus.BLOCKED
    assert "STALE_READINESS_REVISION" in onboarding.reason_codes


def test_unapproved_level_prevents_direct_authority_claim() -> None:
    decision = _full_decision()
    tampered_level = replace(
        decision.for_level(ReadinessTier.PILOT),
        coordinator_decision=CoordinatorDecision.BLOCKED,
    )
    tampered = replace(
        decision,
        levels=tuple(
            tampered_level if item.level == ReadinessTier.PILOT else item
            for item in decision.levels
        ),
    )
    assert tampered.authoritative is False


def test_candidate_requires_exact_supportability_evidence() -> None:
    unbound_evidence = tuple(
        _capability_evidence(name, source_revision=None, artifact_digest=None)
        for name in default_capability_registry().mandatory_capabilities
    )
    supportability_evaluator = SupportabilityEvaluator()
    pending = supportability_evaluator.evaluate(TENANT, APPLICATION, STACK, unbound_evidence)
    unbound_supportability = supportability_evaluator.evaluate(
        TENANT,
        APPLICATION,
        STACK,
        unbound_evidence,
        coordinator_approval=SupportabilityEvaluator.approve(pending),
    )
    evidence = _layer_evidence()
    evaluator = ReadinessEvaluator()
    gate = _security_gate()
    levels = _levels(evidence)
    digest = evaluator.assessment_digest(
        levels,
        evidence=evidence,
        supportability=unbound_supportability,
        security_gate=gate,
        candidate_sha=REVISION,
    )
    decision = evaluator.evaluate(
        levels,
        tenant_id=TENANT,
        application_id=APPLICATION,
        stack_id=STACK,
        evidence=evidence,
        supportability=unbound_supportability,
        security_gate=gate,
        candidate_sha=REVISION,
        coordinator_approval=CoordinatorApproval.for_luna(digest, approved_at=STAMP),
    )
    assert decision.for_level(ReadinessTier.STACK).status == ReadinessStatus.BLOCKED


def test_real_target_capability_failure_automatically_downgrades_layers() -> None:
    decision = _full_decision()
    trigger = _capability_evidence(
        "deploy",
        status=CapabilityStatus.BLOCKED_EXTERNAL,
        evidence_class=EvidenceClass.REAL_TARGET,
    )
    store = InMemoryReadinessDowngradeStore()
    result = ReadinessEvaluator().apply_downgrade(
        decision,
        trigger,
        audit_store=store,
        recorded_at=STAMP,
    )
    assert len(result.events) == 4
    assert len(store.events) == 4
    assert result.decision.authoritative is False
    assert result.decision.for_level(ReadinessTier.STACK).status == ReadinessStatus.BLOCKED
    assert result.decision.for_level(ReadinessTier.PAID_SERVICE).status == ReadinessStatus.BLOCKED


def test_fixture_failure_does_not_downgrade_real_target_readiness() -> None:
    decision = _full_decision()
    trigger = _capability_evidence(
        "deploy",
        status=CapabilityStatus.BLOCKED_EXTERNAL,
        evidence_class=EvidenceClass.FIXTURE,
    )
    store = InMemoryReadinessDowngradeStore()
    result = ReadinessEvaluator().apply_downgrade(decision, trigger, audit_store=store)
    assert result.events == ()
    assert store.events == ()
    assert result.decision.authoritative


def test_security_gate_requires_all_thirty_gates_and_zero_findings() -> None:
    gate = _security_gate()
    incomplete = replace(
        gate,
        individual_gate_results={item: True for item in REQUIRED_SECURITY_GATE_IDS[:-1]},
    )
    assert incomplete.passed is False
    assert incomplete.missing_gate_ids == REQUIRED_SECURITY_GATE_IDS[-1:]
    findings = replace(gate, security_findings_open=1)
    assert findings.passed is False


def test_security_gate_requires_authoritative_receipt_references() -> None:
    missing_receipt = replace(_security_gate(), exact_head_ci_ref=None)
    assert missing_receipt.passed is False
    missing_codex = replace(_security_gate(), codex_security_refs=())
    assert missing_codex.passed is False


def test_incomplete_layer_set_cannot_claim_authority() -> None:
    decision = LayeredReadinessDecision(
        levels=(),
        evidence_digest=ARTIFACT,
        coordinator=LUNA_COORDINATOR_REF,
        coordinator_decision=CoordinatorDecision.APPROVE,
    )
    assert decision.authoritative is False


def test_coordinator_identity_is_narrow_and_approval_digest_is_bound() -> None:
    with pytest.raises(ReadinessValidationError):
        CoordinatorApproval(
            coordinator_ref="worker-model",
            decision=CoordinatorDecision.APPROVE,
            evidence_digest=ARTIFACT,
            approved_at=STAMP,
        )
    decision = _full_decision()
    wrong = CoordinatorApproval.for_luna("c" * 64, approved_at=STAMP)
    evaluator = ReadinessEvaluator()
    evidence = _layer_evidence()
    levels = _levels(evidence)
    result = evaluator.evaluate(
        levels,
        tenant_id=TENANT,
        application_id=APPLICATION,
        stack_id=STACK,
        evidence=evidence,
        supportability=_supportability(),
        security_gate=_security_gate(),
        candidate_sha=REVISION,
        coordinator_approval=wrong,
    )
    assert result.authoritative is False
    assert decision.authoritative
