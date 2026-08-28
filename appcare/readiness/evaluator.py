"""Deterministic, coordinator-gated readiness evaluation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Protocol

from .contracts import (
    LUNA_COORDINATOR_REF,
    CapabilityEvidence,
    CapabilityResult,
    CapabilityStatus,
    CoordinatorApproval,
    CoordinatorDecision,
    DowngradeResult,
    EvidenceClass,
    LayeredReadinessDecision,
    ReadinessDowngrade,
    ReadinessEvidence,
    ReadinessLevel,
    ReadinessStatus,
    ReadinessTier,
    ReadinessValidationError,
    SecurityGateDecision,
    SupportabilityDecision,
    SupportabilityStatus,
    evidence_class_at_least,
    validate_digest,
    validate_revision,
    validate_scope_segment,
)
from .registry import CapabilityRegistry


class ReadinessEvaluationError(ReadinessValidationError):
    """Raised when readiness input crosses a trust or identity boundary."""


class DowngradeStore(Protocol):
    """Append-only sink for readiness downgrade evidence."""

    def append(self, event: ReadinessDowngrade) -> ReadinessDowngrade: ...


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class SupportabilityEvaluator:
    """Resolve every mandatory capability for one exact application scope."""

    def __init__(self, registry: CapabilityRegistry | None = None) -> None:
        self.registry = registry or CapabilityRegistry()

    def evaluate(
        self,
        tenant_id: str,
        application_id: str,
        stack_id: str,
        evidence: Iterable[CapabilityEvidence],
        *,
        expected_source_revision: str | None = None,
        expected_artifact_digest: str | None = None,
        coordinator_approval: CoordinatorApproval | None = None,
        decided_at: datetime | None = None,
    ) -> SupportabilityDecision:
        tenant = validate_scope_segment(tenant_id, field_name="tenant_id")
        application = validate_scope_segment(application_id, field_name="application_id")
        stack = validate_scope_segment(stack_id, field_name="stack_id")
        if (expected_source_revision is None) != (expected_artifact_digest is None):
            raise ReadinessEvaluationError("expected revision and artifact digest must be paired")
        expected_revision = (
            validate_revision(expected_source_revision, field_name="expected_source_revision")
            if expected_source_revision is not None
            else None
        )
        expected_artifact = (
            validate_digest(expected_artifact_digest, field_name="expected_artifact_digest")
            if expected_artifact_digest is not None
            else None
        )
        required = self.registry.required_for(stack)
        required_names = {item.name for item in required}
        by_capability: dict[str, CapabilityEvidence] = {}
        for capability_evidence in evidence:
            if (
                capability_evidence.tenant_id != tenant
                or capability_evidence.application_id != application
                or capability_evidence.stack_id != stack
            ):
                raise ReadinessEvaluationError(
                    "cross-tenant or cross-application evidence rejected"
                )
            if capability_evidence.capability not in required_names:
                raise ReadinessEvaluationError("evidence names an unregistered capability")
            if capability_evidence.capability in by_capability:
                raise ReadinessEvaluationError("duplicate capability evidence rejected")
            by_capability[capability_evidence.capability] = capability_evidence

        results: list[CapabilityResult] = []
        blocking: list[str] = []
        cleanup: list[str] = []
        reasons: list[str] = []
        refs: list[str] = []
        for definition in required:
            evidence_for_capability = by_capability.get(definition.name)
            if evidence_for_capability is None:
                results.append(
                    CapabilityResult(
                        tenant_id=tenant,
                        application_id=application,
                        stack_id=stack,
                        capability=definition.name,
                        status=CapabilityStatus.MISSING_CAPABILITY,
                        evidence_class=None,
                        evidence_ref=None,
                        source_revision=None,
                        artifact_digest=None,
                        observed_at=None,
                        reason_codes=("missing_capability_evidence",),
                    )
                )
                blocking.append(definition.name)
                reasons.append("MISSING_MANDATORY_CAPABILITY")
                continue

            item_reasons: list[str] = []
            result_status = evidence_for_capability.status
            refs.append(evidence_for_capability.evidence_ref)
            if expected_revision is not None and (
                evidence_for_capability.source_revision != expected_revision
                or evidence_for_capability.artifact_digest != expected_artifact
            ):
                item_reasons.append("stale_or_mismatched_evidence")
            if not evidence_class_at_least(
                evidence_for_capability.evidence_class,
                definition.minimum_evidence_class,
            ):
                item_reasons.append("insufficient_evidence_class")
            if item_reasons:
                result_status = CapabilityStatus.BLOCKED_EXTERNAL
                blocking.append(definition.name)
                reasons.extend(item_reasons)
            elif evidence_for_capability.status in {
                CapabilityStatus.MISSING_CAPABILITY,
                CapabilityStatus.UNSUPPORTED,
                CapabilityStatus.BLOCKED_EXTERNAL,
            }:
                blocking.append(definition.name)
                reasons.append(f"{evidence_for_capability.status.value}_capability")
            elif evidence_for_capability.status == CapabilityStatus.NEEDS_CLEANUP:
                cleanup.append(definition.name)
                reasons.append("CAPABILITY_CLEANUP_REQUIRED")
            results.append(
                CapabilityResult(
                    tenant_id=tenant,
                    application_id=application,
                    stack_id=stack,
                    capability=definition.name,
                    status=result_status,
                    evidence_class=evidence_for_capability.evidence_class,
                    evidence_ref=evidence_for_capability.evidence_ref,
                    source_revision=evidence_for_capability.source_revision,
                    artifact_digest=evidence_for_capability.artifact_digest,
                    observed_at=evidence_for_capability.observed_at,
                    reason_codes=tuple(item_reasons),
                )
            )

        if blocking:
            supportability = SupportabilityStatus.UNSUPPORTED
        elif cleanup:
            supportability = SupportabilityStatus.NEEDS_CLEANUP
        else:
            supportability = SupportabilityStatus.SUPPORTED
        normalized_reasons = list(_unique(reasons))
        base = SupportabilityDecision(
            tenant_id=tenant,
            application_id=application,
            stack_id=stack,
            status=supportability,
            mandatory_capability_digest=self.registry.mandatory_digest(stack),
            capability_results=tuple(results),
            blocking_capabilities=tuple(blocking),
            cleanup_capabilities=tuple(cleanup),
            evidence_refs=tuple(refs),
            reason_codes=tuple(normalized_reasons),
            decided_at=decided_at or datetime.now(UTC),
        )
        assessment_digest = base.assessment_digest
        if coordinator_approval is None:
            return replace(
                base,
                reason_codes=_unique((*base.reason_codes, "COORDINATOR_APPROVAL_REQUIRED")),
            )
        if coordinator_approval.evidence_digest != assessment_digest:
            return replace(
                base,
                coordinator=coordinator_approval.coordinator_ref,
                coordinator_decision=CoordinatorDecision.REJECT,
                reason_codes=_unique((*base.reason_codes, "COORDINATOR_APPROVAL_BINDING_MISMATCH")),
            )
        if coordinator_approval.decision != CoordinatorDecision.APPROVE:
            return replace(
                base,
                coordinator=coordinator_approval.coordinator_ref,
                coordinator_decision=coordinator_approval.decision,
                reason_codes=_unique((*base.reason_codes, "COORDINATOR_REJECTED")),
            )
        return replace(
            base,
            coordinator=LUNA_COORDINATOR_REF,
            coordinator_decision=CoordinatorDecision.APPROVE,
        )

    @staticmethod
    def approve(
        decision: SupportabilityDecision,
        *,
        approved_at: datetime | None = None,
    ) -> CoordinatorApproval:
        """Create the explicit Luna approval after the coordinator reviewed it."""

        if decision.status != SupportabilityStatus.SUPPORTED:
            raise ReadinessEvaluationError("cannot approve unsupported application scope")
        return CoordinatorApproval.for_luna(
            decision.assessment_digest,
            approved_at=approved_at,
        )


_LEVEL_ORDER = (
    ReadinessTier.CORE,
    ReadinessTier.STACK,
    ReadinessTier.CUSTOMER_ONBOARDING,
    ReadinessTier.PILOT,
    ReadinessTier.PAID_SERVICE,
)
_MINIMUM_CLASS = {
    ReadinessTier.CORE: EvidenceClass.FIXTURE,
    ReadinessTier.STACK: EvidenceClass.FIXTURE,
    ReadinessTier.CUSTOMER_ONBOARDING: EvidenceClass.REAL_TARGET,
    ReadinessTier.PILOT: EvidenceClass.REAL_TARGET,
    ReadinessTier.PAID_SERVICE: EvidenceClass.REAL_TARGET,
}
_REQUIRED_KINDS = {
    ReadinessTier.CUSTOMER_ONBOARDING: frozenset({"preproduction"}),
    ReadinessTier.PILOT: frozenset(
        {
            "production",
            "verification",
            "rollback",
            "monitoring",
            "alerting",
            "reporting",
            "restart_durability",
            "cost_measurement",
        }
    ),
    ReadinessTier.PAID_SERVICE: frozenset(
        {
            "sustained_operation",
            "operator_workflow",
            "customer_dashboard",
            "offboarding",
            "credential_rotation",
            "cost_controls",
            "disaster_recovery",
        }
    ),
}


class ReadinessEvaluator:
    """Evaluate layers independently while enforcing lower-layer prerequisites."""

    def __init__(self, registry: CapabilityRegistry | None = None) -> None:
        self.registry = registry or CapabilityRegistry()

    @staticmethod
    def assessment_digest(
        levels: Sequence[ReadinessLevel],
        *,
        evidence: Sequence[ReadinessEvidence] = (),
        supportability: SupportabilityDecision | None = None,
        security_gate: SecurityGateDecision | None = None,
        candidate_sha: str | None = None,
    ) -> str:
        payload: dict[str, object] = {
            "levels": [item.canonical_payload() for item in levels],
            "evidence": [item.canonical_payload() for item in evidence],
            "supportability": supportability.assessment_digest if supportability else None,
            "security_gate": security_gate.evidence_digest if security_gate else None,
            "candidate_sha": validate_revision(candidate_sha, field_name="candidate_sha")
            if candidate_sha
            else None,
        }
        return _digest(payload)

    def evaluate(
        self,
        levels: Iterable[ReadinessLevel],
        *,
        tenant_id: str | None = None,
        application_id: str | None = None,
        stack_id: str | None = None,
        evidence: Iterable[ReadinessEvidence] = (),
        supportability: SupportabilityDecision | None = None,
        security_gate: SecurityGateDecision | None = None,
        candidate_sha: str | None = None,
        coordinator_approval: CoordinatorApproval | None = None,
        evaluated_at: datetime | None = None,
    ) -> LayeredReadinessDecision:
        raw_levels = tuple(levels)
        by_level: dict[ReadinessTier, ReadinessLevel] = {}
        for level in raw_levels:
            if level.level in by_level:
                raise ReadinessEvaluationError("readiness levels must be unique")
            by_level[level.level] = level
        normalized_evidence = tuple(evidence)
        tenant = tenant_id.strip() if tenant_id is not None else None
        application = application_id.strip() if application_id is not None else None
        stack = stack_id.strip() if stack_id is not None else None
        if tenant is not None:
            tenant = validate_scope_segment(tenant, field_name="tenant_id")
        if application is not None:
            application = validate_scope_segment(application, field_name="application_id")
        if stack is not None:
            stack = validate_scope_segment(stack, field_name="stack_id")
        if (tenant is None) != (application is None):
            raise ReadinessEvaluationError("tenant and application scope must be paired")
        if supportability is not None:
            if tenant is None or application is None:
                raise ReadinessEvaluationError("scoped supportability requires application scope")
            if stack is None:
                raise ReadinessEvaluationError("scoped supportability requires stack scope")
            if (
                supportability.tenant_id != tenant
                or supportability.application_id != application
                or supportability.stack_id != stack
            ):
                raise ReadinessEvaluationError("supportability evidence crosses readiness scope")
        elif normalized_evidence and (tenant is None or application is None):
            raise ReadinessEvaluationError("scoped readiness evidence requires application scope")
        for readiness_evidence in normalized_evidence:
            if tenant is not None and (
                readiness_evidence.tenant_id != tenant
                or readiness_evidence.application_id != application
            ):
                raise ReadinessEvaluationError(
                    "readiness evidence crosses tenant/application scope"
                )
        candidate = (
            validate_revision(candidate_sha, field_name="candidate_sha")
            if candidate_sha is not None
            else None
        )
        security_gate_mismatch = (
            candidate is None
            or security_gate is None
            or security_gate.release_candidate_sha != candidate
        )
        evidence_by_ref: dict[str, ReadinessEvidence] = {}
        for readiness_evidence in normalized_evidence:
            if readiness_evidence.evidence_ref in evidence_by_ref:
                raise ReadinessEvaluationError("duplicate readiness evidence reference")
            evidence_by_ref[readiness_evidence.evidence_ref] = readiness_evidence

        base_digest = self.assessment_digest(
            raw_levels,
            evidence=normalized_evidence,
            supportability=supportability,
            security_gate=security_gate,
            candidate_sha=candidate,
        )
        output: dict[ReadinessTier, ReadinessLevel] = {}
        global_reasons: list[str] = []
        now = evaluated_at or datetime.now(UTC)
        for tier in _LEVEL_ORDER:
            raw = by_level.get(tier)
            if raw is None:
                output[tier] = ReadinessLevel(
                    level=tier,
                    scope=stack or application or "global",
                    status=ReadinessStatus.BLOCKED,
                    evidence_refs=(),
                    evaluated_at=now,
                    evaluator="readiness-evaluator",
                    reason_codes=("READINESS_EVIDENCE_REQUIRED",),
                )
                global_reasons.append("READINESS_EVIDENCE_REQUIRED")
                continue
            reasons = list(raw.reason_codes)
            status = raw.status
            allowed_scopes = {"global"}
            if application is not None:
                allowed_scopes.add(application)
            if stack is not None:
                allowed_scopes.add(stack)
            if raw.scope not in allowed_scopes:
                reasons.append("READINESS_SCOPE_MISMATCH")
                status = ReadinessStatus.BLOCKED
            if status == ReadinessStatus.READY:
                if candidate is not None and raw.exact_head != candidate:
                    reasons.append("STALE_READINESS_REVISION")
                if tier in {
                    ReadinessTier.CUSTOMER_ONBOARDING,
                    ReadinessTier.PILOT,
                    ReadinessTier.PAID_SERVICE,
                } and (
                    candidate is None or raw.exact_head != candidate or raw.artifact_digest is None
                ):
                    reasons.append("READINESS_EXACT_HEAD_REQUIRED")
                if (
                    not raw.evidence_refs
                    or len(raw.evidence_refs) != len(raw.evidence_classes)
                    or len(raw.evidence_refs) != len(raw.evidence_kinds)
                ):
                    reasons.append("READINESS_EVIDENCE_REQUIRED")
                    status = ReadinessStatus.BLOCKED
                else:
                    matched: list[ReadinessEvidence] = []
                    for ref in raw.evidence_refs:
                        matched_evidence = evidence_by_ref.get(ref)
                        if matched_evidence is None or matched_evidence.level != tier:
                            reasons.append("READINESS_EVIDENCE_REFERENCE_INVALID")
                            continue
                        if not matched_evidence.passed:
                            reasons.append("READINESS_EVIDENCE_FAILED")
                        if candidate is not None and matched_evidence.source_revision != candidate:
                            reasons.append("STALE_READINESS_REVISION")
                        if (
                            raw.artifact_digest is not None
                            and matched_evidence.artifact_digest != raw.artifact_digest
                        ):
                            reasons.append("READINESS_ARTIFACT_MISMATCH")
                        if tier in {
                            ReadinessTier.CUSTOMER_ONBOARDING,
                            ReadinessTier.PILOT,
                            ReadinessTier.PAID_SERVICE,
                        } and (
                            matched_evidence.source_revision is None
                            or matched_evidence.artifact_digest is None
                        ):
                            reasons.append("READINESS_EXACT_HEAD_REQUIRED")
                        matched.append(matched_evidence)
                    if len(matched) != len(raw.evidence_refs):
                        status = ReadinessStatus.BLOCKED
                    if tuple(item.evidence_class for item in matched) != raw.evidence_classes:
                        reasons.append("READINESS_EVIDENCE_CLASS_MISMATCH")
                    if tuple(item.kind for item in matched) != raw.evidence_kinds:
                        reasons.append("READINESS_EVIDENCE_KIND_MISMATCH")
                    required_class = _MINIMUM_CLASS[tier]
                    if any(
                        not evidence_class_at_least(item.evidence_class, required_class)
                        for item in matched
                    ):
                        reasons.append("READINESS_EVIDENCE_CLASS_INSUFFICIENT")
                    required_kinds = _REQUIRED_KINDS.get(tier, frozenset())
                    if required_kinds and not required_kinds.issubset(
                        {item.kind for item in matched}
                    ):
                        reasons.append("READINESS_EVIDENCE_KINDS_INCOMPLETE")
                    if any(
                        reason
                        in {
                            "READINESS_EVIDENCE_FAILED",
                            "STALE_READINESS_REVISION",
                            "READINESS_ARTIFACT_MISMATCH",
                            "READINESS_EVIDENCE_CLASS_INSUFFICIENT",
                            "READINESS_EVIDENCE_KINDS_INCOMPLETE",
                            "READINESS_EXACT_HEAD_REQUIRED",
                            "READINESS_EVIDENCE_CLASS_MISMATCH",
                            "READINESS_EVIDENCE_KIND_MISMATCH",
                        }
                        for reason in reasons
                    ):
                        status = ReadinessStatus.BLOCKED
            prerequisite = {
                ReadinessTier.STACK: ReadinessTier.CORE,
                ReadinessTier.CUSTOMER_ONBOARDING: ReadinessTier.STACK,
                ReadinessTier.PILOT: ReadinessTier.CUSTOMER_ONBOARDING,
                ReadinessTier.PAID_SERVICE: ReadinessTier.PILOT,
            }.get(tier)
            if prerequisite is not None and output[prerequisite].status != ReadinessStatus.READY:
                if status == ReadinessStatus.READY:
                    status = ReadinessStatus.BLOCKED
                reasons.append("LOWER_READINESS_REQUIRED")
            supportability_ready = False
            if supportability is not None:
                expected_capabilities = set(self.registry.mandatory_capabilities)
                actual_capabilities = {
                    result.capability for result in supportability.capability_results
                }
                supportability_ready = (
                    supportability.authoritative
                    and supportability.status == SupportabilityStatus.SUPPORTED
                    and supportability.stack_id == (stack or supportability.stack_id)
                    and supportability.mandatory_capability_digest
                    == self.registry.mandatory_digest(supportability.stack_id)
                    and actual_capabilities == expected_capabilities
                    and len(supportability.capability_results) == len(expected_capabilities)
                    and all(
                        result.tenant_id == tenant
                        and result.application_id == application
                        and result.stack_id == supportability.stack_id
                        and result.capability in expected_capabilities
                        and result.status == CapabilityStatus.SUPPORTED
                        and result.evidence_class is not None
                        and evidence_class_at_least(
                            result.evidence_class,
                            self.registry.definition(result.capability).minimum_evidence_class,
                        )
                        for result in supportability.capability_results
                    )
                    and all(
                        result.evidence_class is not None and result.evidence_ref is not None
                        for result in supportability.capability_results
                    )
                    and all(
                        candidate is None
                        or (
                            result.source_revision == candidate
                            and result.artifact_digest is not None
                        )
                        for result in supportability.capability_results
                    )
                )
            if tier == ReadinessTier.STACK and not supportability_ready:
                if status == ReadinessStatus.READY:
                    status = ReadinessStatus.BLOCKED
                reasons.append("AUTHORITATIVE_SUPPORTABILITY_REQUIRED")
            if tier in {
                ReadinessTier.CUSTOMER_ONBOARDING,
                ReadinessTier.PILOT,
                ReadinessTier.PAID_SERVICE,
            }:
                if security_gate is None or not security_gate.passed or security_gate_mismatch:
                    if status == ReadinessStatus.READY:
                        status = ReadinessStatus.BLOCKED
                    reasons.append("PRE_BETA_SECURITY_GATE_REQUIRED")
            output[tier] = replace(
                raw,
                status=status,
                reason_codes=_unique(reasons),
                coordinator_decision=(
                    CoordinatorDecision.BLOCKED
                    if status != ReadinessStatus.READY
                    else CoordinatorDecision.APPROVE
                ),
            )
            global_reasons.extend(reasons)

        all_levels_ready = all(item.status == ReadinessStatus.READY for item in output.values())
        approval_ok = (
            coordinator_approval is not None
            and coordinator_approval.decision == CoordinatorDecision.APPROVE
            and coordinator_approval.evidence_digest == base_digest
            and all_levels_ready
        )
        if coordinator_approval is None:
            global_reasons.append("COORDINATOR_APPROVAL_REQUIRED")
        elif not approval_ok:
            global_reasons.append("COORDINATOR_APPROVAL_BINDING_MISMATCH")
        if not approval_ok:
            output = {
                tier: replace(
                    item,
                    status=(
                        ReadinessStatus.BLOCKED
                        if item.status == ReadinessStatus.READY
                        else item.status
                    ),
                    reason_codes=_unique((*item.reason_codes, "COORDINATOR_APPROVAL_REQUIRED")),
                    coordinator_decision=CoordinatorDecision.BLOCKED,
                )
                for tier, item in output.items()
            }
        else:
            output = {
                tier: replace(item, coordinator_decision=CoordinatorDecision.APPROVE)
                for tier, item in output.items()
            }
        normalized_global = _unique(global_reasons)
        return LayeredReadinessDecision(
            levels=tuple(output[tier] for tier in _LEVEL_ORDER),
            evidence_digest=base_digest,
            tenant_id=tenant,
            application_id=application,
            stack_id=stack,
            reason_codes=normalized_global,
            coordinator_decision=(
                CoordinatorDecision.APPROVE if approval_ok else CoordinatorDecision.BLOCKED
            ),
            coordinator=LUNA_COORDINATOR_REF if approval_ok else None,
        )

    @staticmethod
    def approve(
        decision: LayeredReadinessDecision,
        *,
        approved_at: datetime | None = None,
    ) -> CoordinatorApproval:
        if any(item.status != ReadinessStatus.READY for item in decision.levels):
            raise ReadinessEvaluationError("cannot approve blocked readiness decision")
        return CoordinatorApproval.for_luna(decision.evidence_digest, approved_at=approved_at)

    def apply_downgrade(
        self,
        decision: LayeredReadinessDecision,
        trigger: CapabilityEvidence,
        *,
        audit_store: DowngradeStore,
        recorded_at: datetime | None = None,
    ) -> DowngradeResult:
        if (
            decision.tenant_id is None
            or decision.application_id is None
            or decision.stack_id is None
        ):
            raise ReadinessEvaluationError("downgrade requires application-scoped readiness")
        if (
            trigger.tenant_id != decision.tenant_id
            or trigger.application_id != decision.application_id
            or trigger.stack_id != decision.stack_id
        ):
            raise ReadinessEvaluationError("downgrade trigger crosses readiness scope")
        if trigger.evidence_class != EvidenceClass.REAL_TARGET:
            return DowngradeResult(decision=decision, events=())
        if trigger.status not in {
            CapabilityStatus.MISSING_CAPABILITY,
            CapabilityStatus.UNSUPPORTED,
            CapabilityStatus.BLOCKED_EXTERNAL,
        }:
            return DowngradeResult(decision=decision, events=())
        if not self.registry.contains(trigger.capability):
            raise ReadinessEvaluationError("downgrade trigger is not a mandatory capability")
        affected = {
            f"{trigger.tenant_id}:{trigger.application_id}:{trigger.stack_id}",
            trigger.capability,
        }
        output: list[ReadinessLevel] = []
        events: list[ReadinessDowngrade] = []
        when = recorded_at or datetime.now(UTC)
        for item in decision.levels:
            if (
                item.level
                not in {
                    ReadinessTier.STACK,
                    ReadinessTier.CUSTOMER_ONBOARDING,
                    ReadinessTier.PILOT,
                    ReadinessTier.PAID_SERVICE,
                }
                or item.status == ReadinessStatus.BLOCKED
            ):
                output.append(item)
                continue
            event = ReadinessDowngrade(
                previous_level=item.level,
                previous_status=item.status,
                new_status=ReadinessStatus.BLOCKED,
                trigger_capability=trigger.capability,
                trigger_evidence_ref=trigger.evidence_ref,
                affected_scopes=tuple(sorted(affected)),
                reason_code="MANDATORY_REAL_TARGET_CAPABILITY_MISSING",
                recorded_at=when,
                tenant_id=trigger.tenant_id,
                application_id=trigger.application_id,
                stack_id=trigger.stack_id,
            )
            audit_store.append(event)
            events.append(event)
            output.append(
                replace(
                    item,
                    status=ReadinessStatus.BLOCKED,
                    reason_codes=_unique(
                        (*item.reason_codes, "MANDATORY_REAL_TARGET_CAPABILITY_MISSING")
                    ),
                    coordinator_decision=CoordinatorDecision.BLOCKED,
                )
            )
        downgraded = replace(
            decision,
            levels=tuple(output),
            reason_codes=_unique((*decision.reason_codes, "READINESS_DOWNGRADED")),
            coordinator_decision=CoordinatorDecision.BLOCKED,
            coordinator=None,
        )
        return DowngradeResult(decision=downgraded, events=tuple(events))


__all__ = [
    "DowngradeStore",
    "ReadinessEvaluationError",
    "ReadinessEvaluator",
    "SupportabilityEvaluator",
]
