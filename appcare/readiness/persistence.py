"""Append-only readiness evidence sinks."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    Application,
    CapabilityEvidenceRecord,
    ReadinessDowngradeRecord,
    ReadinessLevelRecord,
    SecurityGateDecisionRecord,
    SupportabilityDecisionRecord,
    new_id,
)
from .contracts import (
    CapabilityEvidence,
    CapabilityResult,
    LayeredReadinessDecision,
    ReadinessDowngrade,
    ReadinessValidationError,
    SecurityGateDecision,
    SupportabilityDecision,
)
from .evaluator import DowngradeStore


@dataclass
class InMemoryReadinessDowngradeStore:
    """Deterministic append-only sink used by unit tests and local evaluation."""

    _events: dict[str, ReadinessDowngrade] | None = None

    def __post_init__(self) -> None:
        if self._events is None:
            self._events = {}

    def append(self, event: ReadinessDowngrade) -> ReadinessDowngrade:
        assert self._events is not None
        digest = event.event_digest
        existing = self._events.get(digest)
        if existing is not None and existing != event:
            raise ReadinessValidationError("readiness downgrade evidence is immutable")
        self._events[digest] = event
        return event

    @property
    def events(self) -> tuple[ReadinessDowngrade, ...]:
        assert self._events is not None
        return tuple(self._events[key] for key in sorted(self._events))


class SqlAlchemyReadinessStore(DowngradeStore):
    """Persist Spec 013 evidence through the AppCare tenant-scoped database."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save_capability_evidence(self, evidence: CapabilityEvidence) -> CapabilityEvidenceRecord:
        self._assert_application_scope(evidence.tenant_id, evidence.application_id)
        existing = self.session.scalar(
            select(CapabilityEvidenceRecord).where(
                CapabilityEvidenceRecord.evidence_digest == evidence.evidence_digest
            )
        )
        if existing is not None:
            return existing
        row = CapabilityEvidenceRecord(
            id=new_id(),
            tenant_id=evidence.tenant_id,
            application_id=evidence.application_id,
            stack_id=evidence.stack_id,
            capability=evidence.capability,
            status=evidence.status.value,
            evidence_class=evidence.evidence_class.value,
            evidence_ref=evidence.evidence_ref,
            source_revision=evidence.source_revision,
            artifact_digest=evidence.artifact_digest,
            observed_at=evidence.observed_at,
            evidence_digest=evidence.evidence_digest,
            coordinator_decision=(
                evidence.coordinator_decision.value
                if evidence.coordinator_decision is not None
                else None
            ),
        )
        self.session.add(row)
        self._flush("capability evidence")
        return row

    def save_supportability(self, decision: SupportabilityDecision) -> SupportabilityDecisionRecord:
        self._assert_application_scope(decision.tenant_id, decision.application_id)
        existing = self.session.scalar(
            select(SupportabilityDecisionRecord).where(
                SupportabilityDecisionRecord.assessment_digest == decision.assessment_digest
            )
        )
        if existing is not None:
            return existing
        row = SupportabilityDecisionRecord(
            id=new_id(),
            tenant_id=decision.tenant_id,
            application_id=decision.application_id,
            stack_id=decision.stack_id,
            status=decision.status.value,
            mandatory_capability_digest=decision.mandatory_capability_digest,
            blocking_capabilities_json=list(decision.blocking_capabilities),
            cleanup_capabilities_json=list(decision.cleanup_capabilities),
            evidence_refs_json=list(decision.evidence_refs),
            reason_codes_json=list(decision.reason_codes),
            capability_results_json=[
                self._capability_result_payload(item) for item in decision.capability_results
            ],
            coordinator=decision.coordinator,
            coordinator_decision=decision.coordinator_decision.value,
            decided_at=decision.decided_at,
            assessment_digest=decision.assessment_digest,
        )
        self.session.add(row)
        self._flush("supportability decision")
        return row

    def save_readiness(
        self, decision: LayeredReadinessDecision
    ) -> tuple[ReadinessLevelRecord, ...]:
        if decision.tenant_id is not None and decision.application_id is not None:
            self._assert_application_scope(decision.tenant_id, decision.application_id)
        rows: list[ReadinessLevelRecord] = []
        for level in decision.levels:
            query = select(ReadinessLevelRecord).where(
                ReadinessLevelRecord.level == level.level.value,
                ReadinessLevelRecord.scope == level.scope,
                ReadinessLevelRecord.assessment_digest == decision.evidence_digest,
            )
            if decision.tenant_id is None:
                query = query.where(ReadinessLevelRecord.tenant_id.is_(None))
            else:
                query = query.where(ReadinessLevelRecord.tenant_id == decision.tenant_id)
            if decision.application_id is None:
                query = query.where(ReadinessLevelRecord.application_id.is_(None))
            else:
                query = query.where(ReadinessLevelRecord.application_id == decision.application_id)
            existing = self.session.scalar(query)
            if existing is not None:
                rows.append(existing)
                continue
            row = ReadinessLevelRecord(
                id=new_id(),
                tenant_id=decision.tenant_id,
                application_id=decision.application_id,
                level=level.level.value,
                scope=level.scope,
                status=level.status.value,
                evidence_refs_json=list(level.evidence_refs),
                evidence_classes_json=[item.value for item in level.evidence_classes],
                evidence_kinds_json=list(level.evidence_kinds),
                reason_codes_json=list(level.reason_codes),
                evaluator=level.evaluator,
                exact_head=level.exact_head,
                artifact_digest=level.artifact_digest,
                coordinator_decision=(
                    level.coordinator_decision.value
                    if level.coordinator_decision is not None
                    else None
                ),
                evaluated_at=level.evaluated_at,
                assessment_digest=decision.evidence_digest,
            )
            self.session.add(row)
            rows.append(row)
        self._flush("readiness decision")
        return tuple(rows)

    def save_security_gate(self, decision: SecurityGateDecision) -> SecurityGateDecisionRecord:
        existing = self.session.scalar(
            select(SecurityGateDecisionRecord).where(
                SecurityGateDecisionRecord.evidence_digest == decision.evidence_digest
            )
        )
        if existing is not None:
            return existing
        row = SecurityGateDecisionRecord(
            id=new_id(),
            release_candidate_sha=decision.release_candidate_sha,
            gate_version=decision.gate_version,
            individual_gate_results_json=dict(decision.individual_gate_results),
            security_findings_open=decision.security_findings_open,
            codex_security_refs_json=list(decision.codex_security_refs),
            dependency_audit_ref=decision.dependency_audit_ref,
            secret_scan_ref=decision.secret_scan_ref,
            graphify_ref=decision.graphify_ref,
            saveruflo_ref=decision.saveruflo_ref,
            exact_head_ci_ref=decision.exact_head_ci_ref,
            real_target_security_ref=decision.real_target_security_ref,
            known_limitations_ref=decision.known_limitations_ref,
            coordinator_decision=decision.coordinator_decision.value,
            decided_at=decision.decided_at,
            evidence_digest=decision.evidence_digest,
        )
        self.session.add(row)
        self._flush("security gate decision")
        return row

    def append(self, event: ReadinessDowngrade) -> ReadinessDowngrade:
        if event.tenant_id is None or event.application_id is None or event.stack_id is None:
            raise ReadinessValidationError(
                "durable readiness downgrade requires tenant, application, and stack scope"
            )
        self._assert_application_scope(event.tenant_id, event.application_id)
        existing = self.session.scalar(
            select(ReadinessDowngradeRecord).where(
                ReadinessDowngradeRecord.event_digest == event.event_digest
            )
        )
        if existing is not None:
            return event
        row = ReadinessDowngradeRecord(
            id=new_id(),
            tenant_id=event.tenant_id,
            application_id=event.application_id,
            stack_id=event.stack_id,
            previous_level=event.previous_level.value,
            previous_status=event.previous_status.value,
            new_status=event.new_status.value,
            trigger_capability=event.trigger_capability,
            trigger_evidence_ref=event.trigger_evidence_ref,
            affected_scopes_json=list(event.affected_scopes),
            reason_code=event.reason_code,
            recorded_at=event.recorded_at,
            event_digest=event.event_digest,
        )
        self.session.add(row)
        self._flush("readiness downgrade")
        return event

    @staticmethod
    def _capability_result_payload(item: CapabilityResult) -> dict[str, object]:
        return {
            "tenant_id": item.tenant_id,
            "application_id": item.application_id,
            "stack_id": item.stack_id,
            "capability": item.capability,
            "status": item.status.value,
            "evidence_class": item.evidence_class.value if item.evidence_class else None,
            "evidence_ref": item.evidence_ref,
            "source_revision": item.source_revision,
            "artifact_digest": item.artifact_digest,
            "observed_at": item.observed_at.isoformat() if item.observed_at else None,
            "reason_codes": list(item.reason_codes),
        }

    def _flush(self, label: str) -> None:
        try:
            self.session.flush()
        except IntegrityError as exc:
            raise ReadinessValidationError(
                f"{label} violates an immutable scope constraint"
            ) from exc

    def _assert_application_scope(self, tenant_id: str, application_id: str) -> None:
        exists = self.session.scalar(
            select(Application.id).where(
                Application.id == application_id,
                Application.tenant_id == tenant_id,
            )
        )
        if exists is None:
            raise ReadinessValidationError("readiness evidence crosses application scope")


__all__ = ["InMemoryReadinessDowngradeStore", "SqlAlchemyReadinessStore"]
