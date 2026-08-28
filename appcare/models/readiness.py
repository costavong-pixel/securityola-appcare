"""Durable, tenant-scoped Spec 013 readiness evidence records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdentityMixin


class CapabilityEvidenceRecord(IdentityMixin, Base):
    """Immutable normalized result for one capability observation."""

    __tablename__ = "capability_evidence"
    __table_args__ = (
        CheckConstraint(
            "status IN ('supported', 'needs_cleanup', 'missing_capability', "
            "'unsupported', 'blocked_external')",
            name="ck_capability_evidence_status",
        ),
        CheckConstraint(
            "evidence_class IN ('fixture', 'reference', 'controlled_live_provider', 'real_target')",
            name="ck_capability_evidence_class",
        ),
        UniqueConstraint(
            "tenant_id",
            "application_id",
            "stack_id",
            "capability",
            "evidence_digest",
            name="uq_capability_evidence_event",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stack_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    capability: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    evidence_class: Mapped[str] = mapped_column(String(30), nullable=False)
    evidence_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    source_revision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    coordinator_decision: Mapped[str | None] = mapped_column(String(20), nullable=True)


class SupportabilityDecisionRecord(IdentityMixin, Base):
    """Immutable coordinator-reviewed supportability assessment."""

    __tablename__ = "supportability_decisions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('supported', 'needs_cleanup', 'unsupported')",
            name="ck_supportability_decision_status",
        ),
        CheckConstraint(
            "coordinator_decision IN ('approve', 'reject', 'blocked')",
            name="ck_supportability_decision_coordinator",
        ),
        UniqueConstraint(
            "tenant_id",
            "application_id",
            "stack_id",
            "assessment_digest",
            name="uq_supportability_decision_assessment",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stack_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    mandatory_capability_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    blocking_capabilities_json: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    cleanup_capabilities_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reason_codes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    capability_results_json: Mapped[list[dict[str, object]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    coordinator: Mapped[str | None] = mapped_column(String(100), nullable=True)
    coordinator_decision: Mapped[str] = mapped_column(String(20), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assessment_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class ReadinessLevelRecord(IdentityMixin, Base):
    """Immutable evaluation result for one readiness layer."""

    __tablename__ = "readiness_levels"
    __table_args__ = (
        CheckConstraint(
            "level IN ('core', 'stack', 'customer_onboarding', 'pilot', 'paid_service')",
            name="ck_readiness_level_name",
        ),
        CheckConstraint(
            "status IN ('ready', 'blocked', 'partial')", name="ck_readiness_level_status"
        ),
        UniqueConstraint(
            "tenant_id",
            "application_id",
            "level",
            "scope",
            "assessment_digest",
            name="uq_readiness_level_assessment",
        ),
    )

    tenant_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    application_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=True, index=True
    )
    level: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_classes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_kinds_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reason_codes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evaluator: Mapped[str] = mapped_column(String(128), nullable=False)
    exact_head: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    coordinator_decision: Mapped[str | None] = mapped_column(String(20), nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assessment_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class ReadinessDowngradeRecord(IdentityMixin, Base):
    """Append-only durable audit event for an automatic readiness downgrade."""

    __tablename__ = "readiness_downgrades"
    __table_args__ = (
        CheckConstraint(
            "previous_level IN ('core', 'stack', 'customer_onboarding', 'pilot', 'paid_service')",
            name="ck_readiness_downgrade_level",
        ),
        CheckConstraint(
            "previous_status IN ('ready', 'blocked', 'partial')",
            name="ck_readiness_downgrade_previous_status",
        ),
        CheckConstraint(
            "new_status IN ('ready', 'blocked', 'partial')",
            name="ck_readiness_downgrade_new_status",
        ),
        UniqueConstraint("event_digest", name="uq_readiness_downgrade_digest"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stack_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    previous_level: Mapped[str] = mapped_column(String(30), nullable=False)
    previous_status: Mapped[str] = mapped_column(String(20), nullable=False)
    new_status: Mapped[str] = mapped_column(String(20), nullable=False)
    trigger_capability: Mapped[str] = mapped_column(String(128), nullable=False)
    trigger_evidence_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    affected_scopes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class SecurityGateDecisionRecord(IdentityMixin, Base):
    """Immutable binding between a release candidate and S01-S30 evidence."""

    __tablename__ = "security_gate_decisions"
    __table_args__ = (
        CheckConstraint(
            "coordinator_decision IN ('approve', 'reject', 'blocked')",
            name="ck_security_gate_coordinator",
        ),
        UniqueConstraint(
            "release_candidate_sha", "evidence_digest", name="uq_security_gate_evidence"
        ),
    )

    release_candidate_sha: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    gate_version: Mapped[str] = mapped_column(String(128), nullable=False)
    individual_gate_results_json: Mapped[dict[str, bool]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    security_findings_open: Mapped[int] = mapped_column(nullable=False, default=0)
    codex_security_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    dependency_audit_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    secret_scan_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    graphify_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    saveruflo_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    exact_head_ci_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    real_target_security_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    known_limitations_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    coordinator_decision: Mapped[str] = mapped_column(String(20), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


__all__ = [
    "CapabilityEvidenceRecord",
    "ReadinessDowngradeRecord",
    "ReadinessLevelRecord",
    "SecurityGateDecisionRecord",
    "SupportabilityDecisionRecord",
]
