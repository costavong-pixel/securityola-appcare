"""Descriptive control-plane operation records without provider capabilities."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdentityMixin, TimestampMixin


class Connector(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "connectors"
    __table_args__ = (
        CheckConstraint(
            "status IN ('configured', 'unavailable', 'disabled')", name="ck_connector_status"
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="configured")
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    resource_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    owner_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    scope_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    health_status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    permission_status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    ownership_status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ConnectorCredential(IdentityMixin, TimestampMixin, Base):
    """Non-secret credential metadata; the provider credential is never stored here."""

    __tablename__ = "connector_credentials"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'expired', 'revoked', 'invalid', 'insufficient_scope')",
            name="ck_connector_credential_status",
        ),
        UniqueConstraint("connector_id", name="uq_connector_credential_connector"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    reference: Mapped[str] = mapped_column(String(500), nullable=False)
    authority: Mapped[str] = mapped_column(String(100), nullable=False)
    scopes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="active")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)


class ConnectorCheck(IdentityMixin, Base):
    """Sanitized health, permission, and ownership evidence."""

    __tablename__ = "connector_checks"
    __table_args__ = (
        CheckConstraint(
            "check_kind IN ('health', 'permissions', 'ownership')",
            name="ck_connector_check_kind",
        ),
        CheckConstraint(
            "status IN ('passed', 'failed', 'unknown')", name="ck_connector_check_status"
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    check_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    evidence_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class InventoryRun(IdentityMixin, TimestampMixin, Base):
    """A local, idempotent connector inventory reconciliation."""

    __tablename__ = "inventory_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'succeeded', 'failed')", name="ck_inventory_run_status"
        ),
        UniqueConstraint(
            "tenant_id", "connector_id", "snapshot_key", name="uq_inventory_run_snapshot"
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    snapshot_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    asset_count: Mapped[int] = mapped_column(nullable=False, default=0)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Job(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')",
            name="ck_job_status",
        ),
        CheckConstraint("retry_count >= 0", name="ck_job_retry_count"),
        CheckConstraint("cost_amount IS NULL OR cost_amount >= 0", name="ck_job_cost_amount"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    retry_count: Mapped[int] = mapped_column(nullable=False, default=0)
    cost_amount: Mapped[Decimal | None] = mapped_column(Numeric(12, 6), nullable=True)
    cost_currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    failure_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class Backup(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "backups"
    __table_args__ = (
        CheckConstraint(
            "status IN ('requested', 'verified', 'failed', 'expired')", name="ck_backup_status"
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="requested")
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    artifact_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)


class Approval(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint(
            "status IN ('requested', 'approved', 'rejected', 'expired')",
            name="ck_approval_status",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="requested")
    requested_by: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    decided_by: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Deployment(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "deployments"
    __table_args__ = (
        CheckConstraint(
            "environment IN ('development', 'staging', 'production')",
            name="ck_deployment_environment",
        ),
        CheckConstraint(
            "status IN ('requested', 'approved', 'running', 'succeeded', 'failed', 'cancelled')",
            name="ck_deployment_status",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    environment: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="requested")
    requested_by: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    approved_by: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    revision: Mapped[str] = mapped_column(String(200), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)


class WorkflowAction(IdentityMixin, TimestampMixin, Base):
    """Durable idempotency ledger for one bounded workflow side effect."""

    __tablename__ = "workflow_actions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed', 'escalated')",
            name="ck_workflow_action_status",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_workflow_action_attempt_count"),
        UniqueConstraint(
            "tenant_id", "workflow_id", "action_key", name="uq_workflow_action_idempotency"
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workflow_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action_key: Mapped[str] = mapped_column(String(200), nullable=False)
    action_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    result_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)


class DatabaseOperationRecord(IdentityMixin, TimestampMixin, Base):
    """Durable idempotency record for bounded Spec 015 database operations."""

    __tablename__ = "database_operations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed', 'recovery_required')",
            name="ck_database_operation_status",
        ),
        UniqueConstraint("scope", "idempotency_key", name="uq_database_operation_idempotency"),
        Index(
            "uq_database_operation_active_scope",
            "scope",
            unique=True,
            sqlite_where=text("status IN ('pending', 'running', 'recovery_required')"),
            postgresql_where=text("status IN ('pending', 'running', 'recovery_required')"),
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    application_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    operation_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending")
    outcome_json: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    result_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)


class DatabaseRestoreTargetRecord(IdentityMixin, TimestampMixin, Base):
    """Durable registration/quarantine state for isolated restore targets."""

    __tablename__ = "database_restore_targets"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'quarantined')",
            name="ck_database_restore_target_status",
        ),
        UniqueConstraint(
            "tenant_id",
            "application_id",
            "stack_id",
            "isolated_target_reference",
            name="uq_database_restore_target_identity",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    application_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    stack_id: Mapped[str] = mapped_column(String(128), nullable=False)
    isolated_target_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    target_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_target_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    source_database_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    source_logical_database_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    quarantine_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cleanup_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)


class WorkflowEvidence(IdentityMixin, TimestampMixin, Base):
    """Durable, bounded evidence reference separate from AI explanations."""

    __tablename__ = "workflow_evidence"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "workflow_id", "evidence_ref", name="uq_workflow_evidence_reference"
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workflow_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    evidence_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    summary_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class WorkflowTransition(IdentityMixin, Base):
    """Idempotent workflow transition linked to the append-only audit chain."""

    __tablename__ = "workflow_transitions"
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('started', 'succeeded', 'failed', 'paused', 'escalated')",
            name="ck_workflow_transition_outcome",
        ),
        UniqueConstraint(
            "tenant_id", "workflow_id", "transition_key", name="uq_workflow_transition_key"
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workflow_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    transition_key: Mapped[str] = mapped_column(String(200), nullable=False)
    from_phase: Mapped[str] = mapped_column(String(80), nullable=False)
    to_phase: Mapped[str] = mapped_column(String(80), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence_refs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    audit_event_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("audit_events.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
