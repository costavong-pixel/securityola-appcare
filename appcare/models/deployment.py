"""Durable, tenant-scoped BETA-07 deployment evidence records."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdentityMixin, TimestampMixin

_DEPLOYMENT_STATUSES = (
    "approval_pending",
    "approved",
    "deploying",
    "verifying",
    "succeeded",
    "denied",
    "rolling_back",
    "rolled_back",
    "rollback_failed",
    "emergency_stopped",
    "failed",
)


class DeploymentIntentRecord(IdentityMixin, TimestampMixin, Base):
    """Current state of one immutable intent; evidence is stored separately."""

    __tablename__ = "deployment_intents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('approval_pending', 'approved', 'deploying', 'verifying', "
            "'succeeded', 'denied', 'rolling_back', 'rolled_back', 'rollback_failed', "
            "'emergency_stopped', 'failed')",
            name="ck_deployment_intent_status",
        ),
        UniqueConstraint("intent_id", name="uq_deployment_intent_reference"),
        UniqueConstraint("idempotency_key", name="uq_deployment_intent_idempotency"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    intent_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    intent_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    backup_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    deployment_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    verification_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    rollback_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    record_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class DeploymentEvidenceRecord(IdentityMixin, Base):
    """Append-only transition evidence for one deployment intent."""

    __tablename__ = "deployment_evidence"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "intent_id", "sequence", name="uq_deployment_evidence_sequence"
        ),
        UniqueConstraint("tenant_id", "intent_id", "digest", name="uq_deployment_evidence_digest"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    intent_id: Mapped[str] = mapped_column(
        String(200),
        ForeignKey("deployment_intents.intent_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(nullable=False)
    event: Mapped[str] = mapped_column(String(100), nullable=False)
    from_status: Mapped[str] = mapped_column(String(30), nullable=False)
    to_status: Mapped[str] = mapped_column(String(30), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)


class DeploymentControlRecord(IdentityMixin, TimestampMixin, Base):
    """Durable tenant-scoped emergency-stop latch."""

    __tablename__ = "deployment_controls"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_deployment_control_tenant"),)

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    emergency_stopped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    emergency_stop_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)


class DeploymentRevokedCredential(IdentityMixin, TimestampMixin, Base):
    """Durable allowlist-denial records containing only opaque references."""

    __tablename__ = "deployment_revoked_credentials"
    __table_args__ = (
        UniqueConstraint("tenant_id", "credential_ref", name="uq_deployment_revoked_credential"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_ref: Mapped[str] = mapped_column(String(200), nullable=False)


__all__ = [
    "DeploymentControlRecord",
    "DeploymentEvidenceRecord",
    "DeploymentIntentRecord",
    "DeploymentRevokedCredential",
]
