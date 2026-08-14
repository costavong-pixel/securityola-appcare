"""Descriptive control-plane operation records without provider capabilities."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Numeric, String, Text
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
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


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
