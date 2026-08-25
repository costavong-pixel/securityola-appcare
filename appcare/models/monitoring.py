"""Durable, tenant-scoped BETA-08 monitoring event records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdentityMixin


class MonitoringEventRecord(IdentityMixin, Base):
    """Append-only sanitized event storage for one monitoring target."""

    __tablename__ = "monitoring_events"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "application_id", "environment", "sequence",
            name="uq_monitoring_event_sequence",
        ),
        UniqueConstraint(
            "tenant_id", "application_id", "environment", "digest",
            name="uq_monitoring_event_digest",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    environment: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    app_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    sequence: Mapped[int] = mapped_column(nullable=False)
    event_type: Mapped[str] = mapped_column(String(30), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    check_kind: Mapped[str | None] = mapped_column(String(30), nullable=True)
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    evidence_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(String(300), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(500), nullable=True)
    alert_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    alert_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    occurrences: Mapped[int] = mapped_column(nullable=False, default=0)
    suppressed_count: Mapped[int] = mapped_column(nullable=False, default=0)
    usage_json: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)


__all__ = ["MonitoringEventRecord"]
