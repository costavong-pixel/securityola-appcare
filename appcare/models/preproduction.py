"""Durable, immutable provider-neutral preproduction evidence."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdentityMixin, TimestampMixin


class PreproductionEvidenceRecord(IdentityMixin, TimestampMixin, Base):
    """One exact-head-bound acceptance record for a controlled environment."""

    __tablename__ = "preproduction_evidence"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pass', 'fail', 'unverified')",
            name="ck_preproduction_evidence_status",
        ),
        UniqueConstraint(
            "tenant_id",
            "authoritative_evidence_digest",
            name="uq_preproduction_evidence_digest",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source_revision: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    artifact_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    environment_identity: Mapped[str] = mapped_column(String(200), nullable=False)
    deployment_reference: Mapped[str] = mapped_column(String(200), nullable=False)
    deployment_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    smoke_test_receipt: Mapped[str] = mapped_column(String(200), nullable=False)
    security_test_receipt: Mapped[str] = mapped_column(String(200), nullable=False)
    rollback_reference_receipt: Mapped[str] = mapped_column(String(200), nullable=False)
    authoritative_evidence_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    exact_head: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)


__all__ = ["PreproductionEvidenceRecord"]
