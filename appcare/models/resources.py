"""Tenant-owned application, asset, and finding records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdentityMixin, TimestampMixin


class Application(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "applications"
    __table_args__ = (
        CheckConstraint(
            "environment IN ('development', 'staging', 'production')",
            name="ck_application_environment",
        ),
        CheckConstraint("status IN ('active', 'archived')", name="ck_application_status"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    repository_url: Mapped[str] = mapped_column(String(500), nullable=False)
    environment: Mapped[str] = mapped_column(String(20), nullable=False, default="development")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")


class Asset(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'retired')", name="ck_asset_status"),
        UniqueConstraint(
            "tenant_id", "connector_id", "provider_reference", name="uq_asset_provider_reference"
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    locator: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    connector_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("connectors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    provider: Mapped[str | None] = mapped_column(String(100), nullable=True)
    provider_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    display_metadata_json: Mapped[dict[str, object]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_finding_severity",
        ),
        CheckConstraint("status IN ('open', 'accepted', 'resolved')", name="ck_finding_status"),
        UniqueConstraint("tenant_id", "fingerprint", name="uq_finding_tenant_fingerprint"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
