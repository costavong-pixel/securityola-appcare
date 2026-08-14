"""Tenant and user identity records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, IdentityMixin, TimestampMixin


class Tenant(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'suspended', 'disabled')", name="ck_tenant_status"),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    users: Mapped[list[User]] = relationship(back_populates="tenant")


class User(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        CheckConstraint("status IN ('active', 'disabled')", name="ck_user_status"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    auth_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    auth_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    last_authenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tenant: Mapped[Tenant] = relationship(back_populates="users")
