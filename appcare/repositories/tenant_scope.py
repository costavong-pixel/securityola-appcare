"""Centralized tenant-filtered persistence helpers."""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def valid_public_id(value: str) -> bool:
    return bool(_ID_PATTERN.fullmatch(value))


def get_owned[ModelT](
    session: Session, model: type[ModelT], tenant_id: str, record_id: str
) -> ModelT | None:
    if not valid_public_id(record_id):
        return None
    statement = select(model).where(
        getattr(model, "id") == record_id,  # noqa: B009 - SQLAlchemy mapped class attribute
        getattr(model, "tenant_id") == tenant_id,  # noqa: B009 - SQLAlchemy mapped attribute
    )
    return session.scalar(statement)


def list_owned[ModelT](
    session: Session, model: type[ModelT], tenant_id: str, *, limit: int, offset: int = 0
) -> list[ModelT]:
    tenant_column = getattr(model, "tenant_id")  # noqa: B009
    created_column = getattr(model, "created_at")  # noqa: B009
    id_column = getattr(model, "id")  # noqa: B009
    statement = (
        select(model)
        .where(tenant_column == tenant_id)
        .order_by(created_column.desc(), id_column)
        .offset(offset)
        .limit(limit)
    )
    return list(session.scalars(statement).all())


def owned_by_id[ModelT](
    session: Session, model: type[ModelT], tenant_id: str, record_id: str
) -> ModelT | None:
    return get_owned(session, model, tenant_id, record_id)
