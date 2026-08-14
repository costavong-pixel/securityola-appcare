"""Shared HTTP validation helpers that keep error details non-sensitive."""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from ..models import Application, User
from ..repositories.tenant_scope import get_owned


def not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")


def invalid_input() -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid input")


def owned_application(session: Session, user: User, application_id: str) -> Application:
    application = get_owned(session, Application, user.tenant_id, application_id)
    if application is None:
        raise not_found()
    return application


def safe_reference(value: str) -> bool:
    """Allow opaque/local references but never persist credential-bearing URLs."""

    if any(marker in value.casefold() for marker in ("-----begin", "private key", "bearer ")):
        return False
    if "://" not in value:
        return True
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        return False
    query_keys = {piece.split("=", 1)[0].casefold() for piece in parsed.query.split("&") if piece}
    return not query_keys.intersection(
        {"token", "access_token", "refresh_token", "api_key", "apikey", "secret", "password"}
    )
