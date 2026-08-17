"""Shared HTTP validation helpers that keep error details non-sensitive."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from ..models import Application, User
from ..repositories.tenant_scope import get_owned
from ..services.security import contains_credential_like


def not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")


def invalid_input() -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="invalid input")


def owned_application(session: Session, user: User, application_id: str) -> Application:
    application = get_owned(session, Application, user.tenant_id, application_id)
    if application is None:
        raise not_found()
    return application


def safe_reference(value: str) -> bool:
    """Allow opaque/local references but never persist credential-bearing URLs."""

    if contains_credential_like(value):
        return False
    if any(marker in value.casefold() for marker in ("-----begin", "private key", "bearer ")):
        return False
    if "://" not in value:
        return True
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    secret_key = re.compile(
        r"(?:^|[_-])(access[_-]?token|api[_-]?key|apikey|authorization|auth|client[_-]?secret|"
        r"code|credential|jwt|key|password|private[_-]?key|refresh[_-]?token|secret|session|"
        r"signature|sig|token)(?:$|[_-])",
        re.IGNORECASE,
    )
    parameters = parse_qsl(parsed.query, keep_blank_values=True)
    if parsed.fragment:
        parameters.extend(parse_qsl(parsed.fragment, keep_blank_values=True))
    for key, parameter_value in parameters:
        if secret_key.search(unquote_plus(key)) or contains_credential_like(parameter_value):
            return False
    return True
