"""FastAPI dependencies for sessions and authenticated tenant context."""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..db import Database
from ..models import User
from .service import AuthenticationError, TokenService

bearer = HTTPBearer(auto_error=False)


def get_database(request: Request) -> Database:
    database = getattr(request.app.state, "database", None)
    if not isinstance(database, Database):
        raise RuntimeError("AppCare database is not initialized")
    return database


def get_session(database: Database = Depends(get_database)) -> Generator[Session, None, None]:
    session = database.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: Session = Depends(get_session),
) -> User:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    settings = getattr(request.app.state, "settings", None)
    ttl = int(getattr(settings, "token_ttl_seconds", 900))
    try:
        return TokenService(ttl).authenticate(session, credentials.credentials)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
