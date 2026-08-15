"""Local development authentication endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_session
from ..auth.service import AuthenticationError, TokenService
from .schemas import TokenRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
def issue_token(
    body: TokenRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> TokenResponse:
    settings = request.app.state.settings
    service = TokenService(settings.token_ttl_seconds)
    try:
        user = service.authenticate_password(session, body.email, body.password)
        token, expires_in = service.issue(session, user)
    except (AuthenticationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return TokenResponse(access_token=token, expires_in=expires_in)
