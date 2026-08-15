"""Local identity authentication with hashed, short-lived bearer tokens."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Tenant, User

_PASSWORD_ITERATIONS = 600_000
_TOKEN_PATTERN = re.compile(
    r"^(?P<user>[0-9a-f]{32})\.(?P<expires>[0-9]{10})\.(?P<secret>[A-Za-z0-9_-]{32,})$"
)


class AuthenticationError(ValueError):
    """A deliberately non-specific authentication failure."""


def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("password length is outside the supported range")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PASSWORD_ITERATIONS)
    encoded_salt = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${_PASSWORD_ITERATIONS}${encoded_salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iteration_text)
        if iterations < 100_000 or iterations > 2_000_000:
            return False
        padding = "=" * (-len(salt_text) % 4)
        salt = base64.urlsafe_b64decode((salt_text + padding).encode("ascii"))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()
    except (ValueError, TypeError):
        return False
    return secrets.compare_digest(actual, expected)


def hash_token(secret: str) -> str:
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


class TokenService:
    """Issue and verify tokens without persisting the bearer value itself."""

    def __init__(self, ttl_seconds: int = 900) -> None:
        self.ttl_seconds = ttl_seconds

    def issue(self, session: Session, user: User) -> tuple[str, int]:
        tenant = session.get(Tenant, user.tenant_id)
        if tenant is None or tenant.status != "active" or user.status != "active":
            raise AuthenticationError("authentication failed")
        expires = int(time.time()) + self.ttl_seconds
        secret = secrets.token_urlsafe(32)
        user.auth_token_hash = hash_token(secret)
        user.auth_token_expires_at = datetime.fromtimestamp(expires, tz=UTC)
        session.flush()
        return f"{user.id}.{expires}.{secret}", self.ttl_seconds

    def authenticate(self, session: Session, token: str) -> User:
        match = _TOKEN_PATTERN.fullmatch(token)
        if match is None:
            raise AuthenticationError("authentication failed")
        try:
            expires = int(match.group("expires"))
        except ValueError as exc:
            raise AuthenticationError("authentication failed") from exc
        if expires <= int(time.time()):
            raise AuthenticationError("authentication failed")

        user = session.get(User, match.group("user"))
        if user is None:
            raise AuthenticationError("authentication failed")
        tenant = session.get(Tenant, user.tenant_id)
        stored_hash = user.auth_token_hash
        stored_expiry = user.auth_token_expires_at
        if stored_expiry is not None and stored_expiry.tzinfo is None:
            stored_expiry = stored_expiry.replace(tzinfo=UTC)
        if (
            tenant is None
            or tenant.status != "active"
            or user.status != "active"
            or stored_hash is None
            or stored_expiry is None
            or stored_expiry.timestamp() <= time.time()
            or not secrets.compare_digest(stored_hash, hash_token(match.group("secret")))
        ):
            raise AuthenticationError("authentication failed")
        user.last_authenticated_at = datetime.now(UTC)
        return user

    def authenticate_password(self, session: Session, email: str, password: str) -> User:
        normalized = email.strip().casefold()
        candidates = session.scalars(select(User).where(User.email == normalized)).all()
        matches = [
            user
            for user in candidates
            if user.status == "active" and verify_password(password, user.password_hash)
        ]
        if len(matches) != 1:
            raise AuthenticationError("authentication failed")
        tenant = session.get(Tenant, matches[0].tenant_id)
        if tenant is None or tenant.status != "active":
            raise AuthenticationError("authentication failed")
        return matches[0]
