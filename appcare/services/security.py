"""Shared detection for credential-shaped values at trust boundaries."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

_REFERENCE = re.compile(
    r"^(?:vault|secret|appcare-secret)://[a-z0-9][a-z0-9._/-]{2,240}$",
    re.IGNORECASE,
)
_JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_JWT_LIKE = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_TOKEN_PREFIX = re.compile(
    r"(?:gh[oprus]_|github_pat_|xox[baprs]-|sk-)[A-Za-z0-9_-]{8,}",
    re.IGNORECASE,
)
_CREDENTIAL_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|https?://[^\s/:]+:[^\s@]+@|"
    r"(?:gh[oprus]_|github_pat_|xox[baprs]-|sk-)[A-Za-z0-9_-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|\bBearer\s+[A-Za-z0-9._~-]{20,})",
    re.IGNORECASE,
)
_SECRET_KEY = re.compile(
    r"(?:pass(?:word|phrase)?|secret|token|api[_-]?key|authorization|cookie|credential|"
    r"private[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?token)",
    re.IGNORECASE,
)
_SECRET_SEGMENT = re.compile(
    r"(?:^|[/_.:-])(?:access[_-]?token|api[_-]?key|apikey|authorization|bearer|"
    r"client[_-]?secret|credential|jwt|password|private[_-]?key|refresh[_-]?token|"
    r"secret|session[_-]?token|signature|sig|token)(?:[/_.:-]|$)",
    re.IGNORECASE,
)
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def contains_credential_like(value: object) -> bool:
    """Detect raw, wrapped, embedded, or JWT-shaped credential values."""

    if not isinstance(value, str):
        return False
    return any(
        pattern.search(value) is not None
        for pattern in (_CREDENTIAL_VALUE, _JWT_LIKE, _TOKEN_PREFIX)
    )


def contains_credential_like_data(value: object) -> bool:
    """Detect credential-shaped strings or secret-named keys in JSON-like data."""

    if isinstance(value, Mapping):
        return any(
            _SECRET_KEY.search(str(key)) is not None or contains_credential_like_data(item)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(contains_credential_like_data(item) for item in value)
    return contains_credential_like(value)


def is_secret_key(value: object) -> bool:
    """Return whether a JSON key names a field that must be redacted."""

    return isinstance(value, str) and _SECRET_KEY.search(value) is not None


def is_safe_credential_reference(value: object) -> bool:
    """Accept only opaque custody references, never wrapped raw tokens."""

    if not isinstance(value, str):
        return False
    normalized = value.strip()
    if _REFERENCE.fullmatch(normalized) is None:
        return False
    opaque = normalized.split("://", 1)[1]
    if _JWT.fullmatch(opaque) is not None or contains_credential_like(opaque):
        return False
    return _SECRET_SEGMENT.search(opaque) is None


def is_safe_credential_fingerprint(value: object) -> bool:
    """Accept only a non-secret SHA-256 fingerprint."""

    return isinstance(value, str) and _FINGERPRINT.fullmatch(value.strip()) is not None
