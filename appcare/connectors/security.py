"""Shared validation for secret-free credential references and fingerprints."""

from __future__ import annotations

import re

_REFERENCE = re.compile(
    r"^(?:vault|secret|appcare-secret)://[a-z0-9][a-z0-9._/-]{2,240}$",
    re.IGNORECASE,
)
_JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_TOKEN_PREFIX = re.compile(
    r"(?:^|[/_.:-])(?:gh[oprus]_\w+|github_pat_\w+|xox[baprs]-\w+|sk-[A-Za-z0-9_-]{12,})$",
    re.IGNORECASE,
)
_SECRET_SEGMENT = re.compile(
    r"(?:^|[/_.:-])(?:access[_-]?token|api[_-]?key|apikey|authorization|bearer|"
    r"client[_-]?secret|credential|jwt|password|private[_-]?key|refresh[_-]?token|"
    r"secret|session[_-]?token|signature|sig|token)(?:[/_.:-]|$)",
    re.IGNORECASE,
)
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def is_safe_credential_reference(value: object) -> bool:
    """Accept only opaque custody references, never wrapped raw tokens."""

    if not isinstance(value, str):
        return False
    normalized = value.strip()
    if _REFERENCE.fullmatch(normalized) is None:
        return False
    opaque = normalized.split("://", 1)[1]
    if _JWT.fullmatch(opaque) is not None or _TOKEN_PREFIX.search(opaque) is not None:
        return False
    return _SECRET_SEGMENT.search(opaque) is None


def is_safe_credential_fingerprint(value: object) -> bool:
    """Accept only a non-secret SHA-256 fingerprint."""

    return isinstance(value, str) and _FINGERPRINT.fullmatch(value.strip()) is not None
