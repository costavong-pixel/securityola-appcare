"""Sanitized audit recording with deterministic hash chaining."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..models import AuditEvent, User, new_id, utcnow
from .security import contains_credential_like, is_secret_key

_REDACTED = "[REDACTED]"
_MAX_DEPTH = 6
_MAX_ITEMS = 50
_MAX_STRING = 500


class MetadataError(ValueError):
    """Metadata cannot be safely written to an audit record."""


def _sanitize(value: Any, *, depth: int, secret_key: bool = False) -> Any:
    if depth > _MAX_DEPTH:
        raise MetadataError("metadata nesting is too deep")
    if secret_key:
        return _REDACTED
    if isinstance(value, Mapping):
        if len(value) > _MAX_ITEMS:
            raise MetadataError("metadata contains too many keys")
        return {
            str(key)[:100]: _sanitize(item, depth=depth + 1, secret_key=is_secret_key(str(key)))
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_ITEMS:
            raise MetadataError("metadata contains too many items")
        return [_sanitize(item, depth=depth + 1) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if contains_credential_like(value):
            raise MetadataError("metadata contains a credential-like value")
        return value[:_MAX_STRING]
    raise MetadataError("metadata contains an unsupported value")


def sanitize_metadata(metadata: Mapping[str, Any], *, max_bytes: int = 16_384) -> dict[str, Any]:
    sanitized = _sanitize(metadata, depth=0)
    if not isinstance(sanitized, dict):
        raise MetadataError("audit metadata must be an object")
    encoded = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(encoded.encode("utf-8")) > max_bytes:
        raise MetadataError("audit metadata exceeds the size limit")
    return sanitized


def sanitize_text(value: str | None, *, max_length: int = 1_000) -> str | None:
    if value is None:
        return None
    if contains_credential_like(value):
        raise MetadataError("text contains a credential-like value")
    return value[:max_length]


def _hash_event(event: AuditEvent) -> str:
    payload = {
        "id": event.id,
        "tenant_id": event.tenant_id,
        "actor_user_id": event.actor_user_id,
        "action": event.action,
        "subject_type": event.subject_type,
        "subject_id": event.subject_id,
        "outcome": event.outcome,
        "metadata_json": event.metadata_json,
        "occurred_at": event.occurred_at.isoformat(),
        "previous_event_hash": event.previous_event_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append_event(
    session: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    action: str,
    subject_type: str,
    subject_id: str | None,
    outcome: str,
    metadata: Mapping[str, Any] | None = None,
    max_bytes: int = 16_384,
) -> AuditEvent:
    if actor_user_id is not None:
        actor = session.get(User, actor_user_id)
        if actor is None or actor.tenant_id != tenant_id:
            raise MetadataError("audit actor does not belong to the tenant")
    previous = session.scalar(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_id)
        .order_by(desc(AuditEvent.occurred_at), desc(AuditEvent.id))
        .limit(1)
    )
    event = AuditEvent(
        id=new_id(),
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action=action,
        subject_type=subject_type,
        subject_id=subject_id,
        outcome=outcome,
        metadata_json=sanitize_metadata(metadata or {}, max_bytes=max_bytes),
        occurred_at=utcnow(),
        previous_event_hash=previous.event_hash if previous else None,
        event_hash="pending",
    )
    event.event_hash = _hash_event(event)
    session.add(event)
    session.flush()
    return event


def verify_event_hash(event: AuditEvent) -> bool:
    return event.event_hash == _hash_event(event)
