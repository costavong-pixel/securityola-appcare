"""Canonical, sanitized identity helpers for scanner evidence."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from appcare.services.security import contains_credential_like, is_secret_key

from .models import EvidenceRecord, ScanContext, ScannerObservation


class CanonicalizationError(ValueError):
    """Raised when untrusted scanner data cannot be made public-safe."""


def canonicalize(value: Any, *, key: str | None = None) -> Any:
    """Return a JSON-safe, sorted, secret-free representation."""

    if key is not None and is_secret_key(key):
        raise CanonicalizationError("unsafe evidence field")
    if isinstance(value, str):
        normalized = value.strip()
        if contains_credential_like(normalized):
            raise CanonicalizationError("credential-like evidence rejected")
        return normalized
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("non-finite evidence value")
        return value
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str) or not raw_key.strip():
                raise CanonicalizationError("evidence keys must be non-empty strings")
            normalized_key = raw_key.strip().casefold()
            if normalized_key in output:
                raise CanonicalizationError("evidence keys must be unique")
            output[normalized_key] = canonicalize(raw_value, key=normalized_key)
        return {name: output[name] for name in sorted(output)}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        normalized_items = [canonicalize(item) for item in value]
        return sorted(normalized_items, key=canonical_json)
    raise CanonicalizationError("unsupported evidence value")


def canonical_json(value: Any) -> str:
    """Canonicalize and serialize data without whitespace or unstable ordering."""

    return json.dumps(
        canonicalize(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def observation_payload(context: ScanContext, observation: ScannerObservation) -> dict[str, Any]:
    """Build identity-bearing observation data without timestamp fields."""

    return {
        "adapter_kind": observation.adapter_kind,
        "asset_id": observation.asset_id,
        "confidence": observation.confidence,
        "location": observation.location,
        "metadata": observation.metadata,
        "raw_evidence": observation.raw_evidence,
        "rule_id": observation.rule_id,
        "scope": {"target_id": context.target_id, "tenant_id": context.tenant_id},
        "severity": observation.severity,
        "summary": observation.summary,
        "title": observation.title,
    }


def build_evidence(
    context: ScanContext,
    *,
    source: str,
    kind: str,
    payload: Mapping[str, Any],
    observed_at: datetime | None = None,
) -> EvidenceRecord:
    if kind not in {"observation", "scanner_failure"}:
        raise CanonicalizationError("unsupported evidence kind")
    safe_payload = canonicalize(payload)
    digest = sha256_digest(safe_payload)
    return EvidenceRecord(
        evidence_id=digest,
        kind=kind,  # type: ignore[arg-type]
        source=source,
        tenant_id=context.tenant_id,
        target_id=context.target_id,
        canonical_payload=safe_payload,
        digest=digest,
        observed_at=observed_at or datetime.now().astimezone(),
    )


def finding_fingerprint(
    *,
    tenant_id: str,
    target_id: str,
    adapter_kind: str,
    rule_id: str,
    asset_id: str,
    location: str,
    severity: str,
    confidence: str,
    evidence_id: str,
) -> str:
    """Compute a stable identity that intentionally excludes timestamps."""

    return sha256_digest(
        {
            "adapter_kind": adapter_kind,
            "asset_id": asset_id,
            "confidence": confidence,
            "evidence_id": evidence_id,
            "location": location,
            "rule_id": rule_id,
            "severity": severity,
            "target_id": target_id,
            "tenant_id": tenant_id,
        }
    )
