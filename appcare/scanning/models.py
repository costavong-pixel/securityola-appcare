"""Immutable domain records for the BETA-03 scanning foundation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Literal

from appcare.services.security import contains_credential_like, contains_credential_like_data

AdapterKind = Literal["source", "secret", "dependency"]
EvidenceKind = Literal["observation", "scanner_failure"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "high", "medium", "low"]
FailureCode = Literal[
    "timeout",
    "unavailable",
    "execution_error",
    "malformed_output",
    "validation_error",
    "out_of_scope",
    "secret_rejected",
]
FindingStatus = Literal["active", "suppressed"]

ADAPTER_KINDS: frozenset[str] = frozenset({"source", "secret", "dependency"})
SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})
CONFIDENCES: frozenset[str] = frozenset({"confirmed", "high", "medium", "low"})
FAILURE_CODES: frozenset[str] = frozenset(
    {
        "timeout",
        "unavailable",
        "execution_error",
        "malformed_output",
        "validation_error",
        "out_of_scope",
        "secret_rejected",
    }
)
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{1,127}$")


def utcnow() -> datetime:
    """Return an aware timestamp for non-identity metadata."""

    return datetime.now(UTC)


def _identifier(value: str, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip().casefold()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} is malformed")
    return normalized


def _rule(value: str, *, field_name: str = "rule_id") -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip().casefold()
    if _RULE_ID.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} is malformed")
    return normalized


def _mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise ValueError("metadata must be a mapping")
    if contains_credential_like_data(value):
        raise ValueError("metadata contains unsafe credential-like data")
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Authorized tenant/target scope for one bounded scan."""

    tenant_id: str
    target_id: str
    target_kind: str = "application"
    scan_id: str = "scan-0"
    adapter_allowlist: tuple[AdapterKind, ...] = ("source", "secret", "dependency")
    enabled: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(self, "target_id", _identifier(self.target_id, field_name="target_id"))
        object.__setattr__(
            self, "target_kind", _identifier(self.target_kind, field_name="target_kind")
        )
        object.__setattr__(self, "scan_id", _identifier(self.scan_id, field_name="scan_id"))
        normalized = tuple(dict.fromkeys(self.adapter_allowlist))
        if not normalized or any(item not in ADAPTER_KINDS for item in normalized):
            raise ValueError("adapter_allowlist contains an unsupported adapter")
        object.__setattr__(self, "adapter_allowlist", normalized)
        if not self.enabled:
            raise ValueError("scan context must be enabled")


@dataclass(frozen=True, slots=True)
class SanitizedTargetInput:
    """Bounded target input passed to an adapter; payload remains untrusted."""

    target_id: str
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_id", _identifier(self.target_id, field_name="target_id"))
        object.__setattr__(self, "payload", _mapping(self.payload))


@dataclass(frozen=True, slots=True)
class ScannerObservation:
    """Untrusted candidate observation returned by an adapter."""

    adapter_kind: AdapterKind
    rule_id: str
    title: str
    summary: str
    location: str
    asset_id: str
    severity: Severity
    confidence: Confidence
    raw_evidence: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    tenant_id: str | None = None
    target_id: str | None = None
    observed_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.adapter_kind not in ADAPTER_KINDS:
            raise ValueError("unsupported adapter kind")
        object.__setattr__(self, "rule_id", _rule(self.rule_id))
        for name in ("title", "summary", "location"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or contains_credential_like(value):
                raise ValueError(f"{name} is unsafe or empty")
            object.__setattr__(self, name, value.strip())
        object.__setattr__(self, "asset_id", _identifier(self.asset_id, field_name="asset_id"))
        if self.severity not in SEVERITIES or self.confidence not in CONFIDENCES:
            raise ValueError("unsupported severity or confidence")
        object.__setattr__(self, "raw_evidence", _mapping(self.raw_evidence))
        object.__setattr__(self, "metadata", _mapping(self.metadata))
        if self.tenant_id is not None:
            object.__setattr__(
                self, "tenant_id", _identifier(self.tenant_id, field_name="tenant_id")
            )
        if self.target_id is not None:
            object.__setattr__(
                self, "target_id", _identifier(self.target_id, field_name="target_id")
            )
        timestamp = self.observed_at or utcnow()
        if timestamp.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        object.__setattr__(self, "observed_at", timestamp.astimezone(UTC))


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Sanitized proof created before a finding or failure is returned."""

    evidence_id: str
    kind: EvidenceKind
    source: str
    tenant_id: str
    target_id: str
    canonical_payload: Mapping[str, Any]
    digest: str
    observed_at: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        if self.kind not in {"observation", "scanner_failure"}:
            raise ValueError("unsupported evidence kind")
        object.__setattr__(
            self, "evidence_id", _identifier(self.evidence_id, field_name="evidence_id")
        )
        object.__setattr__(self, "source", _rule(self.source, field_name="source"))
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(self, "target_id", _identifier(self.target_id, field_name="target_id"))
        object.__setattr__(self, "canonical_payload", _mapping(self.canonical_payload))
        if not re.fullmatch(r"[0-9a-f]{64}", self.digest):
            raise ValueError("digest must be a SHA-256 hex value")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class Finding:
    """Normalized security result derived only from deterministic evidence."""

    fingerprint: str
    rule_id: str
    title: str
    description: str
    location: str
    asset_id: str
    adapter_kind: AdapterKind
    tenant_id: str
    target_id: str
    severity: Severity
    confidence: Confidence
    evidence_ids: tuple[str, ...]
    remediation: Mapping[str, Any] = field(default_factory=dict)
    status: FindingStatus = "active"
    suppression_reason: str | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint):
            raise ValueError("fingerprint must be a SHA-256 hex value")
        if self.adapter_kind not in ADAPTER_KINDS:
            raise ValueError("unsupported adapter kind")
        object.__setattr__(self, "rule_id", _rule(self.rule_id))
        object.__setattr__(self, "asset_id", _identifier(self.asset_id, field_name="asset_id"))
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(self, "target_id", _identifier(self.target_id, field_name="target_id"))
        if self.severity not in SEVERITIES or self.confidence not in CONFIDENCES:
            raise ValueError("unsupported severity or confidence")
        if self.status not in {"active", "suppressed"} or not self.evidence_ids:
            raise ValueError("finding status or evidence is invalid")
        evidence_ids = tuple(sorted(set(self.evidence_ids)))
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in evidence_ids):
            raise ValueError("evidence_ids must be SHA-256 values")
        object.__setattr__(self, "evidence_ids", evidence_ids)
        if any(
            not isinstance(value, str) or contains_credential_like(value)
            for value in (self.title, self.description, self.location)
        ):
            raise ValueError("finding text is unsafe")
        object.__setattr__(self, "remediation", _mapping(self.remediation))
        if self.status == "suppressed" and not self.suppression_reason:
            raise ValueError("suppressed findings require a reason")


@dataclass(frozen=True, slots=True)
class ScannerFailure:
    """Non-finding result describing scanner or pipeline failure."""

    failure_id: str
    code: FailureCode
    adapter_kind: AdapterKind
    message: str
    tenant_id: str
    target_id: str
    evidence_id: str | None = None
    retryable: bool = False

    def __post_init__(self) -> None:
        if self.code not in FAILURE_CODES or self.adapter_kind not in ADAPTER_KINDS:
            raise ValueError("unsupported scanner failure")
        object.__setattr__(
            self, "failure_id", _identifier(self.failure_id, field_name="failure_id")
        )
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(self, "target_id", _identifier(self.target_id, field_name="target_id"))
        if (
            not isinstance(self.message, str)
            or not self.message.strip()
            or contains_credential_like(self.message)
        ):
            raise ValueError("failure message is unsafe")
        if self.evidence_id is not None and not re.fullmatch(r"[0-9a-f]{64}", self.evidence_id):
            raise ValueError("failure evidence_id must be a SHA-256 value")


@dataclass(frozen=True, slots=True)
class Suppression:
    """Tenant-scoped, evidence-preserving false-positive decision."""

    fingerprint: str
    tenant_id: str
    target_id: str
    reason: str
    actor: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint):
            raise ValueError("fingerprint must be a SHA-256 hex value")
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(self, "target_id", _identifier(self.target_id, field_name="target_id"))
        for name in ("reason", "actor"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or contains_credential_like(value):
                raise ValueError(f"{name} is unsafe or empty")
            object.__setattr__(self, name, value.strip())


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """Exactly one adapter success or failure outcome."""

    adapter_kind: AdapterKind
    observations: tuple[ScannerObservation, ...] = ()
    failure: ScannerFailure | None = None

    def __post_init__(self) -> None:
        if self.adapter_kind not in ADAPTER_KINDS:
            raise ValueError("unsupported adapter kind")
        if self.failure is not None and self.observations:
            raise ValueError("adapter result cannot contain observations and failure")
        if self.failure is not None and self.failure.adapter_kind != self.adapter_kind:
            raise ValueError("failure adapter kind does not match result")

    @classmethod
    def success(
        cls, adapter_kind: AdapterKind, observations: Sequence[ScannerObservation]
    ) -> AdapterResult:
        return cls(adapter_kind=adapter_kind, observations=tuple(observations))

    @classmethod
    def failed(cls, adapter_kind: AdapterKind, failure: ScannerFailure) -> AdapterResult:
        return cls(adapter_kind=adapter_kind, failure=failure)


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Complete deterministic output of one bounded scan."""

    findings: tuple[Finding, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()
    failures: tuple[ScannerFailure, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "failures", tuple(self.failures))
