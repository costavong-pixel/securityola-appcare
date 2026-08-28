"""Fail-closed contracts for layered AppCare product readiness.

These contracts deliberately separate platform evidence from customer-service
readiness.  A fixture or reference result can prove a subsystem contract, but
it cannot become real-target evidence merely because a caller labels it ready.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from ..services.security import contains_credential_like


class ReadinessTier(StrEnum):
    """Independent readiness layers, from platform foundation to paid service."""

    CORE = "core"
    STACK = "stack"
    CUSTOMER_ONBOARDING = "customer_onboarding"
    PILOT = "pilot"
    PAID_SERVICE = "paid_service"


class ReadinessStatus(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    PARTIAL = "partial"


class CapabilityStatus(StrEnum):
    SUPPORTED = "supported"
    NEEDS_CLEANUP = "needs_cleanup"
    MISSING_CAPABILITY = "missing_capability"
    UNSUPPORTED = "unsupported"
    BLOCKED_EXTERNAL = "blocked_external"


class SupportabilityStatus(StrEnum):
    SUPPORTED = "supported"
    NEEDS_CLEANUP = "needs_cleanup"
    UNSUPPORTED = "unsupported"


class EvidenceClass(StrEnum):
    FIXTURE = "fixture"
    REFERENCE = "reference"
    CONTROLLED_LIVE_PROVIDER = "controlled_live_provider"
    REAL_TARGET = "real_target"


class CoordinatorDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    BLOCKED = "blocked"


ReadinessLevelName = Literal["core", "stack", "customer_onboarding", "pilot", "paid_service"]
ReadinessLevelStatus = Literal["ready", "blocked", "partial"]

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,95}$")
_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_EVIDENCE_RANK: dict[EvidenceClass, int] = {
    EvidenceClass.FIXTURE: 0,
    EvidenceClass.REFERENCE: 1,
    EvidenceClass.CONTROLLED_LIVE_PROVIDER: 2,
    EvidenceClass.REAL_TARGET: 3,
}

# The accepted coordinator identity is intentionally narrow.  A worker/model
# output string is not an approval object and is never consulted by evaluators.
LUNA_COORDINATOR_REF = "gpt-5.6-luna-max"
REQUIRED_SECURITY_GATE_IDS = tuple(f"s{number:02d}" for number in range(1, 31))


class ReadinessValidationError(ValueError):
    """Raised when evidence crosses a scope, provenance, or safety boundary."""


def validate_scope_segment(value: object, *, field_name: str) -> str:
    """Validate one tenant/application/stack/capability scope segment."""

    if not isinstance(value, str):
        raise ReadinessValidationError(f"{field_name} must be a string")
    normalized = value.strip()
    if (
        _SAFE_SEGMENT.fullmatch(normalized) is None
        or normalized in {".", ".."}
        or ".." in normalized
        or "/" in normalized
        or "\\" in normalized
        or contains_credential_like(normalized)
    ):
        raise ReadinessValidationError(f"{field_name} is outside the AppCare scope")
    return normalized


def validate_evidence_reference(value: object, *, field_name: str = "evidence_ref") -> str:
    """Validate a public-safe opaque evidence reference, never a filesystem path."""

    if not isinstance(value, str):
        raise ReadinessValidationError(f"{field_name} must be a string")
    normalized = value.strip()
    if (
        _SAFE_REFERENCE.fullmatch(normalized) is None
        or normalized in {".", ".."}
        or ".." in normalized
        or normalized.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:[\\/]", normalized) is not None
        or contains_credential_like(normalized)
    ):
        raise ReadinessValidationError(f"{field_name} is unsafe")
    return normalized


def validate_revision(value: object, *, field_name: str = "source_revision") -> str:
    if not isinstance(value, str):
        raise ReadinessValidationError(f"{field_name} must be a Git revision")
    normalized = value.strip().casefold()
    if _REVISION.fullmatch(normalized) is None:
        raise ReadinessValidationError(f"{field_name} must be a Git revision")
    return normalized


def validate_digest(value: object, *, field_name: str = "artifact_digest") -> str:
    if not isinstance(value, str):
        raise ReadinessValidationError(f"{field_name} must be a SHA-256 digest")
    normalized = value.strip().casefold()
    if _SHA256.fullmatch(normalized) is None:
        raise ReadinessValidationError(f"{field_name} must be a SHA-256 digest")
    return normalized


def _aware_timestamp(value: object, *, field_name: str = "observed_at") -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ReadinessValidationError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _coerce_enum[T: StrEnum](value: object, enum_type: type[T], *, field_name: str) -> T:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        raise ReadinessValidationError(f"{field_name} is invalid")
    try:
        return enum_type(value.strip().casefold())
    except ValueError as exc:
        raise ReadinessValidationError(f"{field_name} is invalid") from exc


def evidence_class_at_least(actual: EvidenceClass, minimum: EvidenceClass) -> bool:
    return _EVIDENCE_RANK[actual] >= _EVIDENCE_RANK[minimum]


def _canonical_digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _contains_credential_values(value: object) -> bool:
    """Inspect receipt values without treating safe schema keys as secrets."""

    if isinstance(value, Mapping):
        return any(_contains_credential_values(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_credential_values(item) for item in value)
    return contains_credential_like(value)


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    """One scoped result for one mandatory application capability."""

    tenant_id: str
    application_id: str
    stack_id: str
    capability: str
    status: CapabilityStatus
    evidence_class: EvidenceClass
    evidence_ref: str
    observed_at: datetime
    source_revision: str | None = None
    artifact_digest: str | None = None
    # This field may record a claim, but evaluators never treat it as authority.
    coordinator_decision: CoordinatorDecision | None = None

    def __post_init__(self) -> None:
        for name in ("tenant_id", "application_id", "stack_id", "capability"):
            object.__setattr__(
                self, name, validate_scope_segment(getattr(self, name), field_name=name)
            )
        object.__setattr__(
            self,
            "status",
            _coerce_enum(self.status, CapabilityStatus, field_name="capability_status"),
        )
        object.__setattr__(
            self,
            "evidence_class",
            _coerce_enum(self.evidence_class, EvidenceClass, field_name="evidence_class"),
        )
        object.__setattr__(self, "evidence_ref", validate_evidence_reference(self.evidence_ref))
        object.__setattr__(self, "observed_at", _aware_timestamp(self.observed_at))
        if (self.source_revision is None) != (self.artifact_digest is None):
            raise ReadinessValidationError(
                "source_revision and artifact_digest must be supplied together"
            )
        if self.source_revision is not None:
            object.__setattr__(
                self,
                "source_revision",
                validate_revision(self.source_revision, field_name="source_revision"),
            )
            object.__setattr__(
                self,
                "artifact_digest",
                validate_digest(self.artifact_digest, field_name="artifact_digest"),
            )
        if self.coordinator_decision is not None:
            object.__setattr__(
                self,
                "coordinator_decision",
                _coerce_enum(
                    self.coordinator_decision,
                    CoordinatorDecision,
                    field_name="coordinator_decision",
                ),
            )
        if _contains_credential_values(self.canonical_payload(include_claim=True)):
            raise ReadinessValidationError("capability evidence contains credential-like data")

    def canonical_payload(self, *, include_claim: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "stack_id": self.stack_id,
            "capability": self.capability,
            "status": self.status.value,
            "evidence_class": self.evidence_class.value,
            "evidence_ref": self.evidence_ref,
            "observed_at": self.observed_at.isoformat(),
            "source_revision": self.source_revision,
            "artifact_digest": self.artifact_digest,
        }
        if include_claim:
            payload["coordinator_decision"] = (
                self.coordinator_decision.value
                if isinstance(self.coordinator_decision, CoordinatorDecision)
                else self.coordinator_decision
            )
        return payload

    @property
    def evidence_digest(self) -> str:
        """Digest evidence without allowing an approval claim to alter identity."""

        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class CapabilityResult:
    """Normalized evaluator output for one mandatory capability."""

    tenant_id: str
    application_id: str
    stack_id: str
    capability: str
    status: CapabilityStatus
    evidence_class: EvidenceClass | None
    evidence_ref: str | None
    source_revision: str | None
    artifact_digest: str | None
    observed_at: datetime | None
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("tenant_id", "application_id", "stack_id", "capability"):
            object.__setattr__(
                self, name, validate_scope_segment(getattr(self, name), field_name=name)
            )
        if not isinstance(self.status, CapabilityStatus):
            object.__setattr__(
                self, "status", _coerce_enum(self.status, CapabilityStatus, field_name="status")
            )
        if self.evidence_class is not None and not isinstance(self.evidence_class, EvidenceClass):
            object.__setattr__(
                self,
                "evidence_class",
                _coerce_enum(self.evidence_class, EvidenceClass, field_name="evidence_class"),
            )
        if self.evidence_ref is not None:
            object.__setattr__(self, "evidence_ref", validate_evidence_reference(self.evidence_ref))
        if self.source_revision is not None:
            object.__setattr__(
                self,
                "source_revision",
                validate_revision(self.source_revision, field_name="source_revision"),
            )
        if self.artifact_digest is not None:
            object.__setattr__(
                self,
                "artifact_digest",
                validate_digest(self.artifact_digest, field_name="artifact_digest"),
            )
        if self.observed_at is not None:
            object.__setattr__(self, "observed_at", _aware_timestamp(self.observed_at))
        normalized_reasons = tuple(
            validate_scope_segment(reason, field_name="reason_code") for reason in self.reason_codes
        )
        object.__setattr__(self, "reason_codes", normalized_reasons)


@dataclass(frozen=True, slots=True)
class CoordinatorApproval:
    """An explicit Luna approval bound to an immutable assessment digest."""

    coordinator_ref: str
    decision: CoordinatorDecision
    evidence_digest: str
    approved_at: datetime

    def __post_init__(self) -> None:
        normalized_ref = self.coordinator_ref.strip().casefold()
        if normalized_ref != LUNA_COORDINATOR_REF:
            raise ReadinessValidationError("approval is not from the configured coordinator")
        object.__setattr__(self, "coordinator_ref", normalized_ref)
        object.__setattr__(
            self,
            "decision",
            _coerce_enum(self.decision, CoordinatorDecision, field_name="decision"),
        )
        object.__setattr__(
            self,
            "evidence_digest",
            validate_digest(self.evidence_digest, field_name="evidence_digest"),
        )
        object.__setattr__(
            self, "approved_at", _aware_timestamp(self.approved_at, field_name="approved_at")
        )

    @classmethod
    def for_luna(
        cls,
        evidence_digest: str,
        *,
        decision: CoordinatorDecision = CoordinatorDecision.APPROVE,
        approved_at: datetime | None = None,
    ) -> CoordinatorApproval:
        return cls(
            coordinator_ref=LUNA_COORDINATOR_REF,
            decision=decision,
            evidence_digest=evidence_digest,
            approved_at=approved_at or datetime.now(UTC),
        )


@dataclass(frozen=True, slots=True)
class SupportabilityDecision:
    """Deterministic application supportability result."""

    tenant_id: str
    application_id: str
    stack_id: str
    status: SupportabilityStatus
    mandatory_capability_digest: str
    capability_results: tuple[CapabilityResult, ...]
    blocking_capabilities: tuple[str, ...]
    cleanup_capabilities: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    decided_at: datetime
    coordinator: str | None = None
    coordinator_decision: CoordinatorDecision = CoordinatorDecision.BLOCKED

    def __post_init__(self) -> None:
        for name in ("tenant_id", "application_id", "stack_id"):
            object.__setattr__(
                self, name, validate_scope_segment(getattr(self, name), field_name=name)
            )
        object.__setattr__(
            self,
            "status",
            _coerce_enum(self.status, SupportabilityStatus, field_name="supportability_status"),
        )
        object.__setattr__(
            self,
            "mandatory_capability_digest",
            validate_digest(
                self.mandatory_capability_digest, field_name="mandatory_capability_digest"
            ),
        )
        object.__setattr__(self, "capability_results", tuple(self.capability_results))
        object.__setattr__(
            self,
            "blocking_capabilities",
            tuple(
                validate_scope_segment(item, field_name="blocking_capability")
                for item in self.blocking_capabilities
            ),
        )
        object.__setattr__(
            self,
            "cleanup_capabilities",
            tuple(
                validate_scope_segment(item, field_name="cleanup_capability")
                for item in self.cleanup_capabilities
            ),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            tuple(validate_evidence_reference(item) for item in self.evidence_refs),
        )
        object.__setattr__(
            self,
            "reason_codes",
            tuple(
                validate_scope_segment(item, field_name="reason_code") for item in self.reason_codes
            ),
        )
        object.__setattr__(
            self, "decided_at", _aware_timestamp(self.decided_at, field_name="decided_at")
        )
        if self.coordinator is not None:
            normalized = self.coordinator.strip().casefold()
            if normalized != LUNA_COORDINATOR_REF:
                raise ReadinessValidationError("supportability coordinator is invalid")
            object.__setattr__(self, "coordinator", normalized)
        object.__setattr__(
            self,
            "coordinator_decision",
            _coerce_enum(
                self.coordinator_decision,
                CoordinatorDecision,
                field_name="coordinator_decision",
            ),
        )

    @property
    def authoritative(self) -> bool:
        return (
            self.status == SupportabilityStatus.SUPPORTED
            and self.coordinator == LUNA_COORDINATOR_REF
            and self.coordinator_decision == CoordinatorDecision.APPROVE
        )

    @property
    def assessment_digest(self) -> str:
        approval_reasons = {
            "COORDINATOR_APPROVAL_REQUIRED",
            "COORDINATOR_APPROVAL_BINDING_MISMATCH",
            "COORDINATOR_REJECTED",
        }
        payload = {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "stack_id": self.stack_id,
            "status": self.status.value,
            "mandatory_capability_digest": self.mandatory_capability_digest,
            "capability_results": [
                {
                    "capability": result.capability,
                    "status": result.status.value,
                    "evidence_class": (
                        result.evidence_class.value if result.evidence_class is not None else None
                    ),
                    "evidence_ref": result.evidence_ref,
                    "source_revision": result.source_revision,
                    "artifact_digest": result.artifact_digest,
                    "reason_codes": list(result.reason_codes),
                }
                for result in self.capability_results
            ],
            "blocking_capabilities": list(self.blocking_capabilities),
            "cleanup_capabilities": list(self.cleanup_capabilities),
            "evidence_refs": list(self.evidence_refs),
            "reason_codes": [
                reason for reason in self.reason_codes if reason not in approval_reasons
            ],
        }
        return _canonical_digest(payload)

    def to_public_dict(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "stack_id": self.stack_id,
            "status": self.status.value,
            "authoritative": self.authoritative,
            "mandatory_capability_digest": self.mandatory_capability_digest,
            "blocking_capabilities": list(self.blocking_capabilities),
            "cleanup_capabilities": list(self.cleanup_capabilities),
            "evidence_refs": list(self.evidence_refs),
            "reason_codes": list(self.reason_codes),
            "coordinator_decision": self.coordinator_decision.value,
            "live_customer_production_enabled": False,
        }


@dataclass(frozen=True, slots=True)
class ReadinessEvidence:
    """A layer-specific evidence receipt with explicit provenance class."""

    tenant_id: str
    application_id: str
    level: ReadinessTier
    evidence_ref: str
    evidence_class: EvidenceClass
    passed: bool
    observed_at: datetime
    source_revision: str | None = None
    artifact_digest: str | None = None
    kind: str = "evidence"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "application_id"):
            object.__setattr__(
                self, name, validate_scope_segment(getattr(self, name), field_name=name)
            )
        object.__setattr__(
            self, "level", _coerce_enum(self.level, ReadinessTier, field_name="level")
        )
        object.__setattr__(self, "evidence_ref", validate_evidence_reference(self.evidence_ref))
        object.__setattr__(
            self,
            "evidence_class",
            _coerce_enum(self.evidence_class, EvidenceClass, field_name="evidence_class"),
        )
        if not isinstance(self.passed, bool):
            raise ReadinessValidationError("evidence passed flag is invalid")
        object.__setattr__(self, "observed_at", _aware_timestamp(self.observed_at))
        if (self.source_revision is None) != (self.artifact_digest is None):
            raise ReadinessValidationError("revision and artifact digest must be paired")
        if self.source_revision is not None:
            object.__setattr__(
                self,
                "source_revision",
                validate_revision(self.source_revision, field_name="source_revision"),
            )
            object.__setattr__(
                self,
                "artifact_digest",
                validate_digest(self.artifact_digest, field_name="artifact_digest"),
            )
        object.__setattr__(
            self, "kind", validate_scope_segment(self.kind, field_name="evidence_kind")
        )
        if _contains_credential_values(self.canonical_payload()):
            raise ReadinessValidationError("readiness evidence contains credential-like data")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "level": self.level.value,
            "evidence_ref": self.evidence_ref,
            "evidence_class": self.evidence_class.value,
            "passed": self.passed,
            "observed_at": self.observed_at.isoformat(),
            "source_revision": self.source_revision,
            "artifact_digest": self.artifact_digest,
            "kind": self.kind,
        }

    @property
    def evidence_digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class ReadinessLevel:
    """One independently evaluated readiness layer."""

    level: ReadinessTier
    scope: str
    status: ReadinessStatus
    evidence_refs: tuple[str, ...]
    evaluated_at: datetime
    evaluator: str
    reason_codes: tuple[str, ...] = ()
    evidence_classes: tuple[EvidenceClass, ...] = ()
    evidence_kinds: tuple[str, ...] = ()
    exact_head: str | None = None
    artifact_digest: str | None = None
    coordinator_decision: CoordinatorDecision | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "level", _coerce_enum(self.level, ReadinessTier, field_name="level")
        )
        object.__setattr__(self, "scope", validate_scope_segment(self.scope, field_name="scope"))
        object.__setattr__(
            self, "status", _coerce_enum(self.status, ReadinessStatus, field_name="status")
        )
        object.__setattr__(
            self,
            "evidence_refs",
            tuple(validate_evidence_reference(item) for item in self.evidence_refs),
        )
        object.__setattr__(
            self, "evaluated_at", _aware_timestamp(self.evaluated_at, field_name="evaluated_at")
        )
        object.__setattr__(
            self, "evaluator", validate_scope_segment(self.evaluator, field_name="evaluator")
        )
        object.__setattr__(
            self,
            "reason_codes",
            tuple(
                validate_scope_segment(item, field_name="reason_code") for item in self.reason_codes
            ),
        )
        object.__setattr__(
            self,
            "evidence_classes",
            tuple(
                _coerce_enum(item, EvidenceClass, field_name="evidence_class")
                for item in self.evidence_classes
            ),
        )
        object.__setattr__(
            self,
            "evidence_kinds",
            tuple(
                validate_scope_segment(item, field_name="evidence_kind")
                for item in self.evidence_kinds
            ),
        )
        if self.exact_head is not None:
            object.__setattr__(
                self, "exact_head", validate_revision(self.exact_head, field_name="exact_head")
            )
        if (self.exact_head is None) != (self.artifact_digest is None):
            raise ReadinessValidationError("exact head and artifact digest must be paired")
        if self.artifact_digest is not None:
            object.__setattr__(
                self,
                "artifact_digest",
                validate_digest(self.artifact_digest, field_name="artifact_digest"),
            )
        if self.coordinator_decision is not None:
            object.__setattr__(
                self,
                "coordinator_decision",
                _coerce_enum(
                    self.coordinator_decision,
                    CoordinatorDecision,
                    field_name="coordinator_decision",
                ),
            )

    @property
    def claimed_ready(self) -> bool:
        return self.status == ReadinessStatus.READY

    def canonical_payload(self) -> dict[str, object]:
        return {
            "level": self.level.value,
            "scope": self.scope,
            "status": self.status.value,
            "evidence_refs": list(self.evidence_refs),
            "evaluated_at": self.evaluated_at.isoformat(),
            "evaluator": self.evaluator,
            "reason_codes": list(self.reason_codes),
            "evidence_classes": [item.value for item in self.evidence_classes],
            "evidence_kinds": list(self.evidence_kinds),
            "exact_head": self.exact_head,
            "artifact_digest": self.artifact_digest,
        }

    @property
    def assessment_digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class ReadinessDowngrade:
    """Append-only record of a real-target capability invalidating readiness."""

    previous_level: ReadinessTier
    previous_status: ReadinessStatus
    new_status: ReadinessStatus
    trigger_capability: str
    trigger_evidence_ref: str
    affected_scopes: tuple[str, ...]
    reason_code: str
    recorded_at: datetime
    tenant_id: str | None = None
    application_id: str | None = None
    stack_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "previous_level",
            _coerce_enum(self.previous_level, ReadinessTier, field_name="previous_level"),
        )
        object.__setattr__(
            self,
            "previous_status",
            _coerce_enum(self.previous_status, ReadinessStatus, field_name="previous_status"),
        )
        object.__setattr__(
            self,
            "new_status",
            _coerce_enum(self.new_status, ReadinessStatus, field_name="new_status"),
        )
        object.__setattr__(
            self,
            "trigger_capability",
            validate_scope_segment(self.trigger_capability, field_name="trigger_capability"),
        )
        object.__setattr__(
            self,
            "trigger_evidence_ref",
            validate_evidence_reference(
                self.trigger_evidence_ref, field_name="trigger_evidence_ref"
            ),
        )
        object.__setattr__(
            self,
            "affected_scopes",
            tuple(
                validate_scope_segment(item, field_name="affected_scope")
                for item in self.affected_scopes
            ),
        )
        object.__setattr__(
            self, "reason_code", validate_scope_segment(self.reason_code, field_name="reason_code")
        )
        object.__setattr__(
            self, "recorded_at", _aware_timestamp(self.recorded_at, field_name="recorded_at")
        )
        for name in ("tenant_id", "application_id", "stack_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, validate_scope_segment(value, field_name=name))
        if (self.tenant_id is None) != (self.application_id is None):
            raise ReadinessValidationError("downgrade tenant and application must be paired")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "previous_level": self.previous_level.value,
            "previous_status": self.previous_status.value,
            "new_status": self.new_status.value,
            "trigger_capability": self.trigger_capability,
            "trigger_evidence_ref": self.trigger_evidence_ref,
            "affected_scopes": list(self.affected_scopes),
            "reason_code": self.reason_code,
            "recorded_at": self.recorded_at.isoformat(),
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "stack_id": self.stack_id,
        }

    @property
    def event_digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class SecurityGateDecision:
    """Authoritative binding for the complete pre-beta security gate."""

    release_candidate_sha: str
    gate_version: str
    individual_gate_results: Mapping[str, bool]
    security_findings_open: int
    codex_security_refs: tuple[str, ...] = ()
    dependency_audit_ref: str | None = None
    secret_scan_ref: str | None = None
    graphify_ref: str | None = None
    saveruflo_ref: str | None = None
    exact_head_ci_ref: str | None = None
    real_target_security_ref: str | None = None
    known_limitations_ref: str | None = None
    coordinator_decision: CoordinatorDecision = CoordinatorDecision.BLOCKED
    decided_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "release_candidate_sha",
            validate_revision(self.release_candidate_sha, field_name="release_candidate_sha"),
        )
        object.__setattr__(
            self,
            "gate_version",
            validate_scope_segment(self.gate_version, field_name="gate_version"),
        )
        if not isinstance(self.individual_gate_results, Mapping):
            raise ReadinessValidationError("security gate results must be a mapping")
        normalized: dict[str, bool] = {}
        for key, result in self.individual_gate_results.items():
            normalized_key = validate_scope_segment(key, field_name="security_gate_id").casefold()
            if not isinstance(result, bool):
                raise ReadinessValidationError("security gate result must be boolean")
            normalized[normalized_key] = result
        object.__setattr__(self, "individual_gate_results", dict(sorted(normalized.items())))
        if (
            not isinstance(self.security_findings_open, int)
            or isinstance(self.security_findings_open, bool)
            or self.security_findings_open < 0
        ):
            raise ReadinessValidationError("security findings count is invalid")
        object.__setattr__(
            self,
            "codex_security_refs",
            tuple(validate_evidence_reference(item) for item in self.codex_security_refs),
        )
        for name in (
            "dependency_audit_ref",
            "secret_scan_ref",
            "graphify_ref",
            "saveruflo_ref",
            "exact_head_ci_ref",
            "real_target_security_ref",
            "known_limitations_ref",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, validate_evidence_reference(value, field_name=name))
        object.__setattr__(
            self,
            "coordinator_decision",
            _coerce_enum(
                self.coordinator_decision, CoordinatorDecision, field_name="coordinator_decision"
            ),
        )
        object.__setattr__(
            self, "decided_at", _aware_timestamp(self.decided_at, field_name="decided_at")
        )
        if _contains_credential_values(self.canonical_payload()):
            raise ReadinessValidationError("security gate evidence contains credential-like data")

    @property
    def missing_gate_ids(self) -> tuple[str, ...]:
        return tuple(
            item for item in REQUIRED_SECURITY_GATE_IDS if item not in self.individual_gate_results
        )

    @property
    def failed_gate_ids(self) -> tuple[str, ...]:
        return tuple(
            item
            for item in REQUIRED_SECURITY_GATE_IDS
            if self.individual_gate_results.get(item) is False
        )

    @property
    def passed(self) -> bool:
        return (
            not self.missing_gate_ids
            and not self.failed_gate_ids
            and self.security_findings_open == 0
            and self.coordinator_decision == CoordinatorDecision.APPROVE
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "release_candidate_sha": self.release_candidate_sha,
            "gate_version": self.gate_version,
            "individual_gate_results": dict(self.individual_gate_results),
            "security_findings_open": self.security_findings_open,
            "codex_security_refs": list(self.codex_security_refs),
            "dependency_audit_ref": self.dependency_audit_ref,
            "secret_scan_ref": self.secret_scan_ref,
            "graphify_ref": self.graphify_ref,
            "saveruflo_ref": self.saveruflo_ref,
            "exact_head_ci_ref": self.exact_head_ci_ref,
            "real_target_security_ref": self.real_target_security_ref,
            "known_limitations_ref": self.known_limitations_ref,
            "coordinator_decision": self.coordinator_decision.value,
            "decided_at": self.decided_at.isoformat(),
        }

    @property
    def evidence_digest(self) -> str:
        return _canonical_digest(self.canonical_payload())


@dataclass(frozen=True, slots=True)
class LayeredReadinessDecision:
    """All five readiness layers, with global production permanently disabled."""

    levels: tuple[ReadinessLevel, ...]
    evidence_digest: str
    tenant_id: str | None = None
    application_id: str | None = None
    stack_id: str | None = None
    reason_codes: tuple[str, ...] = ()
    coordinator_decision: CoordinatorDecision = CoordinatorDecision.BLOCKED
    coordinator: str | None = None
    live_customer_production_enabled: Literal[False] = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "levels", tuple(self.levels))
        keys = [item.level for item in self.levels]
        if len(keys) != len(set(keys)):
            raise ReadinessValidationError("readiness levels must be unique")
        object.__setattr__(
            self,
            "evidence_digest",
            validate_digest(self.evidence_digest, field_name="evidence_digest"),
        )
        for name in ("tenant_id", "application_id", "stack_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, validate_scope_segment(value, field_name=name))
        object.__setattr__(
            self,
            "reason_codes",
            tuple(
                validate_scope_segment(item, field_name="reason_code") for item in self.reason_codes
            ),
        )
        object.__setattr__(
            self,
            "coordinator_decision",
            _coerce_enum(
                self.coordinator_decision, CoordinatorDecision, field_name="coordinator_decision"
            ),
        )
        if self.coordinator is not None:
            normalized = self.coordinator.strip().casefold()
            if normalized != LUNA_COORDINATOR_REF:
                raise ReadinessValidationError("readiness coordinator is invalid")
            object.__setattr__(self, "coordinator", normalized)

    @property
    def authoritative(self) -> bool:
        return (
            self.coordinator == LUNA_COORDINATOR_REF
            and self.coordinator_decision == CoordinatorDecision.APPROVE
            and all(item.status == ReadinessStatus.READY for item in self.levels)
            and all(
                item.coordinator_decision == CoordinatorDecision.APPROVE for item in self.levels
            )
        )

    def for_level(self, level: ReadinessTier | str) -> ReadinessLevel:
        normalized = _coerce_enum(level, ReadinessTier, field_name="level")
        for item in self.levels:
            if item.level == normalized:
                return item
        raise ReadinessValidationError(f"readiness level is missing: {normalized.value}")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "stack_id": self.stack_id,
            "levels": [
                {
                    "level": item.level.value,
                    "scope": item.scope,
                    "status": item.status.value,
                    "evidence_refs": list(item.evidence_refs),
                    "reason_codes": list(item.reason_codes),
                    "evidence_classes": [value.value for value in item.evidence_classes],
                }
                for item in self.levels
            ],
            "evidence_digest": self.evidence_digest,
            "reason_codes": list(self.reason_codes),
            "coordinator_decision": self.coordinator_decision.value,
            "authoritative": self.authoritative,
            "live_customer_production_enabled": False,
        }


@dataclass(frozen=True, slots=True)
class DowngradeResult:
    """Result of applying an append-only readiness downgrade."""

    decision: LayeredReadinessDecision
    events: tuple[ReadinessDowngrade, ...]


__all__ = [
    "CapabilityEvidence",
    "CapabilityResult",
    "CapabilityStatus",
    "CoordinatorApproval",
    "CoordinatorDecision",
    "DowngradeResult",
    "EvidenceClass",
    "LayeredReadinessDecision",
    "LUNA_COORDINATOR_REF",
    "PRE_BETA_SECURITY_GATE_IDS",
    "ReadinessDowngrade",
    "ReadinessEvidence",
    "ReadinessLevel",
    "ReadinessLevelName",
    "ReadinessStatus",
    "ReadinessTier",
    "ReadinessValidationError",
    "REQUIRED_SECURITY_GATE_IDS",
    "SecurityGateDecision",
    "SupportabilityDecision",
    "SupportabilityStatus",
    "evidence_class_at_least",
    "validate_digest",
    "validate_evidence_reference",
    "validate_revision",
    "validate_scope_segment",
]

# Backward-friendly alias matching the governance vocabulary.
PRE_BETA_SECURITY_GATE_IDS = REQUIRED_SECURITY_GATE_IDS
