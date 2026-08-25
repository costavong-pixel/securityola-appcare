"""Fail-closed BETA-07 production deployment contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from ..services.security import contains_credential_like, is_safe_credential_reference

LivePreviewStatus = Literal["pass", "blocked", "unverified"]
DeploymentStatus = Literal[
    "approval_pending",
    "approved",
    "deploying",
    "verifying",
    "succeeded",
    "denied",
    "rolling_back",
    "rolled_back",
    "rollback_failed",
    "emergency_stopped",
    "failed",
]

_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,95}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{7,64}$")


class ProductionControlError(ValueError):
    """Raised when a production-control input crosses a trust boundary."""


class DuplicateDeploymentError(ProductionControlError):
    """Raised when one idempotency key is reused for a different intent."""


def validate_opaque_reference(value: object, *, field_name: str = "reference") -> str:
    """Accept a bounded, public-safe reference and never a path or secret value."""

    if not isinstance(value, str):
        raise ProductionControlError(f"{field_name} must be a string")
    normalized = value.strip()
    if (
        _SAFE_REFERENCE.fullmatch(normalized) is None
        or ".." in normalized
        or contains_credential_like(normalized)
    ):
        raise ProductionControlError(f"{field_name} is malformed")
    return normalized


def _digest(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ProductionControlError(f"{field_name} must be a SHA-256 digest")
    normalized = value.strip().casefold()
    if _SHA256.fullmatch(normalized) is None:
        raise ProductionControlError(f"{field_name} must be a SHA-256 digest")
    return normalized


def _revision(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ProductionControlError(f"{field_name} must be a Git revision")
    normalized = value.strip().casefold()
    if _REVISION.fullmatch(normalized) is None:
        raise ProductionControlError(f"{field_name} must be a Git revision")
    return normalized


def validate_reason_code(value: object, *, field_name: str = "reason_code") -> str:
    if not isinstance(value, str) or _SAFE_CODE.fullmatch(value.strip().casefold()) is None:
        raise ProductionControlError(f"{field_name} is malformed")
    normalized = value.strip().casefold()
    if contains_credential_like(normalized):
        raise ProductionControlError(f"{field_name} is unsafe")
    return normalized


def normalize_live_preview_status(value: object) -> LivePreviewStatus:
    if not isinstance(value, str):
        raise ProductionControlError("beta06_verified_live_preview is invalid")
    normalized = value.strip().casefold()
    if normalized not in {"pass", "blocked", "unverified"}:
        raise ProductionControlError("beta06_verified_live_preview is invalid")
    return cast(LivePreviewStatus, normalized)


def live_preview_is_passed(value: object) -> bool:
    try:
        return normalize_live_preview_status(value) == "pass"
    except ProductionControlError:
        return False


def evidence_digest(*parts: str) -> str:
    """Create a deterministic digest over sanitized evidence fields."""

    if not parts or any(not isinstance(part, str) for part in parts):
        raise ProductionControlError("evidence parts are invalid")
    if any(contains_credential_like(part) for part in parts):
        raise ProductionControlError("evidence contains credential-like data")
    encoded = json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class DeploymentIntent:
    """Immutable request describing exactly one intended production artifact."""

    intent_id: str
    tenant_id: str
    application_id: str
    artifact_digest: str
    source_revision: str
    rollback_reference: str
    rollback_artifact_digest: str
    idempotency_key: str
    requested_by: str
    backup_evidence_ref: str
    credential_ref: str
    beta06_verified_live_preview: LivePreviewStatus = "unverified"
    target_environment: Literal["production"] = "production"

    def __post_init__(self) -> None:
        for name in ("intent_id", "tenant_id", "application_id", "idempotency_key", "requested_by"):
            object.__setattr__(
                self,
                name,
                validate_opaque_reference(getattr(self, name), field_name=name),
            )
        object.__setattr__(
            self,
            "backup_evidence_ref",
            validate_opaque_reference(self.backup_evidence_ref, field_name="backup_evidence_ref"),
        )
        if not is_safe_credential_reference(self.credential_ref):
            raise ProductionControlError("credential_ref must be an opaque custody reference")
        object.__setattr__(self, "credential_ref", self.credential_ref.strip())
        object.__setattr__(
            self,
            "artifact_digest",
            _digest(self.artifact_digest, field_name="artifact_digest"),
        )
        object.__setattr__(
            self,
            "rollback_artifact_digest",
            _digest(self.rollback_artifact_digest, field_name="rollback_artifact_digest"),
        )
        object.__setattr__(
            self,
            "source_revision",
            _revision(self.source_revision, field_name="source_revision"),
        )
        object.__setattr__(
            self,
            "rollback_reference",
            _revision(self.rollback_reference, field_name="rollback_reference"),
        )
        object.__setattr__(
            self,
            "beta06_verified_live_preview",
            normalize_live_preview_status(self.beta06_verified_live_preview),
        )
        if self.target_environment != "production":
            raise ProductionControlError("production intent target is immutable")

    @property
    def intent_digest(self) -> str:
        return evidence_digest(
            "deployment-intent",
            self.intent_id,
            self.tenant_id,
            self.application_id,
            self.artifact_digest,
            self.source_revision,
            self.rollback_reference,
            self.rollback_artifact_digest,
            self.idempotency_key,
            self.requested_by,
            self.backup_evidence_ref,
            self.credential_ref,
            self.beta06_verified_live_preview,
            self.target_environment,
        )


@dataclass(frozen=True, slots=True)
class DeploymentApproval:
    """Approval bound to one immutable intent digest."""

    intent_id: str
    approval_id: str
    actor_ref: str
    decision: Literal["approved", "rejected"]
    decision_ref: str
    intent_digest: str

    def __post_init__(self) -> None:
        for name in ("intent_id", "approval_id", "actor_ref", "decision_ref"):
            object.__setattr__(
                self,
                name,
                validate_opaque_reference(getattr(self, name), field_name=name),
            )
        if self.decision not in {"approved", "rejected"}:
            raise ProductionControlError("approval decision is invalid")
        object.__setattr__(
            self, "intent_digest", _digest(self.intent_digest, field_name="intent_digest")
        )


@dataclass(frozen=True, slots=True)
class ProviderDeployment:
    """Sanitized provider response used for exact identity verification."""

    deployment_ref: str
    target_environment: str
    source_revision: str
    artifact_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "deployment_ref",
            validate_opaque_reference(self.deployment_ref, field_name="deployment_ref"),
        )
        object.__setattr__(
            self,
            "target_environment",
            validate_opaque_reference(self.target_environment, field_name="target_environment"),
        )
        object.__setattr__(
            self,
            "source_revision",
            _revision(self.source_revision, field_name="source_revision"),
        )
        object.__setattr__(
            self,
            "artifact_digest",
            _digest(self.artifact_digest, field_name="artifact_digest"),
        )


@dataclass(frozen=True, slots=True)
class ProviderVerification:
    """Sanitized post-deploy verification result."""

    deployment_ref: str
    passed: bool
    verification_ref: str
    failure_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "deployment_ref",
            validate_opaque_reference(self.deployment_ref, field_name="deployment_ref"),
        )
        object.__setattr__(
            self,
            "verification_ref",
            validate_opaque_reference(self.verification_ref, field_name="verification_ref"),
        )
        if self.failure_code is not None:
            object.__setattr__(
                self,
                "failure_code",
                validate_reason_code(self.failure_code, field_name="failure_code"),
            )
        if self.passed and self.failure_code is not None:
            raise ProductionControlError("passed verification cannot carry a failure")


@dataclass(frozen=True, slots=True)
class ProviderRollback:
    """Sanitized rollback result bound to the requested rollback reference."""

    rollback_ref: str
    rollback_reference: str
    succeeded: bool
    failure_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "rollback_ref",
            validate_opaque_reference(self.rollback_ref, field_name="rollback_ref"),
        )
        object.__setattr__(
            self,
            "rollback_reference",
            _revision(self.rollback_reference, field_name="rollback_reference"),
        )
        if self.failure_code is not None:
            object.__setattr__(
                self,
                "failure_code",
                validate_reason_code(self.failure_code, field_name="failure_code"),
            )


@dataclass(frozen=True, slots=True)
class DeploymentEvidence:
    """One append-only, sanitized state transition record."""

    event: str
    intent_id: str
    from_status: str
    to_status: str
    reason_code: str
    digest: str

    def __post_init__(self) -> None:
        normalized_event = validate_reason_code(self.event, field_name="event")
        normalized_intent = validate_opaque_reference(self.intent_id, field_name="intent_id")
        normalized_from = validate_reason_code(self.from_status, field_name="from_status")
        normalized_to = validate_reason_code(self.to_status, field_name="to_status")
        normalized_reason = validate_reason_code(self.reason_code)
        normalized_digest = _digest(self.digest, field_name="evidence_digest")
        expected_digest = evidence_digest(
            normalized_event,
            normalized_intent,
            normalized_from,
            normalized_to,
            normalized_reason,
        )
        if normalized_digest != expected_digest:
            raise ProductionControlError("deployment evidence digest mismatch")
        for name, value in (
            ("event", normalized_event),
            ("intent_id", normalized_intent),
            ("from_status", normalized_from),
            ("to_status", normalized_to),
            ("reason_code", normalized_reason),
            ("digest", normalized_digest),
        ):
            object.__setattr__(self, name, value)

    @classmethod
    def create(
        cls,
        *,
        event: str,
        intent_id: str,
        from_status: str,
        to_status: str,
        reason_code: str,
    ) -> DeploymentEvidence:
        normalized_event = validate_reason_code(event, field_name="event")
        normalized_intent = validate_opaque_reference(intent_id, field_name="intent_id")
        normalized_from = validate_reason_code(from_status, field_name="from_status")
        normalized_to = validate_reason_code(to_status, field_name="to_status")
        normalized_reason = validate_reason_code(reason_code)
        return cls(
            event=normalized_event,
            intent_id=normalized_intent,
            from_status=normalized_from,
            to_status=normalized_to,
            reason_code=normalized_reason,
            digest=evidence_digest(
                normalized_event,
                normalized_intent,
                normalized_from,
                normalized_to,
                normalized_reason,
            ),
        )


class ProductionProvider(Protocol):
    """Injected provider boundary; this package performs no network calls."""

    def deploy(self, intent: DeploymentIntent) -> ProviderDeployment: ...

    def verify(
        self, intent: DeploymentIntent, deployment: ProviderDeployment
    ) -> ProviderVerification: ...

    def rollback(
        self, intent: DeploymentIntent, deployment: ProviderDeployment
    ) -> ProviderRollback: ...


__all__ = [
    "DeploymentApproval",
    "DeploymentEvidence",
    "DeploymentIntent",
    "DeploymentStatus",
    "DuplicateDeploymentError",
    "LivePreviewStatus",
    "ProductionControlError",
    "ProductionProvider",
    "ProviderDeployment",
    "ProviderRollback",
    "ProviderVerification",
    "evidence_digest",
    "live_preview_is_passed",
    "normalize_live_preview_status",
    "validate_opaque_reference",
    "validate_reason_code",
]
