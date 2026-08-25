"""Typed, sanitized contracts for the durable workflow boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, TypedDict

from ..deployment.preproduction import PreproductionEvidence
from ..services.security import contains_credential_like, contains_credential_like_data

WorkflowPhase = Literal[
    "intake",
    "scope",
    "asset_inventory",
    "backup_gate",
    "parallel_scans",
    "evidence_gate",
    "risk_policy",
    "isolated_workspace",
    "remediation_plan",
    "patch_test",
    "approval",
    "controlled_deploy",
    "post_deploy_verify",
    "rollback",
    "monitor_report",
    "completed",
    "escalated",
]

ActionKind = Literal[
    "asset_inventory",
    "isolated_workspace",
    "remediation_plan",
    "patch_test",
    "controlled_deploy",
    "post_deploy_verify",
    "rollback",
]

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,95}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_SCOPE = ("wordpress", "barnd", "shield", "api.securityola.com", "/var/www")


class WorkflowState(TypedDict, total=False):
    """The only state allowed to cross a checkpoint boundary."""

    workflow_id: str
    tenant_id: str
    application_id: str
    job_id: str
    phase: WorkflowPhase | str
    status: str
    target_environment: Literal["development", "staging", "production"] | str
    preproduction_evidence_ref: str | None
    source_revision: str | None
    artifact_digest: str | None
    risk_level: Literal["low", "medium", "high", "critical"] | str
    backup_status: str
    inventory_status: str
    scan_status: str
    evidence_status: str
    approval_status: str
    deployment_status: str
    rollback_status: str
    scanner_failure_code: str | None
    failure_code: str | None
    retry_budget: int
    timeout_budget_seconds: int
    cost_budget_micros: int
    cost_used_micros: int
    attempts: dict[str, int]
    evidence_refs: list[str]
    finding_refs: list[str]
    ai_explanation_refs: list[str]
    approval_ref: str | None
    deployment_ref: str | None
    rollback_ref: str | None
    verification_passed: bool | None


class WorkflowInput(TypedDict, total=False):
    """Convenience input shape for callers constructing a new workflow."""

    workflow_id: str
    tenant_id: str
    application_id: str
    job_id: str
    target_environment: str
    preproduction_evidence_ref: str
    source_revision: str
    artifact_digest: str
    risk_level: str
    backup_status: str
    retry_budget: int
    timeout_budget_seconds: int
    cost_budget_micros: int


def validate_safe_id(value: str, *, field_name: str) -> str:
    """Validate an opaque identifier and reject path/resource boundary markers."""

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip()
    lowered = normalized.casefold()
    if (
        _SAFE_ID.fullmatch(normalized) is None
        or normalized in {".", ".."}
        or ".." in normalized
        or any(marker in lowered for marker in _FORBIDDEN_SCOPE)
        or contains_credential_like(normalized)
    ):
        raise ValueError(f"{field_name} is outside the AppCare workflow boundary")
    return normalized


def validate_failure_code(value: str, *, field_name: str = "failure_code") -> str:
    """Accept only a short, public-safe machine reason code."""

    if not isinstance(value, str) or _SAFE_CODE.fullmatch(value.strip()) is None:
        raise ValueError(f"{field_name} is malformed")
    if contains_credential_like(value):
        raise ValueError(f"{field_name} is unsafe")
    return value.strip()


def validate_source_revision(value: str, *, field_name: str = "source_revision") -> str:
    """Accept only a bounded Git revision for production evidence binding."""

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a Git revision")
    normalized = value.strip().casefold()
    if _REVISION.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} must be a Git revision")
    return normalized


def validate_artifact_digest(value: str, *, field_name: str = "artifact_digest") -> str:
    """Accept only a SHA-256 artifact identity for production binding."""

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a SHA-256 digest")
    normalized = value.strip().casefold()
    if _SHA256.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} must be a SHA-256 digest")
    return normalized


def validate_checkpoint_state(state: Mapping[str, object]) -> None:
    """Fail closed if a caller tries to checkpoint raw or unbounded data."""

    allowed = {
        "workflow_id",
        "tenant_id",
        "application_id",
        "job_id",
        "phase",
        "status",
        "target_environment",
        "preproduction_evidence_ref",
        "source_revision",
        "artifact_digest",
        "risk_level",
        "backup_status",
        "inventory_status",
        "scan_status",
        "evidence_status",
        "approval_status",
        "deployment_status",
        "rollback_status",
        "scanner_failure_code",
        "failure_code",
        "retry_budget",
        "timeout_budget_seconds",
        "cost_budget_micros",
        "cost_used_micros",
        "attempts",
        "evidence_refs",
        "finding_refs",
        "ai_explanation_refs",
        "approval_ref",
        "deployment_ref",
        "rollback_ref",
        "verification_passed",
    }
    unknown = set(state).difference(allowed)
    if unknown:
        raise ValueError("workflow state contains unsupported fields")
    if any(contains_credential_like_data(value) for value in state.values()):
        raise ValueError("workflow state contains credential-like data")
    for name in ("workflow_id", "tenant_id", "application_id", "job_id"):
        value = state.get(name)
        if not isinstance(value, str):
            raise ValueError(f"workflow state requires {name}")
        validate_safe_id(value, field_name=name)
    for name in (
        "phase",
        "status",
        "target_environment",
        "risk_level",
        "backup_status",
        "inventory_status",
        "scan_status",
        "evidence_status",
        "approval_status",
        "deployment_status",
        "rollback_status",
    ):
        value = state.get(name)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"workflow state {name} is invalid")
            validate_safe_id(value, field_name=name)
    preproduction_ref = state.get("preproduction_evidence_ref")
    if preproduction_ref is not None:
        if not isinstance(preproduction_ref, str):
            raise ValueError("workflow state preproduction_evidence_ref is invalid")
        validate_safe_id(preproduction_ref, field_name="preproduction_evidence_ref")
    source_revision = state.get("source_revision")
    if source_revision is not None:
        if not isinstance(source_revision, str):
            raise ValueError("workflow state source_revision is invalid")
        validate_source_revision(source_revision)
    artifact_digest = state.get("artifact_digest")
    if artifact_digest is not None:
        if not isinstance(artifact_digest, str):
            raise ValueError("workflow state artifact_digest is invalid")
        validate_artifact_digest(artifact_digest)
    for name in ("scanner_failure_code", "failure_code"):
        value = state.get(name)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"workflow state {name} is invalid")
            validate_failure_code(value, field_name=name)
    for name in (
        "retry_budget",
        "timeout_budget_seconds",
        "cost_budget_micros",
        "cost_used_micros",
    ):
        value = state.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"workflow state {name} is invalid")
    for name in ("evidence_refs", "finding_refs", "ai_explanation_refs"):
        values = state.get(name, [])
        if not isinstance(values, list) or len(values) > 100:
            raise ValueError(f"workflow state {name} is invalid")
        for item in values:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"workflow state {name} contains an invalid reference")
            validate_safe_id(item, field_name=name)
    for name in ("approval_ref", "deployment_ref", "rollback_ref"):
        value = state.get(name)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"workflow state {name} is invalid")
            validate_safe_id(value, field_name=name)
    attempts = state.get("attempts", {})
    if not isinstance(attempts, dict) or len(attempts) > 100:
        raise ValueError("workflow state attempts is invalid")
    for key, value in attempts.items():
        validate_safe_id(key, field_name="attempt_key")
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10:
            raise ValueError("workflow state attempts contains an invalid count")
    verification_passed = state.get("verification_passed")
    if verification_passed is not None and not isinstance(verification_passed, bool):
        raise ValueError("workflow state verification_passed is invalid")


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """A deterministic evidence reference supplied by a scanner adapter."""

    evidence_ref: str
    kind: str
    source: str
    digest: str
    summary: Mapping[str, object]

    def __post_init__(self) -> None:
        validate_safe_id(self.evidence_ref, field_name="evidence_ref")
        validate_safe_id(self.kind, field_name="evidence_kind")
        validate_safe_id(self.source, field_name="evidence_source")
        if _SHA256.fullmatch(self.digest) is None:
            raise ValueError("evidence digest must be a SHA-256 hex value")
        if contains_credential_like_data(self.summary):
            raise ValueError("evidence summary contains credential-like data")


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Scanner result where failure is structurally distinct from findings."""

    evidence: tuple[EvidenceItem, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    finding_refs: tuple[str, ...] = ()
    failure_code: str | None = None
    retryable: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "finding_refs", tuple(self.finding_refs))
        if self.failure_code is not None:
            validate_failure_code(self.failure_code)
        for name, values in (
            ("evidence_refs", self.evidence_refs),
            ("finding_refs", self.finding_refs),
        ):
            if len(values) > 100:
                raise ValueError(f"{name} is too large")
            for value in values:
                validate_safe_id(value, field_name=name)
        if self.failure_code is not None and self.finding_refs:
            raise ValueError("scanner failure cannot contain findings")


@dataclass(frozen=True, slots=True)
class ActionResult:
    """Sanitized, bounded result from an injected idempotent action adapter."""

    result_reference: str
    evidence_refs: tuple[str, ...] = ()
    cost_micros: int = 0
    verification_passed: bool | None = None
    attempts: int = 0

    def __post_init__(self) -> None:
        validate_safe_id(self.result_reference, field_name="result_reference")
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        if self.cost_micros < 0 or self.attempts < 0:
            raise ValueError("action result budgets cannot be negative")
        for value in self.evidence_refs:
            validate_safe_id(value, field_name="evidence_ref")


class ActionAdapter(Protocol):
    """Injected boundary for one idempotent, externally controlled action."""

    def execute(
        self, action_key: str, action_kind: ActionKind | str, state: Mapping[str, object]
    ) -> ActionResult:
        """Execute or resume an action using the same idempotency key."""
        ...


class PreproductionEvidenceResolver(Protocol):
    """Resolve persisted preproduction evidence for one production request."""

    def resolve(self, state: Mapping[str, object]) -> PreproductionEvidence | None: ...


class ScanAdapter(Protocol):
    """Injected deterministic scanner boundary."""

    def scan(self, state: Mapping[str, object]) -> ScanResult:
        """Return evidence/findings or a scanner failure, never both."""
        ...


class RetryableWorkflowError(RuntimeError):
    """An adapter failure that may consume a bounded retry budget."""

    def __init__(self, code: str = "retryable_action_failure") -> None:
        self.code = validate_failure_code(code)
        super().__init__(self.code)


class TerminalWorkflowError(RuntimeError):
    """An adapter failure that must not be retried."""

    def __init__(self, code: str = "terminal_action_failure") -> None:
        self.code = validate_failure_code(code)
        super().__init__(self.code)


class WorkflowConfigurationError(ValueError):
    """The workflow runtime or checkpoint boundary is not safe to use."""


__all__ = [
    "ActionAdapter",
    "ActionKind",
    "ActionResult",
    "EvidenceItem",
    "RetryableWorkflowError",
    "ScanAdapter",
    "ScanResult",
    "PreproductionEvidenceResolver",
    "TerminalWorkflowError",
    "WorkflowConfigurationError",
    "WorkflowInput",
    "WorkflowPhase",
    "WorkflowState",
    "validate_checkpoint_state",
    "validate_artifact_digest",
    "validate_failure_code",
    "validate_safe_id",
    "validate_source_revision",
]
