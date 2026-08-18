"""Immutable, secret-safe contracts for bounded remediation work."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Protocol

from appcare.services.security import contains_credential_like, contains_credential_like_data

Operation = Literal["add", "modify"]
GateKind = Literal[
    "regression", "security", "scope", "integrity", "preview_smoke", "preview_security"
]
GateStatus = Literal["passed", "failed", "blocked", "unavailable"]
PreviewMode = Literal["fixture", "live"]
PreviewStatus = Literal["passed", "failed", "blocked"]
PatchValidationStatus = Literal["passed", "blocked"]
ApprovalStatus = Literal["pending", "approved", "rejected", "expired"]
ApprovalDecision = Literal["approved", "rejected"]

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_SHORT_CODE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{1,127}$")
_PROJECT_REFERENCE = re.compile(
    r"^appcare://[a-z0-9][a-z0-9_-]{1,63}(?:/[a-z0-9][a-z0-9_.-]{0,63})*$"
)
_ALLOWED_PREVIEW_SCOPES = frozenset({"preview:deploy", "preview:read"})
_MAX_CONTENT_BYTES = 256 * 1024
_MAX_SUMMARY_LENGTH = 500


class RemediationBoundaryError(ValueError):
    """Raised when a remediation input crosses a trust boundary."""


def _id(value: str, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise RemediationBoundaryError(f"{field_name} is malformed")
    normalized = value.strip().casefold()
    if _SAFE_ID.fullmatch(normalized) is None:
        raise RemediationBoundaryError(f"{field_name} is malformed")
    return normalized


def _code(value: str, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise RemediationBoundaryError(f"{field_name} is malformed")
    normalized = value.strip().casefold()
    if _SHORT_CODE.fullmatch(normalized) is None:
        raise RemediationBoundaryError(f"{field_name} is malformed")
    return normalized


def _digest(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value.strip().casefold()) is None:
        raise RemediationBoundaryError(f"{field_name} must be a SHA-256 digest")
    return value.strip().casefold()


def _revision(value: str, *, field_name: str = "source_revision") -> str:
    if not isinstance(value, str) or _REVISION.fullmatch(value.strip().casefold()) is None:
        raise RemediationBoundaryError(f"{field_name} must be a Git revision reference")
    return value.strip().casefold()


def _refs(values: Sequence[str], *, field_name: str = "evidence_refs") -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(_digest(value, field_name=field_name) for value in values))
    if not normalized or len(normalized) > 100:
        raise RemediationBoundaryError(f"{field_name} is empty or exceeds its bound")
    return normalized


def _safe_text(value: str, *, field_name: str, max_length: int = _MAX_SUMMARY_LENGTH) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise RemediationBoundaryError(f"{field_name} is empty or too long")
    if contains_credential_like(value):
        raise RemediationBoundaryError(f"{field_name} contains credential-like data")
    return value.strip()


def _safe_mapping(value: Mapping[str, object], *, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or contains_credential_like_data(value):
        raise RemediationBoundaryError(f"{field_name} contains unsafe data")
    if len(value) > 50:
        raise RemediationBoundaryError(f"{field_name} exceeds its item bound")
    return MappingProxyType(dict(value))


def _utc(value: datetime | None = None) -> datetime:
    timestamp = value or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise RemediationBoundaryError("timestamp must be timezone-aware")
    return timestamp.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class RemediationContext:
    """One tenant/application/job remediation scope."""

    tenant_id: str
    application_id: str
    job_id: str
    finding_fingerprint: str
    source_revision: str
    environment: Literal["development", "staging", "test"] = "test"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _id(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(
            self, "application_id", _id(self.application_id, field_name="application_id")
        )
        object.__setattr__(self, "job_id", _id(self.job_id, field_name="job_id"))
        object.__setattr__(
            self,
            "finding_fingerprint",
            _digest(self.finding_fingerprint, field_name="finding_fingerprint"),
        )
        object.__setattr__(self, "source_revision", _revision(self.source_revision))
        if self.environment not in {"development", "staging", "test"}:
            raise RemediationBoundaryError("remediation environment cannot be production")


@dataclass(frozen=True, slots=True)
class RemediationWorkspace:
    """Canonical disposable workspace returned by the workspace manager."""

    workspace_id: str
    context: RemediationContext
    root: Path
    created_at: datetime = field(default_factory=_utc)

    def __post_init__(self) -> None:
        object.__setattr__(self, "workspace_id", _id(self.workspace_id, field_name="workspace_id"))
        if not self.root.is_absolute():
            raise RemediationBoundaryError("workspace root must be absolute")
        object.__setattr__(self, "created_at", _utc(self.created_at))


@dataclass(frozen=True, slots=True)
class FileChange:
    """A bounded text-file add/modify operation."""

    path: str
    operation: Operation
    before_digest: str | None
    after_digest: str
    content: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.strip():
            raise RemediationBoundaryError("file change path is empty")
        if self.operation not in {"add", "modify"}:
            raise RemediationBoundaryError("file change operation is unsupported")
        if self.operation == "add" and self.before_digest is not None:
            raise RemediationBoundaryError("add changes cannot have a preimage")
        if self.operation == "modify" and self.before_digest is None:
            raise RemediationBoundaryError("modify changes require a preimage")
        if self.before_digest is not None:
            object.__setattr__(
                self,
                "before_digest",
                _digest(self.before_digest, field_name="before_digest"),
            )
        object.__setattr__(
            self, "after_digest", _digest(self.after_digest, field_name="after_digest")
        )
        if not isinstance(self.content, str) or not self.content or "\x00" in self.content:
            raise RemediationBoundaryError("file change content is invalid")
        if len(self.content.encode("utf-8")) > _MAX_CONTENT_BYTES:
            raise RemediationBoundaryError("file change content exceeds its bound")
        if contains_credential_like(self.content):
            raise RemediationBoundaryError("file change content contains credential-like data")
        actual = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        if actual != self.after_digest:
            raise RemediationBoundaryError("file change postimage digest does not match content")


@dataclass(frozen=True, slots=True)
class PatchCandidate:
    """Reviewable patch derived from deterministic evidence."""

    patch_id: str
    context: RemediationContext
    evidence_refs: tuple[str, ...]
    changes: tuple[FileChange, ...]
    source_revision: str
    reference_commit: str
    rollback_reference: str
    patch_digest: str
    created_at: datetime = field(default_factory=_utc)

    def __post_init__(self) -> None:
        object.__setattr__(self, "patch_id", _digest(self.patch_id, field_name="patch_id"))
        object.__setattr__(self, "evidence_refs", _refs(self.evidence_refs))
        changes = tuple(self.changes)
        if not changes or len(changes) > 100:
            raise RemediationBoundaryError("patch changes are empty or exceed their bound")
        if len({change.path for change in changes}) != len(changes):
            raise RemediationBoundaryError("patch contains duplicate paths")
        object.__setattr__(self, "changes", changes)
        object.__setattr__(self, "source_revision", _revision(self.source_revision))
        object.__setattr__(
            self,
            "reference_commit",
            _revision(self.reference_commit, field_name="reference_commit"),
        )
        object.__setattr__(
            self,
            "rollback_reference",
            _revision(self.rollback_reference, field_name="rollback_reference"),
        )
        object.__setattr__(
            self, "patch_digest", _digest(self.patch_digest, field_name="patch_digest")
        )
        object.__setattr__(self, "created_at", _utc(self.created_at))


@dataclass(frozen=True, slots=True)
class ReviewEvidence:
    """Sanitized evidence presented to a reviewer."""

    patch_id: str
    finding_fingerprint: str
    evidence_refs: tuple[str, ...]
    source_revision: str
    reference_commit: str
    rollback_reference: str
    patch_digest: str
    changed_paths: tuple[str, ...]
    gate_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "patch_id", _digest(self.patch_id, field_name="patch_id"))
        object.__setattr__(
            self,
            "finding_fingerprint",
            _digest(self.finding_fingerprint, field_name="finding_fingerprint"),
        )
        object.__setattr__(self, "evidence_refs", _refs(self.evidence_refs))
        object.__setattr__(self, "source_revision", _revision(self.source_revision))
        object.__setattr__(
            self,
            "reference_commit",
            _revision(self.reference_commit, field_name="reference_commit"),
        )
        object.__setattr__(
            self,
            "rollback_reference",
            _revision(self.rollback_reference, field_name="rollback_reference"),
        )
        object.__setattr__(
            self, "patch_digest", _digest(self.patch_digest, field_name="patch_digest")
        )
        paths = tuple(dict.fromkeys(self.changed_paths))
        if not paths or len(paths) > 100 or any(not isinstance(path, str) for path in paths):
            raise RemediationBoundaryError("changed_paths are invalid")
        object.__setattr__(self, "changed_paths", paths)
        object.__setattr__(self, "gate_refs", _refs(self.gate_refs) if self.gate_refs else ())


@dataclass(frozen=True, slots=True)
class PatchValidationResult:
    """Sanitized scope/integrity result for one patch candidate."""

    patch_id: str
    status: PatchValidationStatus
    code: str
    evidence_ref: str
    changed_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "patch_id", _digest(self.patch_id, field_name="patch_id"))
        if self.status not in {"passed", "blocked"}:
            raise RemediationBoundaryError("patch validation status is unsupported")
        object.__setattr__(self, "code", _code(self.code, field_name="patch validation code"))
        object.__setattr__(
            self, "evidence_ref", _digest(self.evidence_ref, field_name="evidence_ref")
        )
        paths = tuple(dict.fromkeys(self.changed_paths))
        if len(paths) > 100 or any(not isinstance(path, str) or not path for path in paths):
            raise RemediationBoundaryError("patch validation paths are invalid")
        object.__setattr__(self, "changed_paths", paths)


@dataclass(frozen=True, slots=True)
class GateResult:
    """One deterministic regression/security gate outcome."""

    kind: GateKind
    status: GateStatus
    code: str
    evidence_ref: str
    attempts: int = 1
    summary: str = ""

    def __post_init__(self) -> None:
        if self.kind not in {
            "regression",
            "security",
            "scope",
            "integrity",
            "preview_smoke",
            "preview_security",
        }:
            raise RemediationBoundaryError("gate kind is unsupported")
        if self.status not in {"passed", "failed", "blocked", "unavailable"}:
            raise RemediationBoundaryError("gate status is unsupported")
        object.__setattr__(self, "code", _code(self.code, field_name="gate code"))
        object.__setattr__(
            self, "evidence_ref", _digest(self.evidence_ref, field_name="evidence_ref")
        )
        if self.attempts < 1 or self.attempts > 3:
            raise RemediationBoundaryError("gate attempts are outside the bound")
        if self.summary:
            object.__setattr__(self, "summary", _safe_text(self.summary, field_name="gate summary"))


@dataclass(frozen=True, slots=True)
class PreviewPolicy:
    """Allowlist for a non-production preview boundary."""

    provider: Literal["vercel"]
    project_reference: str
    environment: Literal["preview"]
    skill_revision: str
    skill_reviewed: bool
    provider_scope: tuple[str, ...]
    mode: PreviewMode = "fixture"

    def __post_init__(self) -> None:
        if self.provider != "vercel" or self.environment != "preview":
            raise RemediationBoundaryError("preview policy is outside the supported boundary")
        if _PROJECT_REFERENCE.fullmatch(self.project_reference) is None:
            raise RemediationBoundaryError("preview project reference is not AppCare-owned")
        object.__setattr__(
            self, "skill_revision", _code(self.skill_revision, field_name="skill_revision")
        )
        scopes = tuple(dict.fromkeys(self.provider_scope))
        if not scopes or len(scopes) > 10:
            raise RemediationBoundaryError("preview provider scope is invalid")
        normalized_scopes = tuple(_code(scope, field_name="provider_scope") for scope in scopes)
        if normalized_scopes != scopes:
            raise RemediationBoundaryError("preview provider scope is not normalized")
        if set(scopes) - _ALLOWED_PREVIEW_SCOPES or "preview:deploy" not in scopes:
            raise RemediationBoundaryError("preview provider scope is not allowlisted")
        object.__setattr__(self, "provider_scope", scopes)
        if self.mode not in {"fixture", "live"}:
            raise RemediationBoundaryError("preview mode is unsupported")


@dataclass(frozen=True, slots=True)
class PreviewRequest:
    """Validated preview request; it carries no credentials."""

    preview_id: str
    patch_id: str
    tenant_id: str
    application_id: str
    rollback_reference: str
    policy: PreviewPolicy
    patch_validated: bool
    gates_passed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "preview_id", _digest(self.preview_id, field_name="preview_id"))
        object.__setattr__(self, "patch_id", _digest(self.patch_id, field_name="patch_id"))
        object.__setattr__(self, "tenant_id", _id(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(
            self, "application_id", _id(self.application_id, field_name="application_id")
        )
        object.__setattr__(
            self,
            "rollback_reference",
            _revision(self.rollback_reference, field_name="rollback_reference"),
        )
        if not self.patch_validated or not self.gates_passed:
            raise RemediationBoundaryError("preview requires passed patch and test gates")


@dataclass(frozen=True, slots=True)
class PreviewResult:
    """Sanitized result of fixture or denied preview execution."""

    preview_id: str
    patch_id: str
    tenant_id: str
    rollback_reference: str
    status: PreviewStatus
    code: str
    evidence_refs: tuple[str, ...] = ()
    preview_reference: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "preview_id", _digest(self.preview_id, field_name="preview_id"))
        object.__setattr__(self, "patch_id", _digest(self.patch_id, field_name="patch_id"))
        object.__setattr__(self, "tenant_id", _id(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(
            self,
            "rollback_reference",
            _revision(self.rollback_reference, field_name="rollback_reference"),
        )
        if self.status not in {"passed", "failed", "blocked"}:
            raise RemediationBoundaryError("preview status is unsupported")
        object.__setattr__(self, "code", _code(self.code, field_name="preview code"))
        object.__setattr__(
            self, "evidence_refs", _refs(self.evidence_refs) if self.evidence_refs else ()
        )
        if self.preview_reference is not None:
            object.__setattr__(
                self,
                "preview_reference",
                _safe_text(self.preview_reference, field_name="preview_reference", max_length=300),
            )


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Tenant-scoped internal approval record without release authority."""

    approval_id: str
    tenant_id: str
    patch_id: str
    preview_id: str
    rollback_reference: str
    status: ApprovalStatus = "pending"
    decision_ref: str | None = None
    actor_tenant_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "approval_id", _digest(self.approval_id, field_name="approval_id"))
        object.__setattr__(self, "tenant_id", _id(self.tenant_id, field_name="tenant_id"))
        object.__setattr__(self, "patch_id", _digest(self.patch_id, field_name="patch_id"))
        object.__setattr__(self, "preview_id", _digest(self.preview_id, field_name="preview_id"))
        object.__setattr__(
            self,
            "rollback_reference",
            _revision(self.rollback_reference, field_name="rollback_reference"),
        )
        if self.status not in {"pending", "approved", "rejected", "expired"}:
            raise RemediationBoundaryError("approval status is unsupported")
        if self.decision_ref is not None:
            object.__setattr__(
                self, "decision_ref", _digest(self.decision_ref, field_name="decision_ref")
            )
        if self.actor_tenant_id is not None:
            object.__setattr__(
                self,
                "actor_tenant_id",
                _id(self.actor_tenant_id, field_name="actor_tenant_id"),
            )


class PreviewAdapter(Protocol):
    """Provider boundary; implementations must not receive credentials."""

    def request(self, request: PreviewRequest) -> PreviewResult:
        """Return a sanitized preview result."""


def evidence_digest(*parts: str) -> str:
    """Derive an opaque deterministic evidence reference."""

    canonical = "|".join(parts).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "FileChange",
    "GateKind",
    "GateResult",
    "GateStatus",
    "PatchCandidate",
    "PatchValidationResult",
    "PatchValidationStatus",
    "PreviewAdapter",
    "PreviewPolicy",
    "PreviewRequest",
    "PreviewResult",
    "RemediationBoundaryError",
    "RemediationContext",
    "RemediationWorkspace",
    "ReviewEvidence",
    "evidence_digest",
]
