"""Sanitized evidence contracts for the BETA-10 release gate."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Literal

from ..deployment.contracts import LivePreviewStatus, normalize_live_preview_status
from ..services.security import contains_credential_like

DrillStatus = Literal["passed", "failed", "blocked"]
ReleaseStatus = Literal["ready", "blocked"]

_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,95}$")
_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_UNSAFE_TEXT_MARKERS = ("bearer ", "-----begin", "private key")


class ReleaseEvidenceError(ValueError):
    """Raised when release evidence is malformed or unsafe."""


def _safe_code(value: str, *, field_name: str) -> str:
    normalized = value.strip().casefold()
    if _SAFE_CODE.fullmatch(normalized) is None or contains_credential_like(normalized):
        raise ReleaseEvidenceError(f"{field_name} is malformed")
    return normalized


def _revision(value: str) -> str:
    normalized = value.strip().casefold()
    if _REVISION.fullmatch(normalized) is None:
        raise ReleaseEvidenceError("exact_head must be a Git revision")
    return normalized


@dataclass(frozen=True, slots=True)
class DrillEvidence:
    """One bounded, sanitized adversarial drill result."""

    name: str
    status: DrillStatus
    evidence_ref: str
    summary: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _safe_code(self.name, field_name="drill_name"))
        if self.status not in {"passed", "failed", "blocked"}:
            raise ReleaseEvidenceError("drill status is invalid")
        object.__setattr__(
            self, "evidence_ref", _safe_code(self.evidence_ref, field_name="evidence_ref")
        )
        normalized_summary = self.summary.strip()
        if (
            not normalized_summary
            or len(normalized_summary) > 300
            or contains_credential_like(normalized_summary)
            or any(marker in normalized_summary.casefold() for marker in _UNSAFE_TEXT_MARKERS)
        ):
            raise ReleaseEvidenceError("drill summary is unsafe")
        object.__setattr__(self, "summary", normalized_summary)

    def canonical(self) -> tuple[str, str, str, str]:
        return (self.name, self.status, self.evidence_ref, self.summary)


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    """Complete evidence input for a private-beta release decision."""

    exact_head: str
    ci_passed: bool
    test_count: int
    codex_security_findings: int
    tenant_isolation: bool
    backup_restore: bool
    production_rollback: bool
    operator_stop: bool
    customer_report: bool
    dependency_scan: bool
    secret_scan: bool
    pricing_margin: bool
    known_limitations_published: bool
    beta06_live_preview: LivePreviewStatus
    drills: tuple[DrillEvidence, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "exact_head", _revision(self.exact_head))
        object.__setattr__(
            self,
            "beta06_live_preview",
            normalize_live_preview_status(self.beta06_live_preview),
        )
        if self.test_count < 0 or self.codex_security_findings < 0:
            raise ReleaseEvidenceError("numeric evidence cannot be negative")
        names = [drill.name for drill in self.drills]
        if len(names) != len(set(names)):
            raise ReleaseEvidenceError("drill evidence names must be unique")

    def canonical(self) -> dict[str, object]:
        return {
            "exact_head": self.exact_head,
            "ci_passed": self.ci_passed,
            "test_count": self.test_count,
            "codex_security_findings": self.codex_security_findings,
            "tenant_isolation": self.tenant_isolation,
            "backup_restore": self.backup_restore,
            "production_rollback": self.production_rollback,
            "operator_stop": self.operator_stop,
            "customer_report": self.customer_report,
            "dependency_scan": self.dependency_scan,
            "secret_scan": self.secret_scan,
            "pricing_margin": self.pricing_margin,
            "known_limitations_published": self.known_limitations_published,
            "beta06_live_preview": self.beta06_live_preview,
            "drills": [
                drill.canonical() for drill in sorted(self.drills, key=lambda item: item.name)
            ],
        }

    @property
    def evidence_digest(self) -> str:
        encoded = json.dumps(
            self.canonical(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ReleaseDecision:
    """Immutable fail-closed release decision."""

    status: ReleaseStatus
    reason_codes: tuple[str, ...]
    failed_checks: tuple[str, ...]
    evidence_digest: str
    live_production_enabled: Literal[False] = False

    @property
    def ready(self) -> bool:
        return self.status == "ready"

    def to_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "ready": self.ready,
            "reason_codes": list(self.reason_codes),
            "failed_checks": list(self.failed_checks),
            "evidence_digest": self.evidence_digest,
            "live_production_enabled": False,
        }


__all__ = [
    "DrillEvidence",
    "DrillStatus",
    "ReleaseDecision",
    "ReleaseEvidence",
    "ReleaseEvidenceError",
    "ReleaseStatus",
]
