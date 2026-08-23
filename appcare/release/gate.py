"""Deterministic private-beta release readiness evaluation."""

from __future__ import annotations

from collections.abc import Iterable

from .contracts import (
    DrillEvidence,
    ReleaseDecision,
    ReleaseEvidence,
    ReleaseEvidenceError,
    ReleaseStatus,
)

REQUIRED_DRILLS = (
    "seeded_secret_exposure",
    "vulnerable_dependency",
    "tenant_isolation",
    "failed_backup",
    "corrupted_backup",
    "isolated_restore",
    "worker_crash",
    "duplicate_event",
    "preview_failure",
    "production_verification_rollback",
    "revoked_connector",
    "alert_storm_dedup",
    "unsafe_ai_patch_rejection",
)

_REQUIRED_BOOLEAN_CHECKS = (
    ("ci_passed", "EXACT_HEAD_CI_REQUIRED"),
    ("tenant_isolation", "TENANT_ISOLATION_REQUIRED"),
    ("backup_restore", "BACKUP_RESTORE_REQUIRED"),
    ("production_rollback", "PRODUCTION_ROLLBACK_REQUIRED"),
    ("operator_stop", "OPERATOR_STOP_REQUIRED"),
    ("customer_report", "CUSTOMER_REPORT_REQUIRED"),
    ("dependency_scan", "DEPENDENCY_SCAN_REQUIRED"),
    ("secret_scan", "SECRET_SCAN_REQUIRED"),
    ("pricing_margin", "PRICING_MARGIN_REQUIRED"),
    ("known_limitations_published", "LIMITATIONS_REQUIRED"),
)


class ReleaseGate:
    """Evaluate release evidence without provider access or side effects."""

    def evaluate(self, evidence: ReleaseEvidence) -> ReleaseDecision:
        reasons: list[str] = []
        failed_checks: list[str] = []

        if evidence.beta06_live_preview != "pass":
            reasons.append("BETA06_LIVE_PREVIEW_REQUIRED")
            failed_checks.append("beta06_live_preview")

        if evidence.codex_security_findings > 0:
            reasons.append("UNRESOLVED_CODEX_SECURITY_FINDINGS")
            failed_checks.append("codex_security_findings")

        if evidence.test_count < 1:
            reasons.append("TEST_EVIDENCE_REQUIRED")
            failed_checks.append("test_count")

        for field_name, reason_code in _REQUIRED_BOOLEAN_CHECKS:
            if not bool(getattr(evidence, field_name)):
                reasons.append(reason_code)
                failed_checks.append(field_name)

        drill_map = {drill.name: drill for drill in evidence.drills}
        missing = [name for name in REQUIRED_DRILLS if name not in drill_map]
        if missing:
            reasons.append("ADVERSARIAL_DRILLS_INCOMPLETE")
            failed_checks.extend(f"drill:{name}" for name in missing)
        failed_drills = [
            drill.name
            for drill in evidence.drills
            if drill.name in REQUIRED_DRILLS and drill.status != "passed"
        ]
        if failed_drills:
            reasons.append("ADVERSARIAL_DRILLS_FAILED")
            failed_checks.extend(f"drill:{name}" for name in failed_drills)

        unique_reasons = tuple(dict.fromkeys(reasons))
        unique_checks = tuple(dict.fromkeys(failed_checks))
        status: ReleaseStatus = "ready" if not unique_reasons else "blocked"
        return ReleaseDecision(
            status=status,
            reason_codes=unique_reasons,
            failed_checks=unique_checks,
            evidence_digest=evidence.evidence_digest,
        )


def require_blocked(decision: ReleaseDecision, *, reason_code: str) -> None:
    """Assert a named fail-closed blocker without changing the decision."""

    if decision.ready or reason_code not in decision.reason_codes:
        raise ReleaseEvidenceError(f"expected release blocker is absent: {reason_code}")


def all_drills_passed(drills: Iterable[DrillEvidence]) -> bool:
    values = tuple(drills)
    return (
        len(values) == len(REQUIRED_DRILLS)
        and {drill.name for drill in values} == set(REQUIRED_DRILLS)
        and all(drill.status == "passed" for drill in values)
    )


__all__ = ["REQUIRED_DRILLS", "ReleaseGate", "all_drills_passed", "require_blocked"]
