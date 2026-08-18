"""Preview adapters with a deterministic fixture and a fail-closed live edge."""

from __future__ import annotations

from .contracts import (
    PatchCandidate,
    PatchValidationResult,
    PreviewPolicy,
    PreviewRequest,
    PreviewResult,
    evidence_digest,
)
from .gates import GateSummary


def build_preview_request(
    patch: PatchCandidate,
    policy: PreviewPolicy,
    validation: PatchValidationResult,
    gates: GateSummary,
) -> PreviewRequest:
    """Create a preview request only after local patch and gate success."""

    if validation.status != "passed":
        raise ValueError("preview requires a passed patch validation")
    if validation.patch_id != patch.patch_id or not gates.promotion_ready:
        raise ValueError("preview requires matching patch and passed gates")
    preview_id = evidence_digest(
        "preview",
        patch.patch_id,
        policy.provider,
        policy.project_reference,
        policy.skill_revision,
        policy.mode,
    )
    return PreviewRequest(
        preview_id=preview_id,
        patch_id=patch.patch_id,
        tenant_id=patch.context.tenant_id,
        application_id=patch.context.application_id,
        rollback_reference=patch.rollback_reference,
        policy=policy,
        patch_validated=True,
        gates_passed=True,
    )


class FixturePreviewAdapter:
    """Deterministic local preview proof; it performs no network call."""

    def __init__(self, *, smoke_passed: bool = True, security_passed: bool = True) -> None:
        self.smoke_passed = smoke_passed
        self.security_passed = security_passed
        self.external_call_count = 0

    def request(self, request: PreviewRequest) -> PreviewResult:
        if request.policy.mode != "fixture":
            return PreviewResult(
                preview_id=request.preview_id,
                patch_id=request.patch_id,
                tenant_id=request.tenant_id,
                rollback_reference=request.rollback_reference,
                status="blocked",
                code="fixture_mode_required",
            )
        if not request.policy.skill_reviewed:
            return PreviewResult(
                preview_id=request.preview_id,
                patch_id=request.patch_id,
                tenant_id=request.tenant_id,
                rollback_reference=request.rollback_reference,
                status="blocked",
                code="preview_skill_unreviewed",
            )
        if not request.policy.project_reference.startswith("appcare://fixture/"):
            return PreviewResult(
                preview_id=request.preview_id,
                patch_id=request.patch_id,
                tenant_id=request.tenant_id,
                rollback_reference=request.rollback_reference,
                status="blocked",
                code="preview_project_not_fixture",
            )
        if not self.smoke_passed:
            return PreviewResult(
                preview_id=request.preview_id,
                patch_id=request.patch_id,
                tenant_id=request.tenant_id,
                rollback_reference=request.rollback_reference,
                status="failed",
                code="preview_smoke_failed",
                evidence_refs=(evidence_digest("preview-smoke", request.preview_id, "failed"),),
            )
        if not self.security_passed:
            return PreviewResult(
                preview_id=request.preview_id,
                patch_id=request.patch_id,
                tenant_id=request.tenant_id,
                rollback_reference=request.rollback_reference,
                status="failed",
                code="preview_security_failed",
                evidence_refs=(evidence_digest("preview-security", request.preview_id, "failed"),),
            )
        return PreviewResult(
            preview_id=request.preview_id,
            patch_id=request.patch_id,
            tenant_id=request.tenant_id,
            rollback_reference=request.rollback_reference,
            status="passed",
            code="preview_verified",
            evidence_refs=(
                evidence_digest("preview-smoke", request.preview_id, "passed"),
                evidence_digest("preview-security", request.preview_id, "passed"),
            ),
            preview_reference=f"fixture-preview://{request.preview_id}",
        )


class UnapprovedVercelPreviewAdapter:
    """Deny live Vercel execution until a separate skill review approves it."""

    def __init__(self) -> None:
        self.external_call_count = 0

    def request(self, request: PreviewRequest) -> PreviewResult:
        return PreviewResult(
            preview_id=request.preview_id,
            patch_id=request.patch_id,
            tenant_id=request.tenant_id,
            rollback_reference=request.rollback_reference,
            status="blocked",
            code="vercel_skill_unapproved",
            evidence_refs=(evidence_digest("vercel-preview", request.preview_id, "blocked"),),
        )


__all__ = [
    "FixturePreviewAdapter",
    "UnapprovedVercelPreviewAdapter",
    "build_preview_request",
]
