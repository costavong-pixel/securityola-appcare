"""Tenant-scoped internal approval queue with no release authority."""

from __future__ import annotations

import hashlib

from .contracts import (
    ApprovalDecision,
    ApprovalRequest,
    PreviewResult,
    RemediationBoundaryError,
    evidence_digest,
)


class ApprovalQueue:
    """Deterministic in-process approval record boundary for BETA-06 fixtures."""

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}

    def request(
        self,
        *,
        tenant_id: str,
        patch_id: str,
        preview: PreviewResult,
        rollback_reference: str,
    ) -> ApprovalRequest:
        if preview.status != "passed":
            raise RemediationBoundaryError("approval requires a verified preview")
        normalized_tenant = tenant_id.strip().casefold()
        normalized_patch = patch_id.strip().casefold()
        normalized_rollback = rollback_reference.strip().casefold()
        approval_id = hashlib.sha256(
            f"approval|{normalized_tenant}|{normalized_patch}|{preview.preview_id}|{normalized_rollback}".encode()
        ).hexdigest()
        candidate = ApprovalRequest(
            approval_id=approval_id,
            tenant_id=normalized_tenant,
            patch_id=normalized_patch,
            preview_id=preview.preview_id,
            rollback_reference=normalized_rollback,
        )
        if (
            preview.tenant_id != candidate.tenant_id
            or preview.patch_id != candidate.patch_id
            or preview.rollback_reference != candidate.rollback_reference
        ):
            raise RemediationBoundaryError("approval input does not match preview identity")
        existing = self._requests.get(candidate.approval_id)
        if existing is not None and existing != candidate:
            raise RemediationBoundaryError("approval identity was reused with different data")
        self._requests[candidate.approval_id] = existing or candidate
        return self._requests[candidate.approval_id]

    def decide(
        self,
        approval_id: str,
        *,
        actor_tenant_id: str,
        decision: ApprovalDecision,
        decision_ref: str,
    ) -> ApprovalRequest:
        current = self._requests.get(approval_id)
        if current is None:
            raise RemediationBoundaryError("approval request is unknown")
        if current.tenant_id != actor_tenant_id:
            raise RemediationBoundaryError("approval actor is outside the tenant")
        if decision not in {"approved", "rejected"}:
            raise RemediationBoundaryError("approval decision is unsupported")
        decision_digest = evidence_digest("approval-decision", approval_id, decision_ref)
        if current.status != "pending":
            if current.status == decision and current.decision_ref == decision_digest:
                return current
            raise RemediationBoundaryError("approval request already has a different decision")
        updated = ApprovalRequest(
            approval_id=current.approval_id,
            tenant_id=current.tenant_id,
            patch_id=current.patch_id,
            preview_id=current.preview_id,
            rollback_reference=current.rollback_reference,
            status=decision,
            decision_ref=decision_digest,
            actor_tenant_id=actor_tenant_id,
        )
        self._requests[approval_id] = updated
        return updated

    def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._requests.get(approval_id)


__all__ = ["ApprovalQueue"]
