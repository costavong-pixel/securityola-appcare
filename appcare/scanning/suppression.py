"""Evidence-preserving, tenant-scoped false-positive suppression."""

from __future__ import annotations

from dataclasses import replace

from .models import Finding, ScanContext, Suppression
from .scope import ScopeError, validate_scope


def suppress_finding(
    context: ScanContext,
    finding: Finding,
    *,
    reason: str,
    actor: str,
) -> tuple[Finding, Suppression]:
    """Suppress a finding only when its exact tenant and target match the context."""

    try:
        validate_scope(
            context,
            tenant_id=finding.tenant_id,
            target_id=finding.target_id,
            adapter_kind=finding.adapter_kind,
        )
    except ScopeError:
        raise
    decision = Suppression(
        fingerprint=finding.fingerprint,
        tenant_id=context.tenant_id,
        target_id=context.target_id,
        reason=reason,
        actor=actor,
    )
    return replace(finding, status="suppressed", suppression_reason=decision.reason), decision
