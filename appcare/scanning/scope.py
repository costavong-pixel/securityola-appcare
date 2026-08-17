"""Tenant and target scope checks for scanning adapters."""

from __future__ import annotations

from .models import AdapterKind, SanitizedTargetInput, ScanContext


class ScopeError(ValueError):
    """Raised when scanner input crosses the authorized scan boundary."""


def validate_scope(
    context: ScanContext,
    *,
    tenant_id: str,
    target_id: str,
    adapter_kind: AdapterKind,
) -> None:
    """Require exact tenant, target, and adapter authorization."""

    if not context.enabled:
        raise ScopeError("scan context is disabled")
    if tenant_id.casefold() != context.tenant_id or target_id.casefold() != context.target_id:
        raise ScopeError("scanner result is outside the scan scope")
    if adapter_kind not in context.adapter_allowlist:
        raise ScopeError("adapter is outside the scan allowlist")


def validate_target_input(
    context: ScanContext,
    target: SanitizedTargetInput,
) -> None:
    """Require a target object to remain inside the context scope."""

    if target.target_id != context.target_id:
        raise ScopeError("target input is outside the scan scope")
