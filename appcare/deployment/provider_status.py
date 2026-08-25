"""Provider capability inventory kept separate from global release policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

CapabilityStatus = Literal["supported", "vendor_blocked", "disabled"]


@dataclass(frozen=True, slots=True)
class ProviderCapabilityStatus:
    provider: str
    read_only: CapabilityStatus
    scan: CapabilityStatus
    preview: CapabilityStatus
    automated_production: CapabilityStatus


VERCEL_CAPABILITIES = ProviderCapabilityStatus(
    provider="vercel",
    read_only="supported",
    scan="supported",
    preview="vendor_blocked",
    automated_production="disabled",
)


def provider_capabilities(provider: str) -> ProviderCapabilityStatus | None:
    """Return a known provider profile without performing provider I/O."""

    if provider.strip().casefold() == VERCEL_CAPABILITIES.provider:
        return VERCEL_CAPABILITIES
    return None


__all__ = [
    "CapabilityStatus",
    "ProviderCapabilityStatus",
    "VERCEL_CAPABILITIES",
    "provider_capabilities",
]
