"""Read-only provider connector boundaries for AppCare BETA-02."""

from .adapters import ConnectorRegistry, FixtureTransport
from .contracts import (
    CheckResult,
    ConnectorAdapter,
    CredentialContext,
    NormalizedConnectorResult,
    ProviderAssetObservation,
    ProviderName,
    ReadOnlyRequest,
)
from .profiles import (
    GITHUB_PROFILE,
    PROVIDER_PROFILES,
    SUPABASE_PROFILE,
    VERCEL_PROFILE,
    provider_profile,
    validate_scopes,
)
from .transport import ProviderTransportError, UnavailableTransport

__all__ = [
    "CheckResult",
    "ConnectorAdapter",
    "ConnectorRegistry",
    "CredentialContext",
    "FixtureTransport",
    "GITHUB_PROFILE",
    "NormalizedConnectorResult",
    "PROVIDER_PROFILES",
    "ProviderAssetObservation",
    "ProviderName",
    "ProviderTransportError",
    "ReadOnlyRequest",
    "SUPABASE_PROFILE",
    "UnavailableTransport",
    "VERCEL_PROFILE",
    "provider_profile",
    "validate_scopes",
]
