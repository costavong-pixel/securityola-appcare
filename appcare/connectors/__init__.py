"""Read-only GitHub, Vercel, and Supabase connector contracts."""

from __future__ import annotations

from .adapters import ConnectorRegistry, FixtureTransport
from .base import (
    ConnectorAccessError,
    FixtureReadOnlyConnector,
    GitHubReadOnlyConnector,
    ReadOnlyConnector,
    SupabaseReadOnlyConnector,
    VercelReadOnlyConnector,
    build_fixture_connector,
)
from .contracts import (
    CheckResult,
    ConnectorAdapter,
    CredentialContext,
    NormalizedConnectorResult,
    ProviderAssetObservation,
    ProviderName,
    ReadOnlyRequest,
)
from .credentials import CredentialLifecycleError, CredentialRegistry
from .profiles import (
    GITHUB_PROFILE,
    PROVIDER_PROFILES,
    SUPABASE_PROFILE,
    VERCEL_PROFILE,
    provider_profile,
    validate_scopes,
)
from .providers import PROVIDER_SPECS, ProviderConfigurationError, get_provider_spec
from .transport import ProviderTransportError, UnavailableTransport
from .types import (
    ConnectorHealth,
    CredentialMetadata,
    InventoryAsset,
    OwnershipResult,
    OwnershipTarget,
    PermissionResult,
    ProviderSnapshot,
    ProviderSpec,
    RemoteRecord,
)

__all__ = [
    "CheckResult",
    "ConnectorAdapter",
    "ConnectorAccessError",
    "ConnectorHealth",
    "ConnectorRegistry",
    "CredentialContext",
    "CredentialLifecycleError",
    "CredentialMetadata",
    "CredentialRegistry",
    "FixtureTransport",
    "FixtureReadOnlyConnector",
    "GITHUB_PROFILE",
    "GitHubReadOnlyConnector",
    "InventoryAsset",
    "NormalizedConnectorResult",
    "OwnershipResult",
    "OwnershipTarget",
    "PermissionResult",
    "PROVIDER_PROFILES",
    "PROVIDER_SPECS",
    "ProviderConfigurationError",
    "ProviderAssetObservation",
    "ProviderName",
    "ProviderSnapshot",
    "ProviderSpec",
    "ProviderTransportError",
    "ReadOnlyRequest",
    "ReadOnlyConnector",
    "RemoteRecord",
    "SupabaseReadOnlyConnector",
    "SUPABASE_PROFILE",
    "UnavailableTransport",
    "VERCEL_PROFILE",
    "VercelReadOnlyConnector",
    "build_fixture_connector",
    "get_provider_spec",
    "provider_profile",
    "validate_scopes",
]
