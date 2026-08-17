"""Closed provider capability specifications for BETA-02."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

from .types import PermissionResult, ProviderName, ProviderSpec

_FORBIDDEN_CAPABILITY: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[._-])(write|deploy|delete|mutate|execute|sql|secret|key)(?:$|[._-])"
)

PROVIDER_SPECS: Final[dict[ProviderName, ProviderSpec]] = {
    "github": ProviderSpec(
        provider="github",
        required_capabilities=(
            "repository.metadata.read",
            "repository.contents.read",
            "pull_request.metadata.read",
        ),
        forbidden_capabilities=(
            "repository.contents.write",
            "repository.administration.write",
            "workflow.write",
            "issues.write",
        ),
    ),
    "vercel": ProviderSpec(
        provider="vercel",
        required_capabilities=(
            "project.read",
            "deployment.read",
            "domain.read",
            "team.read",
        ),
        forbidden_capabilities=(
            "project.write",
            "domain.write",
            "deployment.write",
            "project-env-vars.write",
        ),
    ),
    "supabase": ProviderSpec(
        provider="supabase",
        required_capabilities=(
            "project.read",
            "auth.metadata.read",
            "storage.metadata.read",
            "database.metadata.read",
        ),
        forbidden_capabilities=(
            "database.query.execute",
            "database.migration.write",
            "project-admin.write",
            "storage-config.write",
            "secret.read",
            "key.read",
        ),
    ),
}


class ProviderConfigurationError(ValueError):
    """The provider or its declared capability set is not safe."""


def get_provider_spec(provider: str) -> ProviderSpec:
    normalized = provider.strip().casefold()
    if normalized not in PROVIDER_SPECS:
        raise ProviderConfigurationError("provider is unsupported")
    return PROVIDER_SPECS[normalized]


def validate_capabilities(provider: str, capabilities: Iterable[str]) -> PermissionResult:
    spec = get_provider_spec(provider)
    normalized = tuple(sorted({capability.strip().casefold() for capability in capabilities}))
    if not normalized or any(not capability for capability in normalized):
        raise ProviderConfigurationError("capability set is invalid")
    forbidden = tuple(
        capability for capability in normalized if _FORBIDDEN_CAPABILITY.search(capability)
    )
    missing = tuple(
        capability
        for capability in spec.required_capabilities
        if capability.casefold() not in normalized
    )
    if forbidden:
        return PermissionResult(
            allowed=False,
            missing_capabilities=missing,
            forbidden_capabilities=forbidden,
            reason="forbidden_capability",
        )
    unrecognized = tuple(
        capability
        for capability in normalized
        if capability not in {item.casefold() for item in spec.required_capabilities}
    )
    if unrecognized:
        return PermissionResult(
            allowed=False,
            forbidden_capabilities=unrecognized,
            reason="unrecognized_capability",
        )
    if missing:
        return PermissionResult(
            allowed=False,
            missing_capabilities=missing,
            reason="missing_capability",
        )
    return PermissionResult(allowed=True)
