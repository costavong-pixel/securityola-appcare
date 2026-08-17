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

_LEGACY_CAPABILITY_ALIASES: Final[dict[ProviderName, dict[str, str]]] = {
    "github": {
        "metadata:read": "repository.metadata.read",
        "contents:read": "repository.contents.read",
    },
    "vercel": {
        "project:read": "project.read",
        "deployment:read": "deployment.read",
        "domain:read": "domain.read",
        "team:read": "team.read",
    },
    "supabase": {
        "projects:read": "project.read",
        "auth:read": "auth.metadata.read",
        "database:read": "database.metadata.read",
        "storage:read": "storage.metadata.read",
        "organizations:read": "project.read",
    },
}
_LEGACY_READ_ONLY_BUNDLES: Final[dict[ProviderName, dict[str, tuple[str, ...]]]] = {
    "github": {"metadata:read": PROVIDER_SPECS["github"].required_capabilities},
    "vercel": {"project:read": PROVIDER_SPECS["vercel"].required_capabilities},
    "supabase": {"projects:read": PROVIDER_SPECS["supabase"].required_capabilities},
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


def canonical_capabilities(provider: str, capabilities: Iterable[str]) -> tuple[str, ...]:
    """Normalize legacy API scope names into the canonical capability set."""

    normalized_provider = get_provider_spec(provider).provider
    aliases = _LEGACY_CAPABILITY_ALIASES[normalized_provider]
    bundles = _LEGACY_READ_ONLY_BUNDLES[normalized_provider]
    normalized_values: set[str] = set()
    for capability in capabilities:
        if not isinstance(capability, str) or not capability.strip():
            continue
        raw = capability.strip().casefold()
        if raw in bundles:
            normalized_values.update(bundles[raw])
        else:
            normalized_values.add(aliases.get(raw, raw))
    normalized = tuple(sorted(normalized_values))
    result = validate_capabilities(normalized_provider, normalized)
    if not result.allowed:
        raise ProviderConfigurationError(result.reason)
    return normalized
