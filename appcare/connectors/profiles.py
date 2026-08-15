"""Server-owned least-privilege profiles for supported providers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .contracts import ProviderName

_READ_ONLY_MARKERS = ("write", "delete", "destroy", "deploy", "mutate", "admin")
_SECRET_MARKERS = ("secret", "token", "password", "private", "credential", "key")


@dataclass(frozen=True, slots=True)
class ProviderProfile:
    provider: ProviderName
    default_scopes: tuple[str, ...]
    allowed_scopes: frozenset[str]
    denied_scopes: frozenset[str]
    inventory_kinds: tuple[str, ...]


GITHUB_PROFILE = ProviderProfile(
    provider="github",
    default_scopes=("metadata:read",),
    allowed_scopes=frozenset({"metadata:read", "contents:read"}),
    denied_scopes=frozenset(
        {
            "administration:write",
            "contents:write",
            "deployments:write",
            "actions:write",
            "secrets:read",
            "organization:write",
            "members:write",
        }
    ),
    inventory_kinds=("repository", "branch", "workflow"),
)

VERCEL_PROFILE = ProviderProfile(
    provider="vercel",
    default_scopes=("project:read",),
    allowed_scopes=frozenset({"project:read", "deployment:read", "team:read", "user:read"}),
    denied_scopes=frozenset(
        {
            "project:write",
            "deployment:write",
            "project-env-vars:read",
            "project-env-vars:write",
            "global-project-env-vars:read",
            "domain:write",
            "log-drain:write",
        }
    ),
    inventory_kinds=("project", "deployment", "domain"),
)

SUPABASE_PROFILE = ProviderProfile(
    provider="supabase",
    default_scopes=("projects:read",),
    allowed_scopes=frozenset(
        {"auth:read", "database:read", "organizations:read", "projects:read", "storage:read"}
    ),
    denied_scopes=frozenset({"secrets:read"}),
    inventory_kinds=("supabase-project", "auth", "storage", "database"),
)

PROVIDER_PROFILES: dict[ProviderName, ProviderProfile] = {
    "github": GITHUB_PROFILE,
    "vercel": VERCEL_PROFILE,
    "supabase": SUPABASE_PROFILE,
}


def provider_profile(provider: str) -> ProviderProfile | None:
    return PROVIDER_PROFILES.get(provider) if provider in PROVIDER_PROFILES else None


def validate_scopes(provider: str, scopes: Sequence[str]) -> tuple[str, ...]:
    """Return normalized scopes or raise a non-sensitive validation error."""

    profile = provider_profile(provider)
    if profile is None:
        raise ValueError("unsupported connector provider")
    normalized_values: set[str] = set()
    for raw_scope in scopes:
        if not isinstance(raw_scope, str):
            raise ValueError("connector scope is malformed")
        scope = raw_scope.strip().casefold()
        if scope:
            normalized_values.add(scope)
    normalized = tuple(sorted(normalized_values))
    if not normalized:
        normalized = profile.default_scopes
    for scope in normalized:
        if (
            scope not in profile.allowed_scopes
            or scope in profile.denied_scopes
            or any(marker in scope for marker in _READ_ONLY_MARKERS)
            or any(marker in scope for marker in _SECRET_MARKERS)
        ):
            raise ValueError("connector scope is not an approved read-only capability")
    return normalized
