"""Least-privilege provider capability profile tests."""

from __future__ import annotations

import pytest

from appcare.connectors.profiles import provider_profile, validate_scopes


@pytest.mark.parametrize(
    ("provider", "scope"),
    [
        ("github", "contents:write"),
        ("github", "secrets:read"),
        ("vercel", "deployment:write"),
        ("vercel", "project-env-vars:read"),
        ("supabase", "database:write"),
        ("supabase", "secrets:read"),
    ],
)
def test_profiles_reject_write_and_secret_capabilities(provider: str, scope: str) -> None:
    with pytest.raises(ValueError):
        validate_scopes(provider, [scope])


@pytest.mark.parametrize("provider", ["github", "vercel", "supabase"])
def test_profiles_have_a_safe_default_read_scope(provider: str) -> None:
    profile = provider_profile(provider)
    assert profile is not None
    assert profile.default_scopes
    assert validate_scopes(provider, []) == profile.default_scopes
    assert all(":write" not in scope for scope in profile.default_scopes)


def test_unknown_provider_is_rejected() -> None:
    with pytest.raises(ValueError):
        validate_scopes("unknown", ["metadata:read"])
