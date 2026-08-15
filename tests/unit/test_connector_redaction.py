"""Safe connector metadata and observation tests."""

from __future__ import annotations

from appcare.connectors.adapters import GITHUB_ADAPTER


def test_secret_shaped_inventory_values_are_rejected_without_echoing_value() -> None:
    secret_fixture = "Bearer fake-fixture-token-not-live"  # noqa: S105 - non-live fixture
    result = GITHUB_ADAPTER.normalize(
        {
            "health": {"ok": True},
            "permissions": {"scopes": ["metadata:read"]},
            "ownership": {
                "resource_reference": "example/appcare",
                "owner_reference": "owner",
                "credential_owner_reference": "owner",
            },
            "inventory": {
                "assets": [
                    {
                        "provider_reference": "example/appcare",
                        "kind": "repository",
                        "display_name": secret_fixture,
                        "locator": "https://github.com/example/appcare",
                        "metadata": {},
                    }
                ]
            },
        },
        resource_reference="example/appcare",
        owner_reference="owner",
        configured_scopes=("metadata:read",),
    )
    assert result.inventory_valid is False
    assert secret_fixture not in str(result)
