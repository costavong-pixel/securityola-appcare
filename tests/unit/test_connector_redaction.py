"""Safe connector metadata and observation tests."""

from __future__ import annotations

import pytest

from appcare.connectors.adapters import GITHUB_ADAPTER


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("display_name", "Bearer fake-fixture-token-not-live"),
        ("provider_reference", "xgho_1234567890abcdefghijklmnop"),
        (
            "locator",
            "https://example.test/prefix.eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123",
        ),
        ("metadata", {"environment": "xgho_1234567890abcdefghijklmnop"}),
    ],
)
def test_secret_shaped_inventory_values_are_rejected_without_echoing_value(
    field: str, value: object
) -> None:
    payload: dict[str, object] = {
        "provider_reference": "example/appcare",
        "kind": "repository",
        "display_name": "App repository",
        "locator": "https://github.com/example/appcare",
        "metadata": {},
    }
    if field == "metadata":
        payload["metadata"] = value
    else:
        payload[field] = value
    result = GITHUB_ADAPTER.normalize(
        {
            "health": {"ok": True},
            "permissions": {"scopes": ["metadata:read"]},
            "ownership": {
                "resource_reference": "example/appcare",
                "owner_reference": "owner",
                "credential_owner_reference": "owner",
            },
            "inventory": {"assets": [payload]},
        },
        resource_reference="example/appcare",
        owner_reference="owner",
        configured_scopes=("metadata:read",),
    )
    assert result.inventory_valid is False
    assert str(value) not in str(result)
