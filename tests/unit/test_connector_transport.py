"""Read-only request and transport boundary tests."""

from __future__ import annotations

from typing import Literal, cast

import pytest

from appcare.connectors import (
    ConnectorRegistry,
    CredentialContext,
    FixtureTransport,
    ProviderName,
    ReadOnlyRequest,
)
from appcare.connectors.contracts import RequestOperation
from appcare.connectors.transport import ProviderTransportError, UnavailableTransport


def _fixtures() -> dict[tuple[ProviderName, RequestOperation], dict[str, object]]:
    return {
        ("github", "health"): {"ok": True},
        ("github", "permissions"): {"scopes": ["metadata:read"]},
        (
            "github",
            "ownership",
        ): {
            "resource_reference": "example/appcare",
            "owner_reference": "owner",
            "credential_owner_reference": "owner",
        },
        (
            "github",
            "inventory",
        ): {"assets": []},
    }


def test_request_rejects_non_get_and_unsafe_path() -> None:
    with pytest.raises(ValueError):
        ReadOnlyRequest(
            provider="github",
            operation="health",
            path="/installation",
            method=cast(Literal["GET"], "POST"),
        )
    with pytest.raises(ValueError):
        ReadOnlyRequest(provider="github", operation="health", path="/repos/a?token=x")
    with pytest.raises(ValueError, match="credential reference is unsafe"):
        CredentialContext(
            "vault://eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123",
            ("metadata:read",),
            tenant_id="a" * 32,
            authority="appcare-secret-service",
        )


def test_registry_emits_only_fixed_get_requests() -> None:
    transport = FixtureTransport(_fixtures())
    registry = ConnectorRegistry(transport=transport)
    payloads = registry.collect(
        "github",
        CredentialContext(
            "vault://fixture/appcare/transport-ref",
            ("metadata:read",),
            tenant_id="a" * 32,
            authority="appcare-secret-service",
        ),
        "example/appcare",
        tenant_id="a" * 32,
    )
    assert set(payloads) == {"health", "permissions", "ownership", "inventory"}
    assert transport.requests
    assert all(request.method == "GET" for request in transport.requests)
    assert all("fixture-reference" not in request.path for request in transport.requests)
    assert all("://" not in request.path for request in transport.requests)


def test_default_transport_fails_closed() -> None:
    transport = UnavailableTransport()
    with pytest.raises(ProviderTransportError) as raised:
        transport.request(
            ReadOnlyRequest(provider="github", operation="health", path="/installation"),
            CredentialContext(
                "vault://fixture/appcare/transport-ref",
                ("metadata:read",),
                tenant_id="a" * 32,
                authority="appcare-secret-service",
            ),
        )
    assert raised.value.reason_code == "provider_transport_unavailable"
