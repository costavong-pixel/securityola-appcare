"""Secret-redaction and audit metadata boundary tests."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from appcare.routes.common import safe_reference
from appcare.routes.schemas import AssetResponse
from appcare.services.audit import MetadataError, sanitize_metadata, sanitize_text


def test_secret_named_metadata_is_redacted_without_persisting_value() -> None:
    result = sanitize_metadata({"api_key": "fake-fixture-value", "safe": "yes"})
    assert result == {"api_key": "[REDACTED]", "safe": "yes"}
    assert "fake-fixture-value" not in str(result)


def test_credential_like_value_in_non_secret_field_fails_closed() -> None:
    with pytest.raises(MetadataError, match="credential-like"):
        sanitize_metadata({"note": "Bearer fake-token-value-12345678901234567890"})


def test_free_text_rejects_private_key_markers_without_echoing_value() -> None:
    fake_private_key = "-----" + "BEGIN PRIVATE KEY----- fake-fixture -----END PRIVATE KEY-----"
    with pytest.raises(MetadataError) as error:
        sanitize_text(fake_private_key)
    assert "fake-fixture" not in str(error.value)


def test_safe_reference_rejects_encoded_and_fragment_credentials() -> None:
    assert not safe_reference("https://example.test/repo?client%5Fsecret=fake-fixture-value")
    assert not safe_reference("https://example.test/repo#signature=fake-fixture-value")
    assert not safe_reference("https://example.test/repo?sig=fake-fixture-value")
    assert safe_reference("https://github.com/example/app#readme")


@pytest.mark.parametrize(
    "value",
    [
        "xgho_1234567890abcdefghijklmnop",
        "vault://fixture/appcare/prefix.eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123",
    ],
)
def test_safe_reference_rejects_embedded_token_and_jwt_values(value: str) -> None:
    assert not safe_reference(value)
    with pytest.raises(MetadataError):
        sanitize_text(value)


def _asset_response_source(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "id": "a" * 32,
        "tenant_id": "t" * 32,
        "application_id": "p" * 32,
        "kind": "repository",
        "locator": "https://github.com/example/app",
        "status": "active",
        "connector_id": None,
        "provider": "github",
        "provider_reference": "repo-001",
        "display_name": "App repository",
        "display_metadata_json": {"environment": "development"},
        "last_seen_at": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"provider_reference": "xgho_1234567890abcdefghijklmnop"},
        {
            "locator": (
                "https://example.test/prefix.eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123"
            )
        },
        {"display_name": "prefix.eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123"},
        {"display_metadata_json": {"note": "xgho_1234567890abcdefghijklmnop"}},
    ],
)
def test_asset_response_rejects_credential_like_persisted_values(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="unsafe asset response"):
        AssetResponse.model_validate(_asset_response_source(**overrides))


def test_asset_response_preserves_safe_values() -> None:
    response = AssetResponse.model_validate(_asset_response_source())
    assert response.provider_reference == "repo-001"
