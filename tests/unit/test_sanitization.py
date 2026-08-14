"""Secret-redaction and audit metadata boundary tests."""

from __future__ import annotations

import pytest

from appcare.services.audit import MetadataError, sanitize_metadata, sanitize_text


def test_secret_named_metadata_is_redacted_without_persisting_value() -> None:
    result = sanitize_metadata({"api_key": "fake-fixture-value", "safe": "yes"})
    assert result == {"api_key": "[REDACTED]", "safe": "yes"}
    assert "fake-fixture-value" not in str(result)


def test_credential_like_value_in_non_secret_field_fails_closed() -> None:
    with pytest.raises(MetadataError, match="credential-like"):
        sanitize_metadata({"note": "Bearer fake-token-value-12345678901234567890"})


def test_free_text_rejects_private_key_markers_without_echoing_value() -> None:
    with pytest.raises(MetadataError) as error:
        sanitize_text("-----BEGIN PRIVATE KEY----- fake-fixture -----END PRIVATE KEY-----")
    assert "fake-fixture" not in str(error.value)
