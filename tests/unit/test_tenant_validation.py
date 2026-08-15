"""Tenant identifier, disabled-boundary, and secret-safe input tests."""

from __future__ import annotations

import pytest

from appcare.models import Tenant, User
from appcare.repositories.tenant_scope import get_owned, valid_public_id
from appcare.services.audit import MetadataError, sanitize_metadata
from tests.control_plane_helpers import new_test_app, seed_user


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a" * 32, True),
        ("A" * 32, False),
        ("a" * 31, False),
        ("not-an-opaque-id", False),
    ],
)
def test_public_ids_are_opaque_lowercase_hex_values(value: str, expected: bool) -> None:
    assert valid_public_id(value) is expected


def test_foreign_and_malformed_ids_are_not_returned_by_owned_repository_queries() -> None:
    app = new_test_app()
    owner = seed_user(app, "Owner")
    foreign = seed_user(app, "Foreign")
    with app.state.database.session_factory() as session:
        tenant = session.get(Tenant, owner.tenant_id)
        user = session.get(User, owner.user_id)
        assert tenant is not None
        assert user is not None
        assert get_owned(session, User, owner.tenant_id, foreign.user_id) is None
        assert get_owned(session, User, owner.tenant_id, "malformed-id") is None


def test_disabled_tenant_is_not_an_authenticated_data_boundary() -> None:
    app = new_test_app()
    seeded = seed_user(app, "DisabledTenant")
    with app.state.database.session_factory() as session:
        tenant = session.get(Tenant, seeded.tenant_id)
        assert tenant is not None
        tenant.status = "disabled"
        session.commit()
    with app.state.database.session_factory() as session:
        user = session.get(User, seeded.user_id)
        assert user is not None
        assert user.tenant_id == seeded.tenant_id
        assert session.get(Tenant, user.tenant_id).status == "disabled"


def test_secret_like_metadata_fails_without_retaining_the_value() -> None:
    with pytest.raises(MetadataError, match="credential-like") as error:
        sanitize_metadata({"note": "Bearer fake-fixture-token-12345678901234567890"})
    assert "fake-fixture-token" not in str(error.value)
