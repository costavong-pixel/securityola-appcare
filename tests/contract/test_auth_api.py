"""Authentication contract and failure-boundary tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from appcare.models import User
from tests.control_plane_helpers import (
    TEST_PASSWORD,
    auth_headers,
    new_test_app,
    seed_user,
    set_token_expired,
)


def test_valid_token_authenticates_only_an_active_user_and_tenant() -> None:
    app = new_test_app()
    seeded = seed_user(app, "Auth")
    with TestClient(app) as client:
        response = client.post(
            "/auth/token", json={"email": seeded.email.upper(), "password": TEST_PASSWORD}
        )
        assert response.status_code == 200
        token = response.json()["access_token"]
        assert client.get("/v1/applications", headers=auth_headers(token)).status_code == 200


def test_invalid_password_and_unknown_email_have_the_same_safe_error() -> None:
    app = new_test_app()
    seed_user(app, "Auth")
    with TestClient(app) as client:
        invalid_password = client.post(
            "/auth/token", json={"email": "auth@example.test", "password": "wrong-password-value"}
        )
        unknown_email = client.post(
            "/auth/token", json={"email": "unknown@example.test", "password": TEST_PASSWORD}
        )
    assert invalid_password.status_code == 401
    assert unknown_email.status_code == 401
    assert invalid_password.json() == unknown_email.json() == {"detail": "authentication failed"}
    assert "wrong-password" not in invalid_password.text


def test_expired_and_disabled_tokens_fail_closed() -> None:
    app = new_test_app()
    expired = seed_user(app, "Expired")
    disabled = seed_user(app, "Disabled")
    with TestClient(app) as client:
        expired_token = client.post(
            "/auth/token", json={"email": expired.email, "password": TEST_PASSWORD}
        ).json()["access_token"]
        set_token_expired(app, expired.user_id)
        assert (
            client.get("/v1/applications", headers=auth_headers(expired_token)).status_code == 401
        )

        disabled_token = client.post(
            "/auth/token", json={"email": disabled.email, "password": TEST_PASSWORD}
        ).json()["access_token"]
        with app.state.database.session_factory() as session:
            user = session.get(User, disabled.user_id)
            assert user is not None
            user.status = "disabled"
            session.commit()
        assert (
            client.get("/v1/applications", headers=auth_headers(disabled_token)).status_code == 401
        )


def test_missing_malformed_and_wrong_scheme_authentication_is_rejected() -> None:
    app = new_test_app()
    seed_user(app, "Auth")
    with TestClient(app) as client:
        responses = [
            client.get("/v1/applications"),
            client.get("/v1/applications", headers={"Authorization": "Basic not-a-bearer"}),
            client.get("/v1/applications", headers={"Authorization": "Bearer malformed"}),
        ]
    assert [response.status_code for response in responses] == [401, 401, 401]
    assert all(
        response.json() == {"detail": "authentication required"} for response in responses[:1]
    )
    assert responses[1].json() in (
        {"detail": "authentication required"},
        {"detail": "authentication failed"},
    )
    assert responses[2].json() == {"detail": "authentication failed"}
