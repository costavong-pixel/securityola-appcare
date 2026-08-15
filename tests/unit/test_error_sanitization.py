"""HTTP error responses do not echo bearer material."""

from fastapi.testclient import TestClient

from appcare.api import create_app


def test_invalid_bearer_has_stable_safe_error() -> None:
    with TestClient(create_app()) as client:
        response = client.get(
            "/v1/applications",
            headers={"Authorization": "Bearer fake-fixture-token-12345678901234567890"},
        )
    assert response.status_code == 401
    assert response.json() == {"detail": "authentication failed"}
    assert "fake-fixture" not in response.text
