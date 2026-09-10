"""Shared test helpers.

Stage 17 put authentication in front of every endpoint that exposes stored
data. Rather than edit the ~66 call sites in the existing API, dashboard and
explainability tests, their fixtures configure a known account and sign in
once; the assertions themselves are unchanged.

Signing in for real, rather than disabling authentication in those fixtures,
means every one of those existing tests now also exercises the authenticated
path. A fixture that turned authentication off would leave the guard covered
only by `test_auth.py`.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

TEST_USERNAME = "test-admin"
TEST_PASSWORD = "test-password-not-a-real-secret"

#: Hashed once per session. PBKDF2 at 480,000 iterations takes a noticeable
#: fraction of a second, and the fixtures build many clients.
_HASH_CACHE: dict[str, str] = {}


def hashed_test_password() -> str:
    """A PBKDF2 hash of the fixed test password."""
    from api.auth import hash_password

    if "hash" not in _HASH_CACHE:
        _HASH_CACHE["hash"] = hash_password(TEST_PASSWORD)
    return _HASH_CACHE["hash"]


def auth_settings_kwargs() -> dict:
    """Settings keyword arguments that switch authentication on."""
    return {"auth_username": TEST_USERNAME,
            "auth_password_hash": hashed_test_password()}


def sign_in(client: TestClient) -> TestClient:
    """Log the client in, so its cookie jar carries a live session."""
    response = client.post("/auth/login",
                           json={"username": TEST_USERNAME,
                                 "password": TEST_PASSWORD})
    assert response.status_code == 200, (
        f"test sign-in failed: {response.status_code} {response.text}")
    return client
