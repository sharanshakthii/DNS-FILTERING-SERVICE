"""Stage 17 tests: authentication.

The claim being tested is that protection is enforced by the backend, not by
the dashboard hiding things. So the tests that matter most are the ones that
skip the login page entirely and go straight at the API, and the one that
checks a session is dead server-side after logout rather than merely
forgotten by the browser.

Also checked: that nothing leaks the password, and that a wrong password and
an unknown user are indistinguishable.
"""

import time

import pytest
from fastapi.testclient import TestClient

import api.auth as auth
import api.main as api_main
from api.auth import (
    ALGORITHM,
    SESSION_COOKIE,
    Authenticator,
    SessionStore,
    hash_password,
    verify_password,
)
from config.settings import Settings
from tests.conftest import (
    TEST_PASSWORD,
    TEST_USERNAME,
    hashed_test_password,
)

#: Endpoints that expose stored data or change configuration.
PROTECTED = [
    ("get", "/decisions"),
    ("get", "/decisions/1/evidence"),
    ("get", "/stats"),
    ("get", "/mode"),
]


@pytest.fixture
def client(monkeypatch) -> TestClient:
    """An unauthenticated client against a server with auth enabled."""
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_enabled=False, engine_modules="null",
                                 auth_username=TEST_USERNAME,
                                 auth_password_hash=hashed_test_password()))
    monkeypatch.setattr(api_main, "_authenticator", None)
    monkeypatch.setattr(api_main, "_engine", None)
    return TestClient(api_main.app)


@pytest.fixture
def open_client(monkeypatch) -> TestClient:
    """A server with no credentials configured: authentication is off."""
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_enabled=False, engine_modules="null"))
    monkeypatch.setattr(api_main, "_authenticator", None)
    monkeypatch.setattr(api_main, "_engine", None)
    return TestClient(api_main.app)


def login(client, username=TEST_USERNAME, password=TEST_PASSWORD):
    return client.post("/auth/login",
                       json={"username": username, "password": password})


# =========================================================================
# Password hashing
# =========================================================================

def test_a_hash_is_not_the_password():
    digest = hash_password("hunter2-not-a-real-password")
    assert "hunter2-not-a-real-password" not in digest
    assert digest.startswith(f"{ALGORITHM}$")
    assert len(digest.split("$")) == 4


def test_the_same_password_hashes_differently_every_time():
    """A per-password salt: identical passwords must not share a hash."""
    first = hash_password("same-password")
    second = hash_password("same-password")
    assert first != second
    assert verify_password("same-password", first)
    assert verify_password("same-password", second)


def test_verification_accepts_the_right_password_and_rejects_others():
    digest = hash_password("right-password")
    assert verify_password("right-password", digest) is True
    assert verify_password("wrong-password", digest) is False
    assert verify_password("", digest) is False


@pytest.mark.parametrize("malformed", [
    "", "not-a-hash", "pbkdf2_sha256$abc$def$ghi",
    "md5$1$aa$bb", "pbkdf2_sha256$1000$zz$yy",
])
def test_a_malformed_stored_hash_fails_closed(malformed):
    """A misconfigured deployment must refuse logins, not crash on each one."""
    assert verify_password("anything", malformed) is False


def test_an_empty_password_cannot_be_hashed():
    with pytest.raises(ValueError, match="must not be empty"):
        hash_password("")


def test_the_iteration_count_is_not_trivially_low():
    iterations = int(hash_password("x").split("$")[1])
    assert iterations >= 100_000, "the work factor is too low to be useful"


# =========================================================================
# Sessions
# =========================================================================

def test_a_session_token_is_long_and_unpredictable():
    store = SessionStore()
    tokens = {store.create("user").token for _ in range(50)}
    assert len(tokens) == 50, "session tokens repeated"
    assert all(len(token) >= 32 for token in tokens)


def test_a_session_can_be_looked_up_then_revoked():
    store = SessionStore()
    session = store.create("user")

    assert store.get(session.token) is not None
    assert store.revoke(session.token) is True
    assert store.get(session.token) is None
    assert store.revoke(session.token) is False


def test_an_unknown_or_missing_token_resolves_to_nothing():
    store = SessionStore()
    assert store.get("not-a-real-token") is None
    assert store.get(None) is None
    assert store.get("") is None


def test_a_session_expires():
    store = SessionStore(ttl_s=100)
    session = store.create("user", now=1_000.0)

    assert store.get(session.token, now=1_050.0) is not None
    assert store.get(session.token, now=1_200.0) is None


# =========================================================================
# The authenticator
# =========================================================================

def test_authentication_is_disabled_when_no_hash_is_configured():
    """An upgrade must not lock a developer out of their own project."""
    assert Authenticator(username="admin", password_hash="").enabled is False
    assert Authenticator(username="", password_hash="x").enabled is False
    assert Authenticator(username="admin",
                         password_hash=hashed_test_password()).enabled is True


def test_correct_credentials_yield_a_session():
    authenticator = Authenticator(TEST_USERNAME, hashed_test_password())
    assert authenticator.authenticate(TEST_USERNAME, TEST_PASSWORD) is not None


@pytest.mark.parametrize("username,password", [
    (TEST_USERNAME, "wrong-password"),
    ("someone-else", TEST_PASSWORD),
    ("someone-else", "wrong-password"),
    ("", ""),
])
def test_bad_credentials_yield_nothing(username, password):
    authenticator = Authenticator(TEST_USERNAME, hashed_test_password())
    assert authenticator.authenticate(username, password) is None


def test_an_unknown_username_still_costs_a_key_derivation():
    """Otherwise response timing reveals which usernames exist.

    Timed rather than asserted exactly, because wall-clock timing is noisy;
    the check is that the unknown-user path is not orders of magnitude
    faster, which is what an early return would produce.
    """
    authenticator = Authenticator(TEST_USERNAME, hashed_test_password())

    start = time.perf_counter()
    authenticator.authenticate(TEST_USERNAME, "wrong-password")
    wrong_password = time.perf_counter() - start

    start = time.perf_counter()
    authenticator.authenticate("no-such-user", "wrong-password")
    unknown_user = time.perf_counter() - start

    assert unknown_user > wrong_password / 10, (
        f"unknown user took {unknown_user:.4f}s against "
        f"{wrong_password:.4f}s; the username is leaking through timing")


# =========================================================================
# The login page and endpoint
# =========================================================================

def test_the_login_page_loads_without_a_session(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Sign in" in response.text


def test_the_login_page_contains_no_credentials():
    """The page must not ship a username, a password or a hash."""
    from pathlib import Path

    source = (Path(api_main.__file__).resolve().parent.parent
              / "dashboard" / "login.html").read_text(encoding="utf-8")
    assert TEST_PASSWORD not in source
    assert ALGORITHM not in source
    for word in ["admin123", "password123", "letmein"]:
        assert word not in source.lower()


def test_successful_login_sets_a_session_cookie(client):
    response = login(client)

    assert response.status_code == 200
    assert response.json() == {"authenticated": True,
                               "username": TEST_USERNAME}
    assert SESSION_COOKIE in response.cookies


def test_the_session_cookie_is_httponly_and_samesite_strict(client):
    """HttpOnly stops injected script reading it; SameSite blunts CSRF."""
    header = login(client).headers["set-cookie"].lower()
    assert "httponly" in header
    assert "samesite=strict" in header
    assert "path=/" in header


def test_an_incorrect_password_is_rejected(client):
    response = login(client, password="definitely-wrong")
    assert response.status_code == 401
    assert SESSION_COOKIE not in response.cookies


def test_an_unknown_user_is_rejected(client):
    assert login(client, username="nobody").status_code == 401


def test_the_two_failures_are_indistinguishable(client):
    """Saying which was wrong would let an attacker enumerate accounts."""
    wrong_password = login(client, password="wrong")
    unknown_user = login(client, username="nobody")

    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["detail"] == unknown_user.json()["detail"]
    assert "invalid username or password" in wrong_password.json()["detail"]


def test_no_response_ever_echoes_the_password(client):
    """Not on success, not on failure."""
    assert TEST_PASSWORD not in login(client).text
    assert "nope-wrong" not in login(client, password="nope-wrong").text


@pytest.mark.parametrize("body", [
    {}, {"username": TEST_USERNAME}, {"password": TEST_PASSWORD},
    {"username": 1, "password": 2}, {"username": None, "password": None},
])
def test_a_malformed_login_body_is_rejected(client, body):
    assert client.post("/auth/login", json=body).status_code == 422


def test_login_is_unavailable_when_no_credentials_are_configured(open_client):
    response = open_client.post("/auth/login",
                                json={"username": "a", "password": "b"})
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


# =========================================================================
# Backend enforcement — the part that matters
# =========================================================================

@pytest.mark.parametrize("method,path", PROTECTED)
def test_a_protected_endpoint_refuses_an_unauthenticated_request(
        client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code == 401, f"{path} was reachable without a session"
    assert response.json()["detail"] == "authentication required"


def test_lookup_and_mode_changes_are_protected(client):
    assert client.post("/lookup",
                       json={"domain": "example.com"}).status_code == 401
    assert client.put("/mode", json={"enforce": False}).status_code == 401


def test_protection_does_not_depend_on_the_login_page(client):
    """The claim under test: enforcement is in the backend.

    This never touches /login or /dashboard/ — it goes straight at the API,
    exactly as curl would.
    """
    for method, path in PROTECTED:
        assert getattr(client, method)(path).status_code == 401

    login(client)
    for method, path in PROTECTED:
        assert getattr(client, method)(path).status_code != 401


def test_a_forged_session_cookie_is_rejected(client):
    client.cookies.set(SESSION_COOKIE, "a-made-up-token-value")
    assert client.get("/mode").status_code == 401


def test_a_session_from_another_server_is_rejected(client):
    """Tokens live in one process's memory; they are not portable."""
    other = SessionStore()
    client.cookies.set(SESSION_COOKIE, other.create(TEST_USERNAME).token)
    assert client.get("/mode").status_code == 401


def test_an_authenticated_request_succeeds(client):
    login(client)
    response = client.get("/mode")
    assert response.status_code == 200
    assert response.json()["engine"] == "engine[null]"


def test_health_stays_public(client):
    """Operational monitoring should not require a session."""
    assert client.get("/health").status_code == 200


def test_health_exposes_no_filesystem_path(client):
    """It is public, so it must not describe the host."""
    body = client.get("/health").json()
    assert "path" not in body["database"]
    assert "error" not in body["database"]
    assert body["authentication"] == "enabled"


def test_the_openapi_schema_stays_reachable(client):
    assert client.get("/openapi.json").status_code == 200


# =========================================================================
# Logout
# =========================================================================

def test_logout_ends_the_session(client):
    login(client)
    assert client.get("/mode").status_code == 200

    assert client.post("/auth/logout").status_code == 200
    assert client.get("/mode").status_code == 401


def test_logout_destroys_the_session_server_side(client):
    """A cookie captured before logout must be useless after it.

    Clearing the browser's cookie alone would not achieve that, which is why
    the token is removed from the store.
    """
    token = login(client).cookies[SESSION_COOKIE]
    client.post("/auth/logout")

    client.cookies.set(SESSION_COOKIE, token)
    assert client.get("/mode").status_code == 401, \
        "a pre-logout cookie still worked"


def test_logout_without_a_session_is_harmless(client):
    response = client.post("/auth/logout")
    assert response.status_code == 200
    assert response.json()["session_destroyed"] is False


def test_the_session_endpoint_reports_state(client):
    assert client.get("/auth/session").json() == {
        "authenticated": False, "username": None, "auth_enabled": True}

    login(client)
    assert client.get("/auth/session").json() == {
        "authenticated": True, "username": TEST_USERNAME, "auth_enabled": True}


# =========================================================================
# The dashboard
# =========================================================================

def test_the_dashboard_redirects_when_unauthenticated(client):
    response = client.get("/dashboard/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/login"


def test_the_dashboard_serves_once_authenticated(client):
    login(client)
    response = client.get("/dashboard/")
    assert response.status_code == 200
    assert "DNS filtering console" in response.text


def test_the_root_still_redirects_to_the_dashboard(client):
    response = client.get("/", follow_redirects=False)
    assert response.headers["location"] == "/dashboard/"


def test_the_dashboard_sends_credentials_and_handles_a_lost_session():
    from pathlib import Path

    source = (Path(api_main.__file__).resolve().parent.parent
              / "dashboard" / "index.html").read_text(encoding="utf-8")
    assert 'credentials: "same-origin"' in source
    assert "handleUnauthorised" in source
    assert '/auth/logout' in source


# =========================================================================
# Disabled mode
# =========================================================================

def test_everything_works_with_authentication_disabled(open_client):
    """An existing developer is not locked out by upgrading."""
    assert open_client.get("/mode").status_code == 200
    assert open_client.get("/health").json()["authentication"] == "disabled"
    assert open_client.get("/dashboard/").status_code == 200


def test_disabled_mode_is_announced_not_silent(caplog):
    """It is a configured state, not an accidental bypass."""
    import logging

    with caplog.at_level(logging.WARNING, logger="api.auth"):
        Authenticator(username="", password_hash="")

    assert any("AUTHENTICATION IS DISABLED" in record.message
               for record in caplog.records)


# =========================================================================
# The hash-generation tool
# =========================================================================

def test_the_password_tool_imports():
    """Regression: it imported a constant `api.auth` does not define.

    `tools/make_password_hash.py` is the only supported way to produce a
    value for DNSF_AUTH_PASSWORD_HASH, so an ImportError there makes
    authentication unconfigurable — while the whole test suite still passed,
    because nothing imported the tool.
    """
    import tools.make_password_hash as tool

    assert callable(tool.main)
    assert tool.hash_password is hash_password


def test_the_tool_uses_the_projects_iteration_constant():
    """Not a second copy of the number, which could drift from the real one."""
    import inspect

    import tools.make_password_hash as tool
    from api.auth import ITERATIONS

    assert tool.ITERATIONS == ITERATIONS
    source = inspect.getsource(tool)
    assert "480_000" not in source and "480000" not in source, \
        "the iteration count is duplicated instead of imported"


def test_the_iteration_constant_is_the_documented_value():
    from api.auth import ITERATIONS

    assert ITERATIONS == 480_000


def test_a_hash_from_the_tools_helper_verifies_against_the_authenticator():
    """The tool's output must be usable as DNSF_AUTH_PASSWORD_HASH.

    Uses a throwaway value; no real password appears anywhere in this suite.
    """
    import tools.make_password_hash as tool

    generated = tool.hash_password("throwaway-value-for-this-test")
    authenticator = Authenticator("someone", generated)

    assert authenticator.enabled is True
    assert authenticator.authenticate(
        "someone", "throwaway-value-for-this-test") is not None
    assert authenticator.authenticate("someone", "wrong") is None


def test_the_tool_never_takes_a_password_as_an_argument():
    """An argument would land in shell history and the process list."""
    import inspect

    import tools.make_password_hash as tool

    source = inspect.getsource(tool)
    assert "getpass" in source
    assert "add_argument(\"--password" not in source
