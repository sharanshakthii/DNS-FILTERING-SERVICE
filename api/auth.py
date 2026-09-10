"""
Authentication for the web application (Stage 17).

**Academic / local-development authentication.** It is real backend
enforcement — an unauthenticated request to a protected endpoint is refused
by FastAPI, not hidden by JavaScript — but it is not production-grade, and
the limitations at the bottom of this docstring are not boilerplate.

## Password hashing

PBKDF2-HMAC-SHA256 from the standard library, 480,000 iterations, with a
random 16-byte salt per password. Standards-based and not invented here.

bcrypt or Argon2 would be better: both are deliberately memory-hard and
PBKDF2 is not, which makes PBKDF2 the weaker choice against an attacker with
a GPU. They were not used because either would add a runtime dependency to a
project whose DNS path has run on the standard library since Stage 1, and
whose dependency set is pinned by an existing test. That is a real trade-off
and it is recorded rather than glossed.

Encoded form, safe to put in an environment variable:

    pbkdf2_sha256$480000$<salt hex>$<derived key hex>

## Sessions

An opaque 256-bit random token, stored server-side, delivered in an HttpOnly
cookie. Deliberately not a JWT: a JWT cannot be revoked without a server-side
store, so the store is unavoidable anyway, and a JWT would need a signing
secret to manage. An HttpOnly cookie is also unreadable from JavaScript,
which a token held in page memory is not.

Logout deletes the server-side record, so a captured cookie stops working
immediately rather than remaining valid until it expires.

## Limitations

  * Sessions live in this process's memory. Restarting uvicorn logs everyone
    out, and this will not work across multiple worker processes.
  * CSRF is mitigated by SameSite=Strict and the absence of CORS, not by
    tokens. Adequate for a single-origin local application; not for a
    deployment.
  * No HTTPS, no rate limiting, no account lockout, one user.
  * When no password hash is configured, authentication is DISABLED and the
    API logs a warning. That is deliberate — silently locking a developer
    out of their own project would be worse — but it means the protection is
    only as good as the configuration.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass

from fastapi import Cookie, HTTPException, Response

log = logging.getLogger("api.auth")

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 480_000
SALT_BYTES = 16

SESSION_COOKIE = "prj112_session"

#: Verified against when the username is unknown, so a wrong username and a
#: wrong password cost the same work. Without it, response time alone would
#: tell an attacker which usernames exist.
_DUMMY_HASH = None


def hash_password(password: str, *, salt: bytes | None = None,
                  iterations: int = ITERATIONS) -> str:
    """Encode a password as `pbkdf2_sha256$iterations$salt$key`."""
    if not password:
        raise ValueError("password must not be empty")
    salt = salt if salt is not None else secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Check a password against an encoded hash. Never raises on bad input.

    A malformed hash returns False rather than an exception: a
    misconfiguration must fail closed, not crash the endpoint and reveal the
    stack.
    """
    if not password or not encoded:
        return False
    try:
        algorithm, raw_iterations, salt_hex, key_hex = encoded.split("$")
        if algorithm != ALGORITHM:
            return False
        iterations = int(raw_iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(key_hex)
    except (ValueError, AttributeError):
        return False

    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  iterations)
    return hmac.compare_digest(derived, expected)


def _dummy_hash() -> str:
    """Built once, lazily, so importing this module costs no key derivation."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
    return _DUMMY_HASH


@dataclass(frozen=True)
class Session:
    token: str
    username: str
    created_at: float
    expires_at: float

    def is_valid(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at


class SessionStore:
    """Server-side session records, so logout can actually revoke one."""

    def __init__(self, ttl_s: float = 8 * 3600) -> None:
        if ttl_s <= 0:
            raise ValueError(f"session ttl must be positive, got {ttl_s}")
        self.ttl_s = ttl_s
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}

    def create(self, username: str, now: float | None = None) -> Session:
        now = now if now is not None else time.time()
        # 256 bits from the OS CSPRNG: not guessable, and never derived from
        # the username or the password.
        session = Session(token=secrets.token_urlsafe(32), username=username,
                          created_at=now, expires_at=now + self.ttl_s)
        with self._lock:
            self._prune(now)
            self._sessions[session.token] = session
        return session

    def get(self, token: str | None, now: float | None = None) -> Session | None:
        if not token:
            return None
        now = now if now is not None else time.time()
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if not session.is_valid(now):
                del self._sessions[token]
                return None
            return session

    def revoke(self, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def _prune(self, now: float) -> None:
        expired = [t for t, s in self._sessions.items() if not s.is_valid(now)]
        for token in expired:
            del self._sessions[token]

    @property
    def active(self) -> int:
        with self._lock:
            self._prune(time.time())
            return len(self._sessions)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


class Authenticator:
    """Checks credentials and issues sessions for one configured account."""

    def __init__(self, username: str, password_hash: str,
                 ttl_s: float = 8 * 3600) -> None:
        self.username = (username or "").strip()
        self.password_hash = (password_hash or "").strip()
        self.sessions = SessionStore(ttl_s=ttl_s)

        if not self.enabled:
            log.warning(
                "AUTHENTICATION IS DISABLED: no DNSF_AUTH_PASSWORD_HASH is "
                "configured, so every endpoint is open. Generate a hash with "
                "tools/make_password_hash.py and set DNSF_AUTH_USERNAME and "
                "DNSF_AUTH_PASSWORD_HASH to enable it.")

    @classmethod
    def from_settings(cls, settings) -> "Authenticator":
        return cls(username=settings.auth_username,
                   password_hash=settings.auth_password_hash,
                   ttl_s=settings.auth_session_ttl_s)

    @property
    def enabled(self) -> bool:
        """Authentication is on only when a hash is actually configured."""
        return bool(self.username and self.password_hash)

    def authenticate(self, username: str, password: str) -> Session | None:
        """Return a session for correct credentials, or None.

        An unknown username still runs a key derivation against a throwaway
        hash, so it costs the same as a wrong password. Returning early would
        let an attacker enumerate usernames by timing alone.
        """
        supplied = (username or "").strip()
        if supplied != self.username:
            verify_password(password or "", _dummy_hash())
            return None
        if not verify_password(password or "", self.password_hash):
            return None
        return self.sessions.create(self.username)


def set_session_cookie(response: Response, session: Session,
                       secure: bool = False) -> None:
    """Attach the session cookie.

    HttpOnly so JavaScript cannot read it; SameSite=Strict so a third-party
    page cannot cause an authenticated request; Path=/ so it covers both the
    API and the dashboard. `secure` is off by default because local
    development is over HTTP — it should be on behind TLS.
    """
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session.token,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
        max_age=int(session.expires_at - session.created_at),
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE, path="/")


def unauthorised() -> HTTPException:
    return HTTPException(status_code=401, detail="authentication required")


def session_cookie():
    """The session cookie as a FastAPI parameter default.

    A helper so route signatures do not each repeat the cookie name, and so
    the name lives in exactly one place.
    """
    return Cookie(default=None, alias=SESSION_COOKIE)


def make_dependency(get_authenticator):
    """Build the FastAPI dependency that guards protected endpoints.

    Takes a callable rather than an Authenticator so the application can
    rebuild its authenticator (as the tests do) without the dependency
    holding a stale reference.
    """

    def require_session(
        prj112_session: str | None = Cookie(default=None),
    ) -> Session | None:
        authenticator = get_authenticator()
        if not authenticator.enabled:
            # Explicitly configured open mode; the warning was logged at
            # startup. Not a silent bypass.
            return None
        session = authenticator.sessions.get(prj112_session)
        if session is None:
            raise unauthorised()
        return session

    return require_session
