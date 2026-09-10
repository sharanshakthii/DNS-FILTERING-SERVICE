"""
Stage 10 — FastAPI backend.

A read-mostly presentation layer over decisions the DNS proxy has already
made. The dependency direction is one-way and deliberate:

    DNS client -> proxy -> modules -> aggregation -> decision
               -> enforcement -> SQLite -> this API -> dashboard

Nothing here participates in resolving a DNS query. The proxy does not import
this module, does not know it exists, and is unaffected if it is not running.
That separation is what keeps dashboard load off the query path, and it is
why the latency figures RQ2 reports stay meaningful.

**Two consequences a reviewer will ask about, stated plainly.**

The API and the proxy are separate OS processes. So `PUT /mode` cannot change
the behaviour of a running proxy — it has no handle on the proxy's memory —
and every mode response says `affects_running_proxy: false` rather than
implying otherwise. Making it work would need IPC or a shared control table,
which is new architecture and outside Stage 10.

For the same reason `POST /lookup` scores a domain using *this process's*
engine instance. Feed indicators will match the proxy's, because both load
the same file. Observation-age state will not, because the first-seen store
is per-process. The response labels which engine answered.

Run:
    python -m uvicorn api.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
import re
import struct
import time
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from config.settings import Settings

from . import auth
from .repository import VALID_VERDICTS, DatabaseUnavailable, DecisionRepository

log = logging.getLogger("api")

API_VERSION = "0.10.0"
STARTED_AT = time.time()

#: Conservative hostname check for /lookup input. Rejects anything that is not
#: plausibly a domain before it reaches the engine.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

app = FastAPI(
    title="PRJ_112 DNS Filtering API",
    version=API_VERSION,
    description=(
        "Read access to decisions made by the DNS filtering proxy. "
        "Local development only: there is no authentication, and this is "
        "not production-ready. Detection accuracy is NOT YET MEASURED."),
)

settings = Settings.from_env()
repository = DecisionRepository(settings.db_path)

#: Built on first use rather than at import, so the API starts even when no
#: feed file is present and so importing the module never performs I/O.
_engine: Any = None

#: Same pattern for the authenticator, so a test can replace `settings` and
#: reset this to pick up new credentials.
_authenticator: Any = None


def get_authenticator() -> auth.Authenticator:
    global _authenticator
    if _authenticator is None:
        _authenticator = auth.Authenticator.from_settings(settings)
    return _authenticator


#: Guards every endpoint that exposes stored data or changes configuration.
#: Enforced by FastAPI before the handler runs, so an unauthenticated request
#: never reaches the query or the database — the protection does not depend
#: on the dashboard hiding anything.
require_session = auth.make_dependency(get_authenticator)
protected = [Depends(require_session)]


def get_engine():
    """The engine this process uses for /lookup and /mode.

    Separate from the proxy's engine. Constructed through the same
    `build_engine` the proxy uses, so /lookup exercises the real decision
    path rather than a reimplementation of it.
    """
    global _engine
    if _engine is None:
        from proxy.dns_proxy import build_engine
        _engine = build_engine(settings)
    return _engine


def _registry_names() -> set[str]:
    """Module names this build can construct, read from the engine registry."""
    from engine.modules import REGISTRY
    return set(REGISTRY)


def _mode_payload() -> dict:
    engine = get_engine()
    aggregator = getattr(engine, "aggregator", None)
    modules = getattr(engine, "modules", [])

    return {
        "engine": engine.name,
        "modules": [{"name": m.name, "enabled": m.enabled} for m in modules],
        "enforcement": {
            "enabled": bool(getattr(aggregator, "enforce", False)),
            "fail_mode": getattr(aggregator, "fail_mode", "open"),
        },
        "thresholds": {
            "flag_at": getattr(aggregator, "flag_at", None),
            "block_at": getattr(aggregator, "block_at", None),
        },
        "block_response": settings.block_response,
        # Every module the build can construct, whether or not this engine
        # uses one. Without it a client cannot tell "implemented but not
        # enabled" from "not implemented at all", and would mislabel a
        # working module as missing.
        "available_modules": sorted(_registry_names()),
        # The single most important field on this endpoint.
        "affects_running_proxy": False,
        "scope": ("This process only. The DNS proxy runs separately and reads "
                  "its configuration from its own environment at startup; "
                  "changes here do not reach it."),
    }


# -- health ---------------------------------------------------------------

@app.get("/health", tags=["system"])
def health() -> dict:
    """Liveness plus database reachability.

    Not a production health check: it does not verify the DNS proxy is
    running, that feeds are fresh, or that anything is being filtered.
    """
    available, _reason = repository.available()
    # Public, so it carries no filesystem path and no error detail: both
    # would tell an unauthenticated caller about the host. Whether the
    # database is readable is the operational fact worth exposing.
    return {
        "status": "ok",
        "api_version": API_VERSION,
        "uptime_s": round(time.time() - STARTED_AT, 1),
        "authentication": "enabled" if get_authenticator().enabled
                          else "disabled",
        "database": {
            "available": available,
            "schema_version": repository.schema_version(),
        },
        "note": ("Reports that this API process is alive and whether it can "
                 "read the database. It does not check the DNS proxy. "
                 "Public by design, so it deliberately omits paths and "
                 "error detail."),
    }


# -- decisions ------------------------------------------------------------

@app.get("/decisions", tags=["decisions"], dependencies=protected)
def list_decisions(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    verdict: str | None = Query(None, description="ALLOW, FLAG, BLOCK, ..."),
    qname: str | None = Query(None, max_length=253,
                              description="prefix match on the queried name"),
) -> dict:
    """Stored decisions, newest first.

    Client addresses are not returned: only the salted digest recorded at
    write time. The raw address was never persisted, so there is nothing to
    redact here.
    """
    if verdict is not None:
        verdict = verdict.strip().upper()
        if verdict not in VALID_VERDICTS:
            raise HTTPException(
                status_code=422,
                detail=f"unknown verdict {verdict!r}; expected one of "
                       f"{sorted(VALID_VERDICTS)}")

    try:
        decisions, total = repository.list_decisions(
            limit=limit, offset=offset, verdict=verdict, qname=qname)
    except DatabaseUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return {
        "decisions": decisions,
        "count": len(decisions),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/decisions/{decision_id}/evidence", tags=["decisions"],
         dependencies=protected)
def decision_evidence(decision_id: int) -> dict:
    """Per-module evidence and the aggregation derivation for one decision.

    This is the project's contribution made visible: not just the verdict,
    but which module contributed what, with the feature values behind it.
    """
    try:
        evidence = repository.get_evidence(decision_id)
    except DatabaseUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if evidence is None:
        raise HTTPException(status_code=404,
                            detail=f"no decision with id {decision_id}")
    return evidence


# -- statistics -----------------------------------------------------------

@app.get("/stats", tags=["system"], dependencies=protected)
def stats() -> dict:
    """Counts computed by the database.

    An unreachable database is a 503, never an empty result: "no data" and
    "cannot read the data" are different answers and must not look alike.
    """
    try:
        return repository.stats()
    except DatabaseUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# -- lookup ---------------------------------------------------------------

def _synthetic_query(domain: str):
    """Build a real `Query` for `domain` by encoding and parsing a DNS packet.

    `decide()` takes a parsed query, so /lookup needs one. Rather than passing
    a hand-made stand-in that happens to expose the attributes the current
    engine reads, the name is encoded to the wire and handed to the project's
    own parser. The lookup is then validated by exactly the code a real
    resolution would go through — a name with an over-long label is rejected
    here for the same reason it would be rejected on the wire, instead of
    reaching an engine that was never designed to see it.

    No packet is sent anywhere. This is construction and parsing only.
    """
    from proxy.packet import parse_query

    header = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode("ascii")
                     for label in domain.split(".")) + b"\x00"
    return parse_query(header + qname + struct.pack("!HH", 1, 1))


@app.post("/lookup", tags=["decisions"], dependencies=protected)
def lookup(payload: dict = Body(..., examples=[{"domain": "example.com"}])) -> dict:
    """Score a domain now, through the engine's own decision interface.

    This performs a **live evaluation**, not a database read. Nothing is
    enforced and no DNS response is sent — this endpoint cannot block
    anything.

    It calls `decide()`, which is the one method every engine in this project
    implements, so the result is whatever the configured engine genuinely
    concludes. With the default allow-all engine that is an ALLOW with no
    modules and no derivation, and the response says so rather than
    manufacturing a score.

    The engine is this process's own, so observation-age state differs from
    the running proxy's. The response says so.
    """
    domain = payload.get("domain") if isinstance(payload, dict) else None
    if not isinstance(domain, str) or not domain.strip():
        raise HTTPException(status_code=422,
                            detail="body must be {\"domain\": \"<name>\"}")

    domain = domain.strip().lower().rstrip(".")
    if len(domain) > 253 or not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=422,
                            detail=f"{domain!r} is not a valid domain name")

    from proxy.packet import MalformedQuery
    from proxy.timing import Stopwatch

    try:
        query = _synthetic_query(domain)
    except (MalformedQuery, UnicodeEncodeError, struct.error) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"{domain!r} cannot be encoded as a DNS query: {exc}") from exc

    engine = get_engine()
    stopwatch = Stopwatch()
    started = time.perf_counter()
    decision = engine.decide(query, stopwatch, client_id="api")
    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)

    # Engines that do not aggregate return neither key. Reporting them as
    # null keeps the response shape stable while making it obvious that no
    # derivation exists, rather than inventing an empty one.
    explanation = decision.get("explanation")
    enforcement = decision.get("enforcement")

    note = ("Live evaluation by this API process's engine. No DNS "
            "response was sent and nothing was enforced. Module state "
            "such as first-seen history is independent of the running "
            "proxy.")
    if explanation is None:
        note += (f" The engine in use ({engine.name}) performs no detection, "
                 f"so there is no score derivation to show.")

    return {
        "qname": domain,
        "source": "live",
        "engine": engine.name,
        "verdict": decision["verdict"],
        "score": decision["score"],
        "enforcement": enforcement,
        "modules": decision.get("evidence") or [],
        "explanation": explanation,
        "evaluation_ms": elapsed_ms,
        "note": note,
    }


# -- mode -----------------------------------------------------------------

@app.get("/mode", tags=["mode"], dependencies=protected)
def get_mode() -> dict:
    """The filtering configuration of this API process."""
    return _mode_payload()


@app.put("/mode", tags=["mode"], dependencies=protected)
def put_mode(payload: dict = Body(
    ..., examples=[{"modules": {"ti": True}, "enforce": False}])) -> dict:
    """Change this process's engine configuration.

    Scope is the point of this endpoint and its main limitation: it changes
    the engine `/lookup` uses, which makes it the ablation control surface
    Stage 16 needs. It does **not** reach the running DNS proxy, which reads
    its configuration from its own environment at startup.

    Only two things are mutable, both single attribute assignments (atomic in
    CPython): a module's `enabled` flag and the aggregator's `enforce` flag.
    No shared structure is rebuilt, so there is nothing here for a concurrent
    request to observe half-changed. Thresholds and weights are deliberately
    immutable at runtime — changing them mid-run would make stored decisions
    incomparable with each other.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="body must be a JSON object")

    engine = get_engine()
    unknown = set(payload) - {"modules", "enforce"}
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"unsupported field(s): {sorted(unknown)}. Only 'modules' "
                   f"and 'enforce' can be changed at runtime.")

    changed: list[str] = []

    modules = payload.get("modules")
    if modules is not None:
        if not isinstance(modules, dict):
            raise HTTPException(status_code=422,
                                detail="'modules' must be an object of "
                                       "name -> true/false")
        known = {m.name for m in engine.modules}
        for name, enabled in modules.items():
            if name not in known:
                raise HTTPException(
                    status_code=422,
                    detail=f"unknown module {name!r}; this engine has "
                           f"{sorted(known)}")
            if not isinstance(enabled, bool):
                raise HTTPException(
                    status_code=422,
                    detail=f"module {name!r} must be true or false")
            if engine.set_enabled(name, enabled):
                changed.append(f"module {name}={enabled}")

    enforce = payload.get("enforce")
    if enforce is not None:
        if not isinstance(enforce, bool):
            raise HTTPException(status_code=422,
                                detail="'enforce' must be true or false")
        engine.aggregator.enforce = enforce
        changed.append(f"enforce={enforce}")

    log.info("mode changed via API: %s", ", ".join(changed) or "nothing")
    return {**_mode_payload(), "changed": changed}


# -- error shape ----------------------------------------------------------

@app.exception_handler(DatabaseUnavailable)
def _database_unavailable(_request, exc: DatabaseUnavailable) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(exc)})


# -- authentication (Stage 17) --------------------------------------------

@app.post("/auth/login", tags=["auth"])
def login(response: Response,
          payload: dict = Body(..., examples=[{"username": "admin",
                                               "password": "…"}])) -> dict:
    """Exchange credentials for a session cookie.

    The password is read from the request body, never a query parameter, so
    it cannot end up in a browser history, a proxy log or an access log.
    Nothing about the submitted password is echoed back or logged.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="body must be a JSON object")

    authenticator = get_authenticator()
    if not authenticator.enabled:
        raise HTTPException(
            status_code=503,
            detail="authentication is not configured on this server; set "
                   "DNSF_AUTH_USERNAME and DNSF_AUTH_PASSWORD_HASH")

    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise HTTPException(
            status_code=422,
            detail="body must be {\"username\": \"…\", \"password\": \"…\"}")

    session = authenticator.authenticate(username, password)
    if session is None:
        # One message for both a wrong password and an unknown user. Saying
        # which would let an attacker enumerate accounts.
        log.warning("failed login attempt for username %r", username[:64])
        raise HTTPException(status_code=401,
                            detail="invalid username or password")

    auth.set_session_cookie(response, session,
                            secure=settings.auth_cookie_secure)
    log.info("login succeeded for %r", session.username)
    return {"authenticated": True, "username": session.username}


@app.post("/auth/logout", tags=["auth"])
def logout(response: Response,
           prj112_session: str | None = auth.session_cookie()) -> dict:
    """Destroy the session server-side and clear the cookie.

    The token is removed from the store, so a copy of the cookie captured
    beforehand is useless afterwards. Clearing the cookie alone would not
    achieve that.
    """
    destroyed = get_authenticator().sessions.revoke(prj112_session)
    auth.clear_session_cookie(response)
    return {"authenticated": False, "session_destroyed": destroyed}


@app.get("/auth/session", tags=["auth"])
def session_state(prj112_session: str | None = auth.session_cookie()) -> dict:
    """Whether this caller is authenticated. Used by the dashboard on load."""
    authenticator = get_authenticator()
    if not authenticator.enabled:
        return {"authenticated": True, "username": None,
                "auth_enabled": False,
                "note": "authentication is not configured on this server"}

    session = authenticator.sessions.get(prj112_session)
    return {"authenticated": session is not None,
            "username": session.username if session else None,
            "auth_enabled": True}


# -- dashboard (Stage 11, gated in Stage 17) ------------------------------

#: Served from the same origin as the API so the page needs no host
#: configuration and no CORS. Served through routes rather than a StaticFiles
#: mount because a mount cannot be gated by a dependency, and the dashboard
#: must not render for an unauthenticated caller.
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


def _page(name: str) -> FileResponse:
    return FileResponse(DASHBOARD_DIR / name, media_type="text/html")


if DASHBOARD_DIR.is_dir():

    @app.get("/login", include_in_schema=False)
    def login_page() -> FileResponse:
        """Public: the page that collects credentials."""
        return _page("login.html")

    @app.get("/dashboard/", include_in_schema=False)
    def dashboard_page(
        prj112_session: str | None = auth.session_cookie(),
    ):
        """The console. Unauthenticated callers are sent to the login page.

        A redirect rather than a 401 because this is a browser navigation,
        not an API call. The data the console displays is protected
        separately at each endpoint, so this redirect is a convenience and
        not the security boundary.
        """
        authenticator = get_authenticator()
        if authenticator.enabled and \
                authenticator.sessions.get(prj112_session) is None:
            return RedirectResponse(url="/login", status_code=302)
        return _page("index.html")

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard/")
else:  # pragma: no cover - only when the directory has been removed
    log.warning("no dashboard/ directory at %s; the API runs without a UI",
                DASHBOARD_DIR)
