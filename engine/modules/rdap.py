"""
Registration-age module (RDAP).

The `nrd` module can only say how long *this resolver* has seen a domain,
and it refuses to judge for its first seven days. That is honest, and it
leaves the most dangerous window — a domain registered this week — covered
by nothing but a feed that has not listed it yet.

RDAP (RFC 9082/9083) is the registries' structured successor to WHOIS. It is
free, needs no account, and returns the domain's real `registration` event.
This module asks for it, so the age it reports is registration age, not
observation age, and the evidence says `age_source: "rdap"` so the two can
never be confused.

**Never on the query path.** A lookup is a network round trip of tens to
hundreds of milliseconds, which would dominate the latency RQ2 reports. The
first query for a domain starts a background lookup and the module reports
itself unavailable for that query (excluded from aggregation, never scored
zero); later queries read the cached answer in microseconds.

**Privacy.** A lookup sends the registrable domain — not the full hostname,
and nothing about the client — to the RDAP service. That is a disclosure the
DNS path itself avoids for blocked names, and it is why this module is opt-in
through DNSF_ENGINE_MODULES like every other.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .base import DetectionModule, ModuleScore, ModuleUnavailable, QueryContext

log = logging.getLogger("engine.rdap")

#: rdap.org redirects each query to the authoritative registry's RDAP server
#: using the IANA bootstrap registry. Verified reachable during development.
DEFAULT_BASE_URL = "https://rdap.org/domain/"

#: Registered at or within this many seconds ago: score 1.0.
DEFAULT_NEW_WITHIN_S = 30 * 24 * 3600.0
#: Registered at least this long ago: score 0.0, linear in between.
DEFAULT_ESTABLISHED_AFTER_S = 365 * 24 * 3600.0

#: Names that are never registered in public DNS, so asking is pointless and
#: would leak internal hostnames to a third party.
_PRIVATE_TLDS = frozenset({
    "local", "localhost", "test", "example", "invalid", "internal", "lan",
    "home", "corp", "intranet", "arpa", "onion",
})


class RegistrationPending(ModuleUnavailable):
    """The lookup for this domain is in flight; no answer yet."""


class RegistrationUnknown(ModuleUnavailable):
    """The registry did not supply a registration date for this domain."""


class RegistrationShared(ModuleUnavailable):
    """The name is a site on a shared hosting platform (PSL private section).

    Its only registration is the platform's — `pages.dev` was registered
    years ago by its operator — so a registration age would describe the
    platform, not this site. Scoring that as 0.0 claimed a clean assessment
    that never happened; this says "cannot assess" instead.
    """


class RdapAgeModule(DetectionModule):
    """Scores a domain by how recently it was registered."""

    name = "rdap"

    def __init__(self, base_url: str = DEFAULT_BASE_URL,
                 new_within_s: float = DEFAULT_NEW_WITHIN_S,
                 established_after_s: float = DEFAULT_ESTABLISHED_AFTER_S,
                 timeout_s: float = 6.0,
                 max_cached: int = 50000,
                 ok_ttl_s: float = 7 * 24 * 3600.0,
                 fail_ttl_s: float = 3600.0,
                 workers: int = 2,
                 fetch=None,
                 psl_mode: str = "off") -> None:
        """`fetch(domain) -> float | None` replaces the network in tests.

        It returns a registration timestamp, None when the registry has no
        date, or raises when the lookup failed.
        """
        if established_after_s <= new_within_s:
            raise ValueError("established_after_s must exceed new_within_s")
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.new_within_s = new_within_s
        self.established_after_s = established_after_s
        self.timeout_s = timeout_s
        self.max_cached = max_cached
        self.ok_ttl_s = ok_ttl_s
        self.fail_ttl_s = fail_ttl_s
        self._fetch = fetch or self.fetch_registration
        from feeds.psl import check_mode
        self.psl_mode = check_mode(psl_mode)

        # domain -> (registered_ts | None, cached_at, error | None)
        self._cache: OrderedDict[str, tuple] = OrderedDict()
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=workers,
                                        thread_name_prefix="rdap")

    @classmethod
    def from_settings(cls, settings) -> "RdapAgeModule":
        return cls(
            base_url=settings.rdap_base_url or DEFAULT_BASE_URL,
            new_within_s=settings.rdap_new_within_s,
            established_after_s=settings.rdap_established_after_s,
            timeout_s=settings.rdap_timeout_s,
            psl_mode=getattr(settings, "psl_mode", "off"),
        )

    # -- scoring -----------------------------------------------------------

    def score_for_age(self, age_s: float) -> float:
        """1.0 when new, 0.0 when established, linear in between."""
        if age_s <= self.new_within_s:
            return 1.0
        if age_s >= self.established_after_s:
            return 0.0
        span = self.established_after_s - self.new_within_s
        return round(1.0 - (age_s - self.new_within_s) / span, 6)

    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        registrable = self._registration(ctx.qname)
        if registrable is None:
            raise RegistrationUnknown(
                f"{ctx.qname} is not a publicly registrable name")
        if self.psl_mode == "full":
            from feeds.psl import on_shared_platform, public_suffix
            if on_shared_platform(ctx.qname):
                raise RegistrationShared(
                    f"{ctx.qname} is hosted on the shared platform "
                    f"{public_suffix(ctx.qname)}; its registration age "
                    f"belongs to the platform, not this site")

        now = ctx.timestamp
        entry = self._cached(registrable, now)
        if entry is None:
            self._schedule(registrable)
            raise RegistrationPending(
                f"registration lookup for {registrable} started; "
                f"the next query will be scored")

        registered_ts, _cached_at, error = entry
        if error is not None:
            raise RegistrationUnknown(
                f"registration lookup for {registrable} failed: {error}")
        if registered_ts is None:
            raise RegistrationUnknown(
                f"the registry returned no registration date for {registrable}")

        age_s = max(0.0, now - registered_ts)
        return ModuleScore(
            score=self.score_for_age(age_s),
            features={
                "age_source": "rdap",
                "registrable": registrable,
                "registered": datetime.fromtimestamp(
                    registered_ts, timezone.utc).strftime("%Y-%m-%d"),
                "registration_age_days": round(age_s / 86400.0, 1),
                "new_within_days": round(self.new_within_s / 86400.0, 1),
                "established_after_days":
                    round(self.established_after_s / 86400.0, 1),
                "note": "A recent registration is a risk signal, not proof "
                        "of malice; legitimate sites are new too.",
            },
        )

    # -- cache and background lookup ---------------------------------------

    def _cached(self, domain: str, now: float):
        with self._lock:
            entry = self._cache.get(domain)
            if entry is None:
                return None
            ttl = self.fail_ttl_s if entry[2] is not None else self.ok_ttl_s
            if now - entry[1] > ttl:
                del self._cache[domain]
                return None
            self._cache.move_to_end(domain)
            return entry

    def _store(self, domain: str, entry: tuple) -> None:
        with self._lock:
            self._cache[domain] = entry
            self._cache.move_to_end(domain)
            while len(self._cache) > self.max_cached:
                self._cache.popitem(last=False)
            self._pending.discard(domain)

    def _schedule(self, domain: str) -> None:
        with self._lock:
            if domain in self._pending:
                return
            self._pending.add(domain)
        try:
            self._pool.submit(self._lookup, domain)
        except RuntimeError:
            # Pool already shut down (module closing); nothing to do.
            with self._lock:
                self._pending.discard(domain)

    def _lookup(self, domain: str) -> None:
        try:
            registered = self._fetch(domain)
            self._store(domain, (registered, time.time(), None))
        except Exception as exc:
            log.info("rdap lookup for %s failed: %s", domain, exc)
            self._store(domain, (None, time.time(),
                                 f"{type(exc).__name__}: {str(exc)[:120]}"))

    def fetch_registration(self, domain: str) -> float | None:
        """One synchronous RDAP lookup. Used by the background pool, and by
        tools/make_real_dataset.py so collection and runtime share one
        implementation."""
        request = urllib.request.Request(
            self.base_url + domain,
            headers={"Accept": "application/rdap+json",
                     "User-Agent": "prj112-dns-filter"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read(512 * 1024).decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # Not registered (or the registry does not know it): there is
                # no registration date to report.
                return None
            raise
        return parse_registration(body)

    def preload(self, domain: str, registered_ts: float | None,
                error: str | None = None, cached_at: float | None = None) -> None:
        """Install a known answer, e.g. from a frozen evaluation dataset."""
        self._store(domain, (registered_ts,
                             time.time() if cached_at is None else cached_at,
                             error))

    def wait_idle(self, timeout_s: float = 10.0) -> bool:
        """Block until no lookup is pending. For tests and tools only."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self._lock:
                if not self._pending:
                    return True
            time.sleep(0.01)
        return False

    def _registration(self, qname: str) -> str | None:
        """The domain a registry holds a record for.

        With the PSL off: the last-two-labels approximation. Otherwise the
        ICANN registrable domain, in both `icann` and `full` mode — RDAP
        records exist only at that level, so `local.gov.uk` is looked up
        rather than the suffix `gov.uk`.
        """
        legacy = self._registrable(qname)
        if self.psl_mode == "off" or legacy is None:
            return legacy
        from feeds.psl import registrable_domain
        return registrable_domain(qname, private=False)

    @staticmethod
    def _registrable(qname: str) -> str | None:
        """Last two labels, the same approximation `nrd` uses.

        Returns None for names that are never publicly registered, so no
        internal hostname is ever sent to the RDAP service.
        """
        labels = [l for l in qname.lower().rstrip(".").split(".") if l]
        if len(labels) < 2 or labels[-1] in _PRIVATE_TLDS:
            return None
        if all(l.isdigit() for l in labels):
            return None   # a dotted IPv4 literal, not a domain
        return ".".join(labels[-2:])

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def parse_registration(body: dict) -> float | None:
    """The `registration` event's timestamp, or None if absent."""
    for event in body.get("events") or []:
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            raw = str(event["eventDate"]).replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(raw).timestamp()
            except ValueError:
                # Some registries emit fractional seconds fromisoformat
                # rejects on older Pythons; trim to seconds and retry.
                return datetime.fromisoformat(raw[:19] + "+00:00").timestamp()
    return None
