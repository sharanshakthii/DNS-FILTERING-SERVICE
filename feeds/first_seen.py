"""
First-seen observation store.

Domain age is the signal Stage 6 needs, and there are two honest ways to get
it. They are not the same thing and must never be presented as if they were.

  **Registration age (true NRD).** Requires registry data — ICANN CZDS, or a
  published newly-registered-domain list. CZDS needs an approved ICANN account
  per TLD; a public NRD list needs a URL that actually exists. Neither is
  configured by default, so this is optional and supplied by the operator.

  **Observation age (NOD, "newly observed domain").** How long since *this
  resolver* first saw the name. Needs nothing external, works offline, and is
  what several commercial resolvers actually deploy. It is a proxy for
  registration age, not a measurement of it.

This module implements the second and can consume the first. Every score
records which source produced it in `age_source`, so no reader of the
database can confuse an inference for a registry fact.

The trap this class exists to avoid: on a cold start every domain has been
"first seen just now", so a naive implementation flags the entire internet as
new. The store therefore reports how long it has itself been observing, and
the module refuses to judge until that window exceeds the age threshold it
would apply. Warming up is stated in the evidence rather than hidden.
"""

from __future__ import annotations

import threading
import time


class FirstSeenStore:
    """Records when each domain was first observed by this resolver."""

    def __init__(self, max_entries: int = 200_000,
                 started_at: float | None = None) -> None:
        self._lock = threading.RLock()
        self._first_seen: dict[str, float] = {}
        self.max_entries = max_entries
        self.started_at = started_at if started_at is not None else time.time()
        self.evictions = 0

    def observe(self, domain: str, now: float | None = None) -> tuple[float, bool]:
        """Record an observation. Returns (first_seen_ts, is_first_time)."""
        now = now if now is not None else time.time()
        with self._lock:
            existing = self._first_seen.get(domain)
            if existing is not None:
                return existing, False

            if len(self._first_seen) >= self.max_entries:
                self._evict()

            self._first_seen[domain] = now
            return now, True

    def _evict(self) -> None:
        """Drop the oldest tenth so the store cannot grow without bound.

        Oldest-first is deliberate: the oldest entries are the ones whose age
        already exceeds any threshold we apply, so losing them costs the least
        information. Evicting a *recent* entry would make a domain we just saw
        look new all over again.
        """
        with self._lock:
            drop = max(1, len(self._first_seen) // 10)
            oldest = sorted(self._first_seen.items(), key=lambda kv: kv[1])[:drop]
            for domain, _ts in oldest:
                del self._first_seen[domain]
            self.evictions += drop

    def first_seen(self, domain: str) -> float | None:
        with self._lock:
            return self._first_seen.get(domain)

    def age_s(self, domain: str, now: float | None = None) -> float | None:
        """Seconds since first observation, or None if never seen."""
        seen = self.first_seen(domain)
        if seen is None:
            return None
        return (now if now is not None else time.time()) - seen

    def window_s(self, now: float | None = None) -> float:
        """How long this store has been observing.

        An age can never be more reliable than the window that produced it,
        and the module uses this to decide whether it is entitled to an
        opinion at all.
        """
        return (now if now is not None else time.time()) - self.started_at

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._first_seen)

    def stats(self) -> dict:
        return {
            "tracked": self.size,
            "window_s": round(self.window_s(), 1),
            "evictions": self.evictions,
            "max_entries": self.max_entries,
        }
