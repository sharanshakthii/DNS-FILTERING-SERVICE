"""
Indicator cache.

Lookups happen on the DNS query path, so this has to be an in-memory set
lookup. A network call or a database query per DNS query would dominate the
latency measurement and make RQ2 meaningless — we would be reporting the
speed of our database, not the cost of threat-intelligence filtering.

Refreshes swap a whole new set in atomically under a lock. Mutating a live
set would let a query see a half-loaded feed and score a listed domain as
clean, which is a false negative caused purely by our own bookkeeping.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from .base import FeedSnapshot

log = logging.getLogger("feeds.cache")

#: Never match a parent with fewer than this many labels. Guards the obvious
#: catastrophe: a feed listing `co.uk` or `com` would otherwise block the
#: internet. It does not solve the general problem — see MATCH_LIMITATION.
MIN_PARENT_LABELS = 2

MATCH_LIMITATION = """\
Parent matching uses a label-count floor, not a public-suffix list. If a feed
lists a domain that is itself a public suffix with three or more labels — for
example a free-hosting domain such as `sub.example.co.uk` style registries, or
`000webhostapp.com` style shared hosts — every customer under it will match.
This is the collateral damage Griffioen et al. (ACNS 2020) documented at IP
level, reproduced at name level. It is a known false-positive source and is
reported as a limitation rather than claimed to be solved."""


@dataclass(frozen=True)
class Match:
    """Why a domain matched. This is the evidence, not a debug aid."""

    indicator: str      # the listed domain that matched
    feed: str
    match_type: str     # "exact" or "parent"


class IndicatorCache:
    """Holds the current indicator set for one or more feeds."""

    def __init__(self, match_parents: bool = True,
                 min_parent_labels: int = MIN_PARENT_LABELS,
                 psl_mode: str = "off") -> None:
        self._lock = threading.RLock()
        self._domains: dict[str, str] = {}     # domain -> feed name
        self._snapshots: dict[str, FeedSnapshot] = {}
        self.match_parents = match_parents
        self.min_parent_labels = min_parent_labels
        #: With the PSL on, a parent match never climbs to a public suffix:
        #: a feed listing `pages.dev` must not match every site hosted there.
        from .psl import check_mode
        self.psl_mode = check_mode(psl_mode)

    # -- population --------------------------------------------------------

    def apply(self, snapshot: FeedSnapshot) -> bool:
        """Install a snapshot. Returns False for a failed fetch.

        A failed fetch never clears what we already hold: stale indicators
        are worth more than none, and the age is recorded so a consumer can
        judge for itself.
        """
        if not snapshot.ok:
            log.warning("feed %s failed, keeping %d existing indicators: %s",
                        snapshot.feed, self.size, snapshot.error)
            with self._lock:
                previous = self._snapshots.get(snapshot.feed)
                if previous is not None:
                    # Preserve the last good fetch time; record the failure.
                    self._snapshots[snapshot.feed] = FeedSnapshot(
                        feed=snapshot.feed, domains=previous.domains,
                        fetched_at=previous.fetched_at, source=previous.source,
                        error=snapshot.error)
                else:
                    self._snapshots[snapshot.feed] = snapshot
            return False

        with self._lock:
            # Rebuild the whole index rather than mutating in place, then
            # swap. Readers hold the lock only for the duration of a dict
            # lookup, so they never observe a partial feed.
            rebuilt = {d: feed
                       for feed, snap in self._snapshots.items()
                       if feed != snapshot.feed and snap.ok
                       for d in snap.domains}
            for domain in snapshot.domains:
                rebuilt[domain] = snapshot.feed

            self._snapshots[snapshot.feed] = snapshot
            self._domains = rebuilt

        log.info("feed %s loaded: %d indicators (%d total across %d feeds)",
                 snapshot.feed, snapshot.entry_count, self.size,
                 len(self._snapshots))
        return True

    # -- lookup ------------------------------------------------------------

    def lookup(self, qname: str) -> Match | None:
        """Exact match first, then progressively shorter parent domains."""
        if not qname:
            return None
        name = qname.strip().lower().rstrip(".")

        with self._lock:
            feed = self._domains.get(name)
            if feed is not None:
                return Match(indicator=name, feed=feed, match_type="exact")

            if not self.match_parents:
                return None

            labels = name.split(".")
            # Start one label in; stop before going shorter than the floor.
            for i in range(1, len(labels) - self.min_parent_labels + 1):
                parent = ".".join(labels[i:])
                if self.psl_mode != "off" and self._is_suffix(parent):
                    break
                feed = self._domains.get(parent)
                if feed is not None:
                    return Match(indicator=parent, feed=feed,
                                 match_type="parent")
        return None

    def _is_suffix(self, name: str) -> bool:
        from .psl import registrable_domain
        return registrable_domain(name,
                                  private=(self.psl_mode == "full")) is None

    def __contains__(self, qname: str) -> bool:
        return self.lookup(qname) is not None

    # -- state -------------------------------------------------------------

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._domains)

    @property
    def ready(self) -> bool:
        """True while usable indicators are held.

        Deliberately based on what we hold, not on whether the most recent
        fetch succeeded. Tying it to the last fetch meant a single transient
        network failure flipped the TI module into FeedUnavailable while a
        perfectly good indicator set was still loaded and matching — turning
        a brief outage at the publisher into a total loss of the signal. The
        age is reported separately so a stale set can be judged on its own
        terms.
        """
        with self._lock:
            return bool(self._domains)

    def snapshots(self) -> list[FeedSnapshot]:
        with self._lock:
            return list(self._snapshots.values())

    def staleness_s(self, now: float | None = None) -> float | None:
        """Age of the oldest indicator set we hold, or None if empty.

        `fetched_at` on a failure snapshot carries the last *successful*
        fetch time, so this keeps growing during an outage rather than
        resetting — which is exactly what a consumer needs to see.
        """
        now = now if now is not None else time.time()
        with self._lock:
            ages = [now - s.fetched_at for s in self._snapshots.values()
                    if s.domains]
        return max(ages) if ages else None

    def stats(self) -> dict:
        with self._lock:
            snaps = list(self._snapshots.values())
        return {
            "indicators": self.size,
            "feeds": len(snaps),
            "ready": self.ready,
            "staleness_s": (round(self.staleness_s(), 1)
                            if self.staleness_s() is not None else None),
            "sources": {s.feed: {"entries": s.entry_count,
                                 "age_s": round(s.age_s(), 1),
                                 "error": s.error} for s in snaps},
        }
