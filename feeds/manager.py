"""
Feed manager.

Owns the sources and the cache, refreshes on a schedule, and reports feed
state to storage. Refresh runs on its own thread so a slow or hanging feed
fetch can never sit on the DNS query path.
"""

from __future__ import annotations

import logging
import threading
import time

from .base import FeedSource
from .cache import IndicatorCache

log = logging.getLogger("feeds.manager")


class FeedManager:
    """Refreshes feed sources into an IndicatorCache."""

    def __init__(self, sources: list[FeedSource], cache: IndicatorCache | None = None,
                 interval_s: float = 3600.0, on_snapshot=None) -> None:
        """`on_snapshot(snapshot)` is called after each fetch, for persistence.

        Passed as a callback rather than importing `storage` so the feed
        layer stays independent of the database, exactly as the proxy does
        with its recorder.
        """
        self.sources = list(sources)
        self.cache = cache or IndicatorCache()
        self.interval_s = interval_s
        self.on_snapshot = on_snapshot

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.refresh_count = 0
        self.failure_count = 0

    def refresh(self) -> int:
        """Fetch every source once. Returns how many succeeded."""
        succeeded = 0
        for source in self.sources:
            started = time.perf_counter()
            snapshot = source.fetch()
            elapsed = (time.perf_counter() - started) * 1000.0

            if self.cache.apply(snapshot):
                succeeded += 1
            else:
                self.failure_count += 1

            log.info("fetched %s in %.0f ms: %s", source.name, elapsed,
                     f"{snapshot.entry_count} indicators" if snapshot.ok
                     else f"FAILED ({snapshot.error})")

            if self.on_snapshot is not None:
                try:
                    self.on_snapshot(snapshot)
                except Exception:
                    log.exception("feed_state persistence failed for %s",
                                  source.name)

        self.refresh_count += 1
        return succeeded

    # -- background refresh ------------------------------------------------

    def start(self, refresh_now: bool = True) -> "FeedManager":
        """Begin periodic refresh on a daemon thread."""
        if refresh_now:
            self.refresh()
        if self.interval_s <= 0:
            log.info("periodic refresh disabled (interval <= 0)")
            return self

        self._thread = threading.Thread(target=self._loop, name="feed-refresh",
                                        daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s):
            try:
                self.refresh()
            except Exception:
                # A refresh must never kill the thread; the next interval
                # gets another attempt.
                log.exception("feed refresh raised")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def stats(self) -> dict:
        stats = self.cache.stats()
        stats["refreshes"] = self.refresh_count
        stats["failures"] = self.failure_count
        return stats
