"""Threat-intelligence feed layer for PRJ_112.

The manager reports feed state through a callback, so the feed sources and
cache stay independent of the database; only this module knows about both.
"""

import logging

from .base import FeedSnapshot, FeedSource, normalise_domain
from .cache import IndicatorCache, Match
from .first_seen import FirstSeenStore
from .manager import FeedManager
from .sources import (
    DEFAULT_FEED_URL,
    EXTRA_DEFAULT_FEEDS,
    HttpFeedSource,
    LocalFileSource,
    build_urlhaus_source,
)


def _feed_state_writer(db_path: str):
    """Persist each snapshot to feed_state on the refresh thread.

    The manager gets its own database connection rather than sharing the
    recorder's. Feed refreshes are hourly and happen off the query path, and
    a separate connection avoids two threads using one sqlite3 handle.
    """
    from datetime import datetime, timezone

    from storage.db import Database

    database = Database(db_path)

    def write(snapshot):
        database.upsert_feed_state(
            feed=snapshot.feed,
            last_fetch_ts=datetime.fromtimestamp(
                snapshot.fetched_at, tz=timezone.utc).isoformat(),
            entry_count=snapshot.entry_count,
            staleness_s=round(snapshot.age_s(), 1),
        )

    return write


def build_manager_from_settings(manager_settings) -> FeedManager:
    """Construct a FeedManager from Settings.

    A local file wins over the network when configured, because experiments
    must run against a pinned snapshot to be reproducible.
    """
    cache = IndicatorCache(
        match_parents=manager_settings.feed_match_parents,
        psl_mode=getattr(manager_settings, "psl_mode", "off"),
    )

    if manager_settings.feed_file:
        source = LocalFileSource(
            name=manager_settings.feed_name,
            path=manager_settings.feed_file,
            fmt=manager_settings.feed_format,
        )
    elif manager_settings.feed_auth_key:
        source = build_urlhaus_source(
            url=manager_settings.feed_url,
            auth_key=manager_settings.feed_auth_key,
            fmt=manager_settings.feed_format,
        )
    else:
        source = HttpFeedSource(
            name=manager_settings.feed_name,
            url=manager_settings.feed_url or DEFAULT_FEED_URL,
            fmt=manager_settings.feed_format,
        )

    sources = [source]
    # Unconfigured network use gets several independent feeds, because one
    # list rarely contains a given malicious domain. An explicit URL, file or
    # key means the operator chose a feed, so nothing is added to it.
    if (not manager_settings.feed_file and not manager_settings.feed_auth_key
            and not manager_settings.feed_url
            and manager_settings.feed_extra_defaults):
        sources += [HttpFeedSource(name=n, url=u, fmt=f)
                    for n, u, f in EXTRA_DEFAULT_FEEDS]

    on_snapshot = None
    if manager_settings.db_enabled and manager_settings.db_path:
        try:
            on_snapshot = _feed_state_writer(manager_settings.db_path)
        except Exception:
            # Persistence of feed state is useful, not essential; failing to
            # open it must not stop threat intelligence from loading.
            logging.getLogger("feeds").exception(
                "could not open the database for feed_state; continuing")

    return FeedManager(sources=sources, cache=cache,
                       interval_s=manager_settings.feed_refresh_s,
                       on_snapshot=on_snapshot)


__all__ = [
    "FeedSnapshot",
    "FeedSource",
    "normalise_domain",
    "IndicatorCache",
    "FirstSeenStore",
    "Match",
    "FeedManager",
    "LocalFileSource",
    "HttpFeedSource",
    "build_urlhaus_source",
    "build_manager_from_settings",
]
