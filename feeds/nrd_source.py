"""
Newly-registered-domain list source.

An NRD list is structurally just a list of domains, so it reuses the Stage 5
feed machinery rather than duplicating it. What differs is provenance: this
list asserts *registration* recency, which is a registry-derived fact, while
the first-seen store only asserts observation recency.

**No default URL, deliberately.** ICANN CZDS requires an approved account per
TLD and cannot be fetched anonymously. Public NRD mirrors exist but move: a
candidate URL checked during development returned HTTP 404, which is exactly
how an invented default fails — silently, later, in front of a panel. So the
source is unconfigured unless the operator supplies `DNSF_NRD_URL` or
`DNSF_NRD_FILE`, and the module falls back to observation age, saying so in
the evidence.

Status: a working public NRD list URL is NOT VERIFIED. CZDS access
requirements are VERIFIED from ICANN's published terms.
"""

from __future__ import annotations

import logging

from .cache import IndicatorCache
from .manager import FeedManager
from .sources import HttpFeedSource, LocalFileSource

log = logging.getLogger("feeds.nrd")


def build_nrd_source(settings):
    """Build the NRD list source, or None when unconfigured.

    A local file wins over the network, for the same reproducibility reason
    as the threat-intelligence feed: an experiment cannot be repeated against
    a list that changes daily.
    """
    if settings.nrd_file:
        return LocalFileSource(name="nrd-list", path=settings.nrd_file,
                               fmt=settings.nrd_format)
    if settings.nrd_url:
        return HttpFeedSource(name="nrd-list", url=settings.nrd_url,
                              fmt=settings.nrd_format,
                              auth_key=settings.nrd_auth_key or None)
    return None


def build_nrd_cache(settings) -> IndicatorCache | None:
    """Load the NRD list into a cache, or return None when unconfigured.

    Parent matching is off: registration recency belongs to one registrable
    domain and does not propagate to a parent. Inheriting it upward would
    mark long-established registrations as new.
    """
    source = build_nrd_source(settings)
    if source is None:
        log.info("no NRD list configured; the nrd module will use "
                 "observation age only (DNSF_NRD_URL or DNSF_NRD_FILE to set one)")
        return None

    cache = IndicatorCache(match_parents=False)
    manager = FeedManager([source], cache=cache,
                          interval_s=settings.nrd_refresh_s)
    manager.refresh()

    if not cache.ready:
        log.warning("NRD list configured but empty or unreachable; "
                    "falling back to observation age")
    return cache
