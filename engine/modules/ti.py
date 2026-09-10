"""
Threat-intelligence module.

The first real signal. It answers one question: is this domain, or a parent
of it, on a threat-intelligence feed?

This module alone is roughly what Quad9 and Pi-hole do, and it is not the
project's contribution. Its purpose here is to be the **TI-only baseline
arm** of the Stage 16 ablation. The contribution is what the comparison
between this arm, the ML arm, and their combination shows — together with
the evidence trace this module produces, which a blocklist resolver does not
expose.
"""

from __future__ import annotations

from feeds.cache import IndicatorCache

from .base import (
    DetectionModule,
    ModuleScore,
    ModuleUnavailable,
    QueryContext,
)


class FeedUnavailable(ModuleUnavailable):
    """No feed has loaded, so this module has no opinion.

    Raised rather than returning 0.0. Zero means "checked, not listed"; an
    empty cache means "could not check". The engine records the difference as
    status=error and excludes it from aggregation, which keeps a feed outage
    from silently looking like a clean verdict on every query.
    """


class ThreatIntelModule(DetectionModule):
    """Scores 1.0 when the queried name matches a feed indicator."""

    name = "ti"

    def __init__(self, cache: IndicatorCache, stale_after_s: float = 86400.0,
                 parent_score: float = 1.0) -> None:
        """`parent_score` is separate from the exact-match score on purpose.

        An exact hit is the feed's own assertion. A parent hit is our
        inference that a subdomain inherits its parent's reputation, and that
        inference is where blocklist collateral damage comes from. Keeping it
        configurable means the ablation can measure what parent matching
        costs in false positives instead of assuming it is free.
        """
        self.cache = cache
        self.stale_after_s = stale_after_s
        self.parent_score = parent_score

    @classmethod
    def from_settings(cls, settings) -> "ThreatIntelModule":
        """Built by `build_engine` when 'ti' appears in DNSF_ENGINE_MODULES."""
        from feeds import build_manager_from_settings

        manager = build_manager_from_settings(settings)
        manager.start(refresh_now=True)
        module = cls(manager.cache,
                     stale_after_s=settings.feed_stale_after_s,
                     parent_score=settings.feed_parent_score)
        module._manager = manager
        return module

    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        if not self.cache.ready:
            raise FeedUnavailable(
                "no threat-intelligence feed has loaded; cannot assess")

        staleness = self.cache.staleness_s()
        base = {
            "indicators": self.cache.size,
            "feed_age_s": round(staleness, 1) if staleness is not None else None,
            "stale": bool(staleness is not None and staleness > self.stale_after_s),
        }

        match = self.cache.lookup(ctx.qname)
        if match is None:
            return ModuleScore(score=0.0, features={**base, "listed": False})

        score = 1.0 if match.match_type == "exact" else self.parent_score
        return ModuleScore(
            score=score,
            features={
                **base,
                "listed": True,
                "indicator": match.indicator,
                "feed": match.feed,
                "match_type": match.match_type,
            },
        )

    def close(self) -> None:
        manager = getattr(self, "_manager", None)
        if manager is not None:
            manager.stop()
