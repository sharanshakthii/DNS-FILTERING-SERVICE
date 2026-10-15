"""
Newly registered / newly observed domain module.

Why this signal exists: Bilge et al. (EXPOSURE, NDSS 2011) found that most
domains their system detected as malicious were active for under two days.
Antonakakis et al. (Kopis, USENIX Security 2011) built on the same
observation that malicious infrastructure is short-lived. Domain age is
therefore a genuine discriminator, and it is one that threat-intelligence
feeds structurally cannot provide: a feed lists a domain only after somebody
has reported it, which is exactly the window in which a brand-new domain does
its damage.

That gap is the reason this module is the second arm of the Stage 16
ablation. TI answers "has anyone seen this be bad?"; age answers "has this
existed long enough for anyone to have found out?".

**Precision of claim.** With no external source configured, the age this
module reports is *observation* age at this resolver, not registration age.
Those are different quantities and `age_source` in the evidence says which
one produced the score. Calling observation age "registration age" in the
report would be a false claim, and this module is written so the database
cannot be misread that way.
"""

from __future__ import annotations

from feeds.cache import IndicatorCache
from feeds.first_seen import FirstSeenStore

from .base import DetectionModule, ModuleScore, QueryContext

#: Age at or below which a domain scores 1.0. Seven days is the window
#: EXPOSURE's short-lifetime finding and current vendor NRD categories both
#: sit inside; it is a configurable starting point, not a derived optimum,
#: and Stage 16 is where it gets tuned against measured false positives.
DEFAULT_NEW_WITHIN_S = 7 * 24 * 3600.0

#: Age at or above which a domain scores 0.0, with linear decay between.
DEFAULT_ESTABLISHED_AFTER_S = 30 * 24 * 3600.0


class NewDomainModule(DetectionModule):
    """Scores a domain by how new it is."""

    name = "nrd"

    def __init__(self, first_seen: FirstSeenStore | None = None,
                 nrd_list: IndicatorCache | None = None,
                 new_within_s: float = DEFAULT_NEW_WITHIN_S,
                 established_after_s: float = DEFAULT_ESTABLISHED_AFTER_S,
                 list_score: float = 1.0,
                 psl_mode: str = "off") -> None:
        if established_after_s <= new_within_s:
            raise ValueError(
                "established_after_s must exceed new_within_s; otherwise the "
                "decay band is empty and the score is a step function")
        self.first_seen = first_seen or FirstSeenStore()
        self.nrd_list = nrd_list
        self.new_within_s = new_within_s
        self.established_after_s = established_after_s
        self.list_score = list_score
        from feeds.psl import check_mode
        self.psl_mode = check_mode(psl_mode)

    @classmethod
    def from_settings(cls, settings) -> "NewDomainModule":
        from feeds.nrd_source import build_nrd_cache

        return cls(
            first_seen=FirstSeenStore(max_entries=settings.nrd_max_tracked),
            nrd_list=build_nrd_cache(settings),
            new_within_s=settings.nrd_new_within_s,
            established_after_s=settings.nrd_established_after_s,
            psl_mode=getattr(settings, "psl_mode", "off"),
        )

    # -- scoring -----------------------------------------------------------

    def score_for_age(self, age_s: float) -> float:
        """1.0 when new, 0.0 when established, linear in between.

        Linear rather than a cliff edge because a domain one second past the
        threshold is not meaningfully different from one a second before it,
        and a step function would put a large population of ordinary domains
        immediately either side of a hard boundary.
        """
        if age_s <= self.new_within_s:
            return 1.0
        if age_s >= self.established_after_s:
            return 0.0
        span = self.established_after_s - self.new_within_s
        return round(1.0 - (age_s - self.new_within_s) / span, 6)

    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        now = ctx.timestamp
        registrable = self._site(ctx.qname)

        # An external list, when configured, is a registry-derived fact and
        # outranks our own observation.
        if self.nrd_list is not None and self.nrd_list.ready:
            match = self.nrd_list.lookup(registrable)
            if match is not None:
                return ModuleScore(
                    score=self.list_score,
                    features={
                        "age_source": "nrd_list",
                        "listed_as_new": True,
                        "indicator": match.indicator,
                        "feed": match.feed,
                        "registrable": registrable,
                    },
                )

        age_s, first_time = self._observe(registrable, now)
        window_s = self.first_seen.window_s(now)

        base = {
            "age_source": "first_seen",
            "registrable": registrable,
            "observed_age_s": round(age_s, 1),
            "observation_window_s": round(window_s, 1),
            "first_observation": first_time,
            "tracked_domains": self.first_seen.size,
        }

        # A cold resolver has seen nothing, so everything looks new. Refusing
        # to judge until the observation window covers the threshold is the
        # difference between a signal and a machine that flags the entire
        # internet on its first morning.
        if window_s < self.new_within_s:
            return ModuleScore(
                score=0.0,
                features={**base, "warming_up": True,
                          "warmup_remaining_s": round(
                              self.new_within_s - window_s, 1)},
            )

        return ModuleScore(score=self.score_for_age(age_s),
                           features={**base, "warming_up": False})

    # -- helpers -----------------------------------------------------------

    def _observe(self, domain: str, now: float) -> tuple[float, bool]:
        first_seen_ts, is_first = self.first_seen.observe(domain, now=now)
        return now - first_seen_ts, is_first

    def _site(self, qname: str) -> str:
        """`_registrable` when the PSL is off; the PSL site otherwise.

        With the PSL on, each customer of a shared platform is its own site,
        so `new.pages.dev` is new even though `pages.dev` is not.
        """
        if self.psl_mode == "off":
            return self._registrable(qname)
        from feeds.psl import site_for
        return site_for(qname, self.psl_mode)

    @staticmethod
    def _registrable(qname: str) -> str:
        """Reduce a qname to its last two labels.

        Age is a property of a registration, not of a hostname: `mail.x.com`
        and `www.x.com` share one registration date, and tracking them
        separately would report a five-year-old domain as new the first time
        a new subdomain appeared.

        This is the same public-suffix approximation used by the TI module's
        parent matching, with the same limitation: for a name under a
        multi-label public suffix such as `co.uk`, the last two labels are the
        suffix itself rather than the registration. Documented, not solved.
        """
        labels = (qname or "").strip().lower().rstrip(".").split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else (qname or "")
