"""
DNS beaconing / periodicity module.

The fifth signal, and the only behavioural one. The other four judge a name:
is it listed, is it young, does it resemble a brand, does it look generated.
This one judges a *pattern* — whether a domain is being queried on a clock.
Malware that checks in with a controller does that; so does a software
updater, and so does an NTP-adjacent library. The distinction is not
available from timing alone.

**Periodic DNS traffic is not malicious.** The score here is a *periodicity
signal*, nothing more. Every piece of evidence this module emits says so, and
the report must keep that wording. A high score is a reason to look, not a
finding.

The technique is standard — regularity of inter-arrival times is what
open-source beacon analysers such as RITA use, and Shalaginov et al. (2016)
applied periodicity detection to DNS logs using the STNR algorithm of Rasheed
and Alhajj (Applied Intelligence, 2010). Nothing here is novel.

## The score

Three bounded factors, multiplied. Each is between 0 and 1, so the product is
too, and each can be read on its own in the evidence.

    regularity  = 1 / (1 + CV)          CV = stdev(intervals) / mean(interval)

        Perfectly even intervals give CV 0 and regularity 1. As the spread
        grows the score falls smoothly, with no threshold to argue about.

    confidence  = min(1, intervals / evidence_intervals)

        Four evenly spaced queries are weak evidence of a clock; twenty are
        strong. Ramps linearly to full confidence at `evidence_intervals`.

    burst_factor = min(1, mean_interval / min_interval_s)

        Guards the case regularity alone gets wrong: fifty queries fired in
        two seconds are extremely "regular" and are not a beacon. Below
        `min_interval_s` the factor scales the score down towards zero.

    score = regularity x confidence x burst_factor

`evidence_intervals` and `min_interval_s` are **engineering conventions, not
derived optima** — like the aggregator weights, they are tuned in Stage 16
and are untuned today. Both are configurable.
"""

from __future__ import annotations

import statistics
import time

from .base import (
    DetectionModule,
    ModuleScore,
    ModuleUnavailable,
    QueryContext,
)

DEFAULT_WINDOW_S = 3600.0        # one hour
DEFAULT_MIN_OBSERVATIONS = 4     # three intervals: the fewest worth measuring
DEFAULT_EVIDENCE_INTERVALS = 8
DEFAULT_MIN_INTERVAL_S = 5.0


class InsufficientObservations(ModuleUnavailable):
    """Not enough history to judge periodicity.

    Raised rather than returning 0.0, and the distinction matters more here
    than anywhere else in the project. Zero would mean "observed this domain
    and its timing is irregular" — a real finding. Silence about a domain
    seen twice is not that finding, and averaging it in as a confident zero
    would drag down the aggregate on every rarely-seen domain in the network.

    The engine records this as status=error and excludes the module, which is
    the project's existing "no usable score" path: the aggregate is computed
    from the other modules rather than diluted by this one. The status word
    "error" is a poor fit for an ordinary condition and is noted as such in
    the README.
    """


class BeaconingModule(DetectionModule):
    """Scores how regularly a domain has been queried in the recent past."""

    name = "beaconing"

    def __init__(self, history=None, window_s: float = DEFAULT_WINDOW_S,
                 min_observations: int = DEFAULT_MIN_OBSERVATIONS,
                 evidence_intervals: int = DEFAULT_EVIDENCE_INTERVALS,
                 min_interval_s: float = DEFAULT_MIN_INTERVAL_S,
                 per_client: bool = False) -> None:
        """`history` is any object with an `observations()` method.

        Injected rather than constructed, so the module is testable against a
        list of timestamps and so `engine/` does not import `storage/` except
        through `from_settings`.
        """
        if window_s <= 0:
            raise ValueError(f"window_s must be positive, got {window_s}")
        if min_observations < 2:
            raise ValueError(
                f"min_observations must be at least 2 — one observation "
                f"yields no interval — got {min_observations}")
        if evidence_intervals < 1:
            raise ValueError(
                f"evidence_intervals must be at least 1, got {evidence_intervals}")
        if min_interval_s <= 0:
            raise ValueError(
                f"min_interval_s must be positive, got {min_interval_s}")

        self.history = history
        self.window_s = window_s
        self.min_observations = min_observations
        self.evidence_intervals = evidence_intervals
        self.min_interval_s = min_interval_s
        self.per_client = per_client

    @classmethod
    def from_settings(cls, settings) -> "BeaconingModule":
        from storage.history import ObservationStore

        return cls(
            history=ObservationStore(settings.db_path),
            window_s=settings.beacon_window_s,
            min_observations=settings.beacon_min_observations,
            evidence_intervals=settings.beacon_evidence_intervals,
            min_interval_s=settings.beacon_min_interval_s,
            per_client=settings.beacon_per_client,
        )

    # -- the arithmetic ----------------------------------------------------

    @staticmethod
    def intervals(timestamps: list[float]) -> list[float]:
        """Gaps between consecutive observations, in seconds.

        Identical timestamps produce zero-length gaps, which are kept: two
        queries in the same instant are a real observation about the traffic,
        and dropping them would make a burst look evenly spaced.
        """
        ordered = sorted(timestamps)
        return [b - a for a, b in zip(ordered, ordered[1:])]

    def regularity(self, gaps: list[float]) -> tuple[float, float]:
        """(regularity, coefficient of variation) for a list of gaps."""
        if len(gaps) < 2:
            return 0.0, 0.0
        mean = statistics.fmean(gaps)
        if mean <= 0:
            # Every observation at the same instant: no rhythm to measure.
            return 0.0, 0.0
        cv = statistics.pstdev(gaps) / mean
        return 1.0 / (1.0 + cv), cv

    def confidence(self, interval_count: int) -> float:
        return min(1.0, interval_count / self.evidence_intervals)

    def burst_factor(self, mean_interval: float) -> float:
        if mean_interval <= 0:
            return 0.0
        return min(1.0, mean_interval / self.min_interval_s)

    # -- evaluation --------------------------------------------------------

    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        if self.history is None:
            raise InsufficientObservations(
                "no observation history is configured for this module")

        qname = (ctx.qname or "").strip().lower().rstrip(".")
        now = ctx.timestamp or time.time()
        since = now - self.window_s

        client = ctx.client_id if self.per_client else None
        timestamps, discarded = self.history.observations(
            qname, since, client_hash=client)

        # Defensive: a store could return values outside the window.
        timestamps = sorted(t for t in timestamps if since <= t <= now)

        base = {
            "qname": qname,
            "window_s": self.window_s,
            "observations": len(timestamps),
            "min_observations": self.min_observations,
            "scope": "client+domain" if self.per_client else "domain",
            "unparseable_rows": discarded,
        }

        if len(timestamps) < self.min_observations:
            raise InsufficientObservations(
                f"{len(timestamps)} observation(s) of {qname!r} in the last "
                f"{int(self.window_s)}s; {self.min_observations} are needed "
                f"before periodicity can be judged")

        gaps = self.intervals(timestamps)
        regularity, cv = self.regularity(gaps)
        mean_interval = statistics.fmean(gaps) if gaps else 0.0
        confidence = self.confidence(len(gaps))
        burst = self.burst_factor(mean_interval)

        score = round(min(1.0, max(0.0, regularity * confidence * burst)), 6)
        span = timestamps[-1] - timestamps[0]

        if score >= 0.7:
            strength = "strong periodicity signal"
        elif score >= 0.4:
            strength = "moderate periodicity signal"
        else:
            strength = "weak periodicity signal"

        return ModuleScore(score=score, features={
            **base,
            "intervals": len(gaps),
            "mean_interval_s": round(mean_interval, 3),
            "median_interval_s": round(statistics.median(gaps), 3),
            "stdev_interval_s": round(statistics.pstdev(gaps), 3),
            "min_interval_s_observed": round(min(gaps), 3),
            "max_interval_s_observed": round(max(gaps), 3),
            "coefficient_of_variation": round(cv, 4),
            "regularity": round(regularity, 4),
            "confidence": round(confidence, 4),
            "burst_factor": round(burst, 4),
            "span_s": round(span, 3),
            "window_coverage": round(min(1.0, span / self.window_s), 4),
            "reason": (
                f"{len(timestamps)} observations in the last "
                f"{int(self.window_s)}s, median interval "
                f"{statistics.median(gaps):.1f}s, coefficient of variation "
                f"{cv:.3f}: {strength}. Periodic DNS traffic is not by itself "
                f"evidence of malware — legitimate software also polls on a "
                f"schedule."),
        })
