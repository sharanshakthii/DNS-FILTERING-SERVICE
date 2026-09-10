"""
Latency measurement (Stage 18).

Answers RQ2 — what each detection signal costs, and what the full fusion
costs — using the timing the system already collects. Nothing here adds
instrumentation: `proxy/timing.Stopwatch` has recorded `parse`, `decide`,
`modules`, `aggregate`, `enforce` and `upstream` since Stage 3, and
`ModuleResult.latency_ms` has recorded per-module time since Stage 4. This
module collects those numbers and reports their shape.

## Why distributions and not means

A mean hides the tail, and the tail is where a filtering resolver is felt.
One query in a hundred taking 40 ms is a visible stall; a 0.4 ms mean
conceals it completely. So every figure is reported as p50/p90/p99 with the
count, and the mean is included only alongside them.

## Why warm-up is discarded

The DGA artifact is loaded lazily on first use, feeds parse once, and
CPython's first pass through a code path is slower than its later ones.
Counting those one-off costs as steady state would overstate the price of
every module that has any setup at all.

## What these numbers are, and are not

Unlike detection accuracy, a timing measurement does not depend on the labels
being right — the clock is the clock. That makes these the most defensible
figures the project has.

They are still measurements of **one machine**, and Mode B runs against a
loopback stub rather than a real resolver, so upstream time is unnaturally
small and stable. Absolute milliseconds are hardware-specific. The portable
results are the *comparisons*: per-module ranking, and added latency as a
fraction of a real resolution.
"""

from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass, field

#: Phases the proxy times, in the order a query passes through them.
#: `enforce` appears only on a blocked query; `upstream` only on one that was
#: forwarded. Their absence is itself a measurement.
PHASES = ("parse", "decide", "modules", "aggregate", "enforce", "upstream",
          "total")

DEFAULT_WARMUP = 20
DEFAULT_REPEATS = 3


@dataclass
class Distribution:
    """The shape of one set of timings, in milliseconds."""

    label: str
    samples: list[float] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.samples)

    def _quantile(self, fraction: float) -> float | None:
        """Nearest-rank percentile.

        Chosen over interpolation because every reported value is then a
        measurement that actually occurred, not an average of two that did.
        For small samples that matters: an interpolated p99 of four
        observations is a number nothing produced.
        """
        if not self.samples:
            return None
        ordered = sorted(self.samples)
        # rank = ceil(fraction x N), 1-based. Rounding instead of ceiling
        # shifts the answer up by one place at the top of the range: for
        # 1..100 it returned 100 as the p99, which is the maximum, not the
        # 99th percentile.
        rank = max(1, min(len(ordered), math.ceil(fraction * len(ordered))))
        return ordered[rank - 1]

    @property
    def p50(self) -> float | None:
        return self._quantile(0.50)

    @property
    def p90(self) -> float | None:
        return self._quantile(0.90)

    @property
    def p99(self) -> float | None:
        return self._quantile(0.99)

    def as_dict(self) -> dict:
        if not self.samples:
            return {"label": self.label, "count": 0, "min": None, "p50": None,
                    "p90": None, "p99": None, "max": None, "mean": None,
                    "stdev": None}

        def rounded(value):
            return round(value, 4) if value is not None else None

        return {
            "label": self.label,
            "count": self.count,
            "min": rounded(min(self.samples)),
            "p50": rounded(self.p50),
            "p90": rounded(self.p90),
            "p99": rounded(self.p99),
            "max": rounded(max(self.samples)),
            "mean": rounded(statistics.fmean(self.samples)),
            "stdev": rounded(statistics.pstdev(self.samples))
            if self.count > 1 else 0.0,
        }


def discard_warmup(samples: list[float], warmup: int = DEFAULT_WARMUP
                   ) -> list[float]:
    """Drop the first `warmup` observations.

    If that would leave nothing, the samples are returned untouched and the
    caller reports the count: a run too short to warm up is better shown as a
    small sample than as an empty one.
    """
    if warmup <= 0 or len(samples) <= warmup:
        return list(samples)
    return list(samples[warmup:])


def collect(rows: list[dict], key: str) -> list[float]:
    """Pull one numeric field out of a list of timing records, skipping gaps.

    A missing key is not zero. `upstream` is absent on a blocked query and
    `enforce` on a forwarded one, and treating either as 0.0 would invent a
    measurement of a phase that never ran.
    """
    out = []
    for row in rows:
        value = row.get(key)
        if value is None:
            continue
        try:
            out.append(float(value))
        except (TypeError, ValueError):
            continue
    return out


def summarise_phases(records: list[dict], warmup: int = DEFAULT_WARMUP
                     ) -> dict[str, dict]:
    """Distribution per timing phase across a set of query records."""
    summary = {}
    for phase in PHASES:
        samples = discard_warmup(collect(records, phase), warmup)
        summary[phase] = Distribution(phase, samples).as_dict()
    return summary


def added_latency(records: list[dict], warmup: int = DEFAULT_WARMUP) -> dict:
    """Total minus upstream: the cost the filtering path adds.

    The field the project has recorded since Stage 3 for exactly this
    question. Computed here from `total` and `upstream` so the same helper
    works on engine-only records, which have no upstream phase at all.
    """
    values = []
    for row in records:
        total = row.get("total")
        if total is None:
            continue
        values.append(float(total) - float(row.get("upstream") or 0.0))
    return Distribution("added", discard_warmup(values, warmup)).as_dict()


# -- Mode A: engine only, no sockets --------------------------------------

def time_engine(engine, contexts, repeats: int = DEFAULT_REPEATS,
                warmup: int = DEFAULT_WARMUP) -> dict:
    """Time module dispatch and aggregation over `contexts`.

    Deterministic and offline: no packet is parsed, no network connection is
    opened, no upstream is contacted, and no database is touched. Isolates
    what detection costs from what the network costs.

    The wording above deliberately avoids the API names a test scans this
    function's source for. That check is what enforces the guarantee, and
    prose describing the guarantee should not be what breaks it.

    Returns per-run records so between-run spread is visible — a difference
    between configurations that is smaller than the spread between repeats of
    the same configuration is noise, and the report should show that.
    """
    per_run: list[dict] = []
    module_samples: dict[str, list[float]] = {}
    records: list[dict] = []

    for run in range(repeats):
        run_records: list[dict] = []
        for context in contexts:
            started = time.perf_counter()
            results = engine.evaluate(context)
            modules_ms = (time.perf_counter() - started) * 1000.0

            started = time.perf_counter()
            engine.aggregator.aggregate(results)
            aggregate_ms = (time.perf_counter() - started) * 1000.0

            for result in results:
                module_samples.setdefault(result.module, []).append(
                    result.latency_ms)

            run_records.append({
                "modules": modules_ms,
                "aggregate": aggregate_ms,
                "total": modules_ms + aggregate_ms,
            })

        records.extend(run_records)
        per_run.append({
            "run": run,
            "queries": len(run_records),
            **{phase: Distribution(
                phase, discard_warmup(collect(run_records, phase), warmup)
            ).as_dict() for phase in ("modules", "aggregate", "total")},
        })

    return {
        "phases": summarise_phases(records, warmup),
        "per_module": {
            name: Distribution(name, discard_warmup(samples, warmup)).as_dict()
            for name, samples in sorted(module_samples.items())
        },
        "per_run": per_run,
        "queries_timed": len(records),
        "warmup_discarded": min(warmup, len(records)),
    }
