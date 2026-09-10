"""
Offline evaluation harness.

Replays a labelled CSV through the **real** `DecisionEngine` and
`RiskAggregator` — the same classes the DNS proxy runs, constructed the same
way. Nothing here reimplements scoring or aggregation, so a result measured
by this harness is a result the resolver would have produced for the same
inputs.

No sockets, no database, no network. Module state that would come from a
feed, a first-seen store or query history is built from the dataset's own
columns, so each module sees exactly the inputs the dataset declares rather
than something the harness invented at run time.

**Production is untouched.** Every configuration builds its own engine and
its own aggregator; nothing global is mutated, no weight or threshold in
`config/` or `engine/` is changed.
"""

from __future__ import annotations

import csv
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from engine.aggregator import RiskAggregator
from engine.decision import DecisionEngine
from engine.modules.base import STATUS_OK, ModuleResult, QueryContext
from engine.modules.beaconing import BeaconingModule
from engine.modules.dga import DGAModule
from engine.modules.nrd import NewDomainModule
from engine.modules.ti import ThreatIntelModule
from engine.modules.typosquat import TyposquatModule
from feeds.base import FeedSnapshot
from feeds.cache import IndicatorCache
from feeds.first_seen import FirstSeenStore

REPO_ROOT = Path(__file__).resolve().parent.parent

ALL_MODULES = ("ti", "nrd", "typosquat", "dga", "beaconing")

#: Verdicts counted as "the system acted on this". Deliberately the system's
#: own decision rule rather than a threshold invented for the report.
POSITIVE_VERDICTS = frozenset({"FLAG", "BLOCK"})

#: Brands and keywords the typosquat module is configured with. These match
#: the generator in tools/make_eval_dataset.py; they are fictional company
#: names so no real brand is implicated by a synthetic fixture.
EVAL_BRANDS = ["examplebrand", "acmeshop", "northwind", "contoso"]

#: Observation offsets, in seconds before "now", for each pattern the dataset
#: can declare. Fixed, so a run is reproducible.
PATTERNS: dict[str, list[float]] = {
    "none": [],
    "sparse": [0, 640],
    "periodic": [i * 300 for i in range(12)],
    "jittered": [0, 297, 604, 901, 1198, 1503, 1797, 2104, 2399, 2702,
                 2998, 3301],
    "irregular": [0, 41, 723, 911, 1204, 1207, 1966, 2011, 2890, 3402],
}


@dataclass
class Row:
    domain: str
    label: int
    category: str
    ti_listed: bool
    first_seen_age_s: float
    observation_pattern: str


@dataclass
class RowResult:
    """What one configuration decided about one row."""

    domain: str
    label: int
    category: str
    verdict: str
    score: float
    predicted: int
    module_scores: dict = field(default_factory=dict)
    module_statuses: dict = field(default_factory=dict)


def dataset_checksum(path: Path) -> str:
    """SHA-256 of the dataset, recorded so results can be tied to their input."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_rows(path: Path) -> list[Row]:
    """Read and validate the evaluation CSV, rejecting bad rows loudly."""
    if not path.exists():
        raise SystemExit(
            f"dataset not found: {path}\n"
            f"Generate it with: python tools/make_eval_dataset.py")

    rows: list[Row] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"domain", "label", "category", "ti_listed",
                    "first_seen_age_s", "observation_pattern"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise SystemExit(f"{path}: missing columns {sorted(missing)}")

        for number, raw in enumerate(reader, start=2):
            label = (raw["label"] or "").strip()
            if label not in {"0", "1"}:
                raise SystemExit(f"{path}:{number}: label must be 0 or 1")
            pattern = (raw["observation_pattern"] or "none").strip()
            if pattern not in PATTERNS:
                raise SystemExit(
                    f"{path}:{number}: unknown pattern {pattern!r}; "
                    f"expected one of {sorted(PATTERNS)}")
            rows.append(Row(
                domain=raw["domain"].strip().lower(),
                label=int(label),
                category=(raw["category"] or "").strip(),
                ti_listed=(raw["ti_listed"] or "0").strip() == "1",
                first_seen_age_s=float(raw["first_seen_age_s"] or 0),
                observation_pattern=pattern,
            ))

    if not rows:
        raise SystemExit(f"{path} contains no rows")
    if len({r.label for r in rows}) < 2:
        raise SystemExit(f"{path} contains only one class")
    return rows


class FixtureHistory:
    """Query history assembled from each row's declared pattern.

    Satisfies the same interface as `storage.history.ObservationStore`, so
    the real `BeaconingModule` runs unmodified against it.
    """

    def __init__(self, rows: list[Row], now: float) -> None:
        self.now = now
        self._by_domain = {
            row.domain: sorted(now - offset
                               for offset in PATTERNS[row.observation_pattern])
            for row in rows
        }

    def observations(self, qname: str, since: float, *, client_hash=None,
                     limit: int = 5000):
        stamps = self._by_domain.get((qname or "").strip().lower(), [])
        return [t for t in stamps if t >= since], 0


class Harness:
    """Runs configured engines over a labelled dataset."""

    def __init__(self, rows: list[Row], model_path: str | None = None,
                 now: float | None = None) -> None:
        self.rows = rows
        self.now = now if now is not None else time.time()
        self.model_path = model_path or str(
            REPO_ROOT / "models" / "dga" / "dga_model.json")

        # Feed contents come from the dataset's own column, not from the
        # labels, so a row can be malicious without being listed.
        listed = {row.domain for row in self.rows if row.ti_listed}
        self._ti_cache = IndicatorCache()
        self._ti_cache.apply(FeedSnapshot(feed="eval-fixture", domains=listed))

        # Observing since long before the oldest row, so the newly-registered
        # module is never merely warming up.
        oldest = max((r.first_seen_age_s for r in self.rows), default=0.0)
        self._first_seen = FirstSeenStore(started_at=self.now - oldest - 86_400,
                                          max_entries=len(self.rows) * 4 + 100)
        for row in self.rows:
            self._first_seen.observe(NewDomainModule._registrable(row.domain),
                                     now=self.now - row.first_seen_age_s)

        self._history = FixtureHistory(self.rows, self.now)

    def build_engine(self, modules: tuple[str, ...],
                     aggregator: RiskAggregator | None = None) -> DecisionEngine:
        """A fresh engine containing exactly `modules`, in canonical order."""
        unknown = set(modules) - set(ALL_MODULES)
        if unknown:
            raise ValueError(f"unknown module(s): {sorted(unknown)}")

        builders = {
            "ti": lambda: ThreatIntelModule(self._ti_cache),
            "nrd": lambda: NewDomainModule(first_seen=self._first_seen),
            "typosquat": lambda: TyposquatModule(brands=EVAL_BRANDS),
            "dga": lambda: DGAModule(model_path=self.model_path),
            "beaconing": lambda: BeaconingModule(history=self._history),
        }
        selected = [builders[name]() for name in ALL_MODULES
                    if name in modules]
        return DecisionEngine(selected,
                              aggregator=aggregator or RiskAggregator())

    def run(self, modules: tuple[str, ...],
            aggregator: RiskAggregator | None = None) -> list[RowResult]:
        """Evaluate every row with the given configuration."""
        engine = self.build_engine(modules, aggregator)
        results: list[RowResult] = []

        for row in self.rows:
            context = QueryContext(qname=row.domain, qtype="A",
                                   client_id="eval", timestamp=self.now)
            module_results: list[ModuleResult] = engine.evaluate(context)
            decision = engine.aggregator.aggregate(module_results)

            results.append(RowResult(
                domain=row.domain,
                label=row.label,
                category=row.category,
                verdict=decision["verdict"],
                score=decision["score"],
                predicted=1 if decision["verdict"] in POSITIVE_VERDICTS else 0,
                # Only modules that actually produced a usable score are
                # recorded here. An unavailable module is absent rather than
                # present with a zero, exactly as in production.
                module_scores={r.module: r.score for r in module_results
                               if r.status == STATUS_OK},
                module_statuses={r.module: r.status for r in module_results},
            ))

        return results


def status_counts(results: list[RowResult]) -> dict:
    """How often each module was usable, so a null result is explicable.

    A configuration scoring zero recall because its model file is missing
    looks identical to one scoring zero because it detects nothing. This
    tells them apart.
    """
    counts: dict[str, dict[str, int]] = {}
    for result in results:
        for module, status in result.module_statuses.items():
            counts.setdefault(module, {})
            counts[module][status] = counts[module].get(status, 0) + 1
    return counts
