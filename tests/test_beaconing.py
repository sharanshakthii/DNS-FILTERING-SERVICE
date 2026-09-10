"""Stage 14 tests: DNS beaconing / periodicity.

Two things carry most of the weight here. First, that thin evidence is never
reported as a confident finding — a domain seen twice must not be scored 0.0
as though its timing had been judged and found irregular. Second, that the
arithmetic cannot divide by zero or blow up on the degenerate cases real
history contains: identical timestamps, bursts, single observations,
unparseable rows.

All timestamps are synthetic. Nothing here waits on the clock.
"""

import statistics
import time

import pytest

from config.settings import Settings
from engine.decision import DecisionEngine
from engine.modules import REGISTRY
from engine.modules.base import (
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    QueryContext,
)
from engine.modules.beaconing import (
    DEFAULT_MIN_OBSERVATIONS,
    DEFAULT_WINDOW_S,
    BeaconingModule,
    InsufficientObservations,
)
from engine.modules.null import FixedScoreModule
from proxy.dns_proxy import build_engine
from storage.db import Database
from storage.history import HistoryUnavailable, ObservationStore, parse_timestamp
from storage.models import QueryRecord

NOW = 2_000_000.0

# -- deterministic temporal fixtures, as offsets before NOW ----------------
PERIODIC = [1200, 900, 600, 300, 0]                 # exactly 300s apart
JITTERED = [1200, 903, 596, 299, 2]                 # 297-307s apart
IRREGULAR = [2017, 1911, 723, 41, 0]
BURST = [round(i * 0.2, 1) for i in range(12)]      # 12 queries in ~2s
LONG_PERIODIC = [i * 300 for i in range(12)]        # 12 check-ins


class FakeHistory:
    """Stands in for the database, so the module is testable on timestamps."""

    def __init__(self, offsets, discarded: int = 0, per_domain=None) -> None:
        self.timestamps = sorted(NOW - offset for offset in (offsets or []))
        self.discarded = discarded
        self.per_domain = per_domain or {}
        self.calls: list[tuple] = []

    def observations(self, qname, since, client_hash=None):
        self.calls.append((qname, since, client_hash))
        if qname in self.per_domain:
            stamps = sorted(NOW - o for o in self.per_domain[qname])
        else:
            stamps = self.timestamps
        return [t for t in stamps if t >= since], self.discarded


def ctx(qname="beacon.test", timestamp=NOW, client_id="cid") -> QueryContext:
    return QueryContext(qname=qname, qtype="A", client_id=client_id,
                        timestamp=timestamp)


def module(offsets=None, **kwargs) -> BeaconingModule:
    kwargs.setdefault("history", FakeHistory(offsets))
    return BeaconingModule(**kwargs)


# =========================================================================
# Temporal arithmetic
# =========================================================================

def test_intervals_are_the_gaps_between_observations():
    assert BeaconingModule.intervals([0, 300, 600, 900]) == [300, 300, 300]


def test_intervals_sort_before_measuring():
    """History arriving out of order must not invent negative gaps."""
    assert BeaconingModule.intervals([900, 0, 600, 300]) == [300, 300, 300]


def test_one_observation_yields_no_intervals():
    assert BeaconingModule.intervals([42]) == []
    assert BeaconingModule.intervals([]) == []


def test_identical_timestamps_yield_zero_gaps():
    """Kept, not dropped: discarding them would make a burst look even."""
    assert BeaconingModule.intervals([100, 100, 100]) == [0, 0]


def test_mean_median_and_stdev_of_a_regular_series():
    gaps = BeaconingModule.intervals([NOW - o for o in PERIODIC])
    assert statistics.fmean(gaps) == 300
    assert statistics.median(gaps) == 300
    assert statistics.pstdev(gaps) == 0


def test_regularity_is_one_for_perfectly_even_gaps():
    regularity, cv = module().regularity([300, 300, 300, 300])
    assert cv == 0.0
    assert regularity == 1.0


def test_regularity_falls_as_variation_grows():
    even, _ = module().regularity([300, 300, 300])
    slight, _ = module().regularity([300, 305, 295])
    wild, _ = module().regularity([10, 900, 60, 1800])
    assert even > slight > wild


def test_the_coefficient_of_variation_is_stdev_over_mean():
    gaps = [100, 200, 300]
    _regularity, cv = module().regularity(gaps)
    assert cv == pytest.approx(statistics.pstdev(gaps) / statistics.fmean(gaps))


def test_a_mean_gap_of_zero_does_not_divide_by_zero():
    """Every observation at the same instant: no rhythm exists to measure."""
    regularity, cv = module().regularity([0, 0, 0])
    assert (regularity, cv) == (0.0, 0.0)


def test_fewer_than_two_gaps_gives_no_regularity():
    assert module().regularity([300]) == (0.0, 0.0)
    assert module().regularity([]) == (0.0, 0.0)


def test_confidence_ramps_with_the_number_of_intervals():
    built = module(evidence_intervals=8)
    assert built.confidence(0) == 0.0
    assert built.confidence(4) == 0.5
    assert built.confidence(8) == 1.0
    assert built.confidence(50) == 1.0     # capped


def test_the_burst_factor_suppresses_impossibly_short_intervals():
    built = module(min_interval_s=5.0)
    assert built.burst_factor(0.0) == 0.0
    assert built.burst_factor(1.0) == 0.2
    assert built.burst_factor(5.0) == 1.0
    assert built.burst_factor(3600.0) == 1.0


@pytest.mark.parametrize("offsets", [PERIODIC, JITTERED, IRREGULAR, BURST,
                                     LONG_PERIODIC])
def test_the_score_is_always_within_range(offsets):
    result = module(offsets).evaluate(ctx())
    assert 0.0 <= result.score <= 1.0
    assert result.is_valid()


# =========================================================================
# Configuration validation
# =========================================================================

@pytest.mark.parametrize("kwargs", [
    {"window_s": 0}, {"window_s": -1},
    {"min_observations": 1},          # one observation yields no interval
    {"evidence_intervals": 0},
    {"min_interval_s": 0},
])
def test_invalid_configuration_is_rejected_at_construction(kwargs):
    with pytest.raises(ValueError):
        module(**kwargs)


def test_the_defaults_are_the_documented_ones():
    assert DEFAULT_WINDOW_S == 3600.0
    assert DEFAULT_MIN_OBSERVATIONS == 4
    assert Settings().beacon_window_s == 3600.0
    assert Settings().beacon_min_observations == 4
    assert Settings().beacon_per_client is False


# =========================================================================
# Insufficient evidence
# =========================================================================

@pytest.mark.parametrize("offsets", [None, [], [0], [0, 300], [0, 300, 600]])
def test_thin_history_raises_rather_than_scoring_zero(offsets):
    """Zero would claim the timing was judged and found irregular."""
    with pytest.raises(InsufficientObservations):
        module(offsets).evaluate(ctx())


def test_the_insufficiency_message_says_what_was_missing():
    with pytest.raises(InsufficientObservations, match="4 are needed"):
        module([0, 300]).evaluate(ctx())


def test_the_engine_excludes_an_insufficient_module():
    """It must not drag the aggregate down on every rarely-seen domain."""
    engine = DecisionEngine([FixedScoreModule("ti", 1.0), module([0, 300])])
    results = engine.evaluate(ctx())

    assert results[1].status == STATUS_UNAVAILABLE
    assert results[1].features["unavailable"] == "InsufficientObservations"
    assert results[1].counts_toward_score is False

    aggregated = engine.aggregator.aggregate(results)
    assert aggregated["score"] == 1.0, "thin history diluted the aggregate"
    assert aggregated["explanation"]["excluded"] == ["beaconing"]


def test_a_missing_history_backend_raises():
    with pytest.raises(InsufficientObservations, match="no observation history"):
        BeaconingModule(history=None).evaluate(ctx())


def test_the_minimum_is_configurable():
    assert module([0, 300, 600], min_observations=3).evaluate(ctx()).score >= 0.0
    with pytest.raises(InsufficientObservations):
        module([0, 300, 600], min_observations=5).evaluate(ctx())


# =========================================================================
# The detections
# =========================================================================

def test_periodic_traffic_scores_above_irregular_traffic():
    """The property the whole module exists for."""
    periodic = module(PERIODIC).evaluate(ctx())
    irregular = module(IRREGULAR).evaluate(ctx())

    assert periodic.score > irregular.score
    assert periodic.features["coefficient_of_variation"] < \
        irregular.features["coefficient_of_variation"]


def test_perfectly_periodic_traffic_has_zero_variation():
    features = module(PERIODIC).evaluate(ctx()).features
    assert features["coefficient_of_variation"] == 0.0
    assert features["regularity"] == 1.0
    assert features["median_interval_s"] == 300.0


def test_jittered_periodic_traffic_still_scores_high():
    """A real beacon jitters; it must not fall off a cliff."""
    jittered = module(JITTERED).evaluate(ctx())
    irregular = module(IRREGULAR).evaluate(ctx())

    assert jittered.features["regularity"] > 0.9
    assert jittered.score > irregular.score


def test_more_observations_increase_the_score_for_the_same_rhythm():
    """Five even check-ins are weaker evidence of a clock than twelve."""
    few = module(PERIODIC).evaluate(ctx())
    many = module(LONG_PERIODIC).evaluate(ctx())

    assert many.score > few.score
    assert many.features["confidence"] == 1.0
    assert few.features["confidence"] < 1.0


def test_a_burst_is_not_reported_as_a_beacon():
    """Fifty queries in two seconds are extremely regular and not a beacon."""
    burst = module(BURST).evaluate(ctx())

    assert burst.features["regularity"] > 0.9, "the burst is indeed regular"
    assert burst.features["burst_factor"] < 0.1
    assert burst.score < 0.2, "a burst was scored as periodic"


def test_observations_outside_the_window_are_ignored():
    inside = module(LONG_PERIODIC, window_s=3600).evaluate(ctx())
    narrow = module(LONG_PERIODIC, window_s=1000)

    assert inside.features["observations"] == 12
    assert narrow.evaluate(ctx()).features["observations"] == 4


def test_a_narrow_window_can_leave_too_little_evidence():
    with pytest.raises(InsufficientObservations):
        module(LONG_PERIODIC, window_s=700).evaluate(ctx())


def test_duplicate_timestamps_do_not_crash_the_module():
    result = module([0, 0, 0, 0, 300, 300]).evaluate(ctx())
    assert result.is_valid()
    assert 0.0 <= result.score <= 1.0


def test_all_identical_timestamps_score_zero_with_a_reason():
    result = module([100, 100, 100, 100]).evaluate(ctx())
    assert result.score == 0.0
    assert result.features["mean_interval_s"] == 0.0


def test_extremely_large_intervals_are_handled():
    result = module([0, 1000, 2000, 3000], window_s=10_000).evaluate(ctx())
    assert result.is_valid()


def test_evaluation_is_deterministic():
    built = module(PERIODIC)
    first = built.evaluate(ctx())
    second = built.evaluate(ctx())
    assert first.score == second.score
    assert first.features == second.features


# =========================================================================
# Scoping
# =========================================================================

def test_the_domain_is_normalised_before_lookup():
    history = FakeHistory(PERIODIC)
    BeaconingModule(history=history).evaluate(ctx("BEACON.TEST."))
    assert history.calls[0][0] == "beacon.test"


def test_different_domains_are_measured_separately():
    history = FakeHistory([], per_domain={
        "regular.test": PERIODIC, "chaotic.test": IRREGULAR})
    built = BeaconingModule(history=history)

    assert (built.evaluate(ctx("regular.test")).score
            > built.evaluate(ctx("chaotic.test")).score)


def test_per_client_scoping_is_off_by_default():
    history = FakeHistory(PERIODIC)
    BeaconingModule(history=history).evaluate(ctx(client_id="abc"))
    assert history.calls[0][2] is None


def test_per_client_scoping_passes_the_client_when_enabled():
    history = FakeHistory(PERIODIC)
    BeaconingModule(history=history, per_client=True).evaluate(
        ctx(client_id="abc123"))
    assert history.calls[0][2] == "abc123"
    assert BeaconingModule(history=FakeHistory(PERIODIC), per_client=True) \
        .evaluate(ctx()).features["scope"] == "client+domain"


def test_the_window_start_is_derived_from_the_query_timestamp():
    """Only the cutoff passed to the store matters here.

    A 600s window leaves too few of these observations to score, so the
    evaluation raises; the call has already been recorded by then.
    """
    history = FakeHistory(PERIODIC)
    with pytest.raises(InsufficientObservations):
        BeaconingModule(history=history, window_s=600).evaluate(ctx(timestamp=NOW))
    assert history.calls[0][1] == pytest.approx(NOW - 600)


# =========================================================================
# Evidence
# =========================================================================

def test_the_evidence_contains_the_documented_fields():
    features = module(LONG_PERIODIC).evaluate(ctx()).features
    for key in ["qname", "window_s", "observations", "intervals",
                "mean_interval_s", "median_interval_s", "stdev_interval_s",
                "coefficient_of_variation", "regularity", "confidence",
                "burst_factor", "span_s", "window_coverage", "scope",
                "reason"]:
        assert key in features, f"evidence is missing {key!r}"


def test_the_evidence_reports_the_strength_not_a_diagnosis():
    """Periodic DNS traffic is not evidence of malware, and it must say so."""
    reason = module(LONG_PERIODIC).evaluate(ctx()).features["reason"]
    assert "periodicity signal" in reason
    assert "not by itself" in reason and "evidence of malware" in reason
    for word in ["malicious", "malware infection", "confirmed", "c2 server"]:
        assert word not in reason.lower().replace(
            "evidence of malware", "")


def test_the_strength_wording_tracks_the_score():
    strong = module(LONG_PERIODIC).evaluate(ctx()).features["reason"]
    weak = module(IRREGULAR).evaluate(ctx()).features["reason"]
    assert "strong periodicity signal" in strong
    assert "weak periodicity signal" in weak


def test_unparseable_rows_are_counted_in_the_evidence():
    built = BeaconingModule(history=FakeHistory(LONG_PERIODIC, discarded=3))
    assert built.evaluate(ctx()).features["unparseable_rows"] == 3


def test_the_evidence_is_json_serialisable():
    import json

    from storage.models import EvidenceRow

    result = module(LONG_PERIODIC).evaluate(ctx())
    row = EvidenceRow.from_payload({
        "module": "beaconing", "score": result.score,
        "features": result.features, "latency_ms": 0.1, "status": "ok"})
    assert "_unserialisable" not in json.loads(row.features_json())


# =========================================================================
# The observation store
# =========================================================================

def seed(db_path: str, domain: str, offsets, client="192.0.2.10",
         now: float | None = None) -> None:
    """Write history through the project's own persistence path."""
    from datetime import datetime, timezone

    now = now if now is not None else time.time()
    database = Database(db_path)
    try:
        for offset in offsets:
            record = QueryRecord.from_log_payload({
                "client": client, "qname": domain, "qtype": "A",
                "verdict": "ALLOW", "rcode": "NOERROR", "score": 0.0,
                "engine": "seeded-fixture", "evidence": [],
                "latency_ms": {"total": 1.0}, "added_latency_ms": 0.1,
            }, "test-salt")
            record.ts = datetime.fromtimestamp(now - offset,
                                               tz=timezone.utc).isoformat()
            database.insert_record(record)
    finally:
        database.close()


def test_the_store_reads_back_what_the_proxy_wrote(tmp_path):
    path = str(tmp_path / "h.sqlite3")
    now = time.time()
    seed(path, "beacon.test", [0, 300, 600, 900], now=now)

    stamps, discarded = ObservationStore(path).observations(
        "beacon.test", now - 3600)
    assert len(stamps) == 4
    assert discarded == 0
    assert stamps == sorted(stamps), "timestamps are not oldest first"


def test_the_store_filters_by_domain(tmp_path):
    path = str(tmp_path / "two.sqlite3")
    now = time.time()
    seed(path, "one.test", [0, 300, 600], now=now)
    seed(path, "two.test", [0, 300], now=now)

    store = ObservationStore(path)
    assert len(store.observations("one.test", now - 3600)[0]) == 3
    assert len(store.observations("two.test", now - 3600)[0]) == 2
    assert store.observations("absent.test", now - 3600)[0] == []


def test_the_store_filters_by_window(tmp_path):
    path = str(tmp_path / "win.sqlite3")
    now = time.time()
    seed(path, "beacon.test", [0, 300, 7200], now=now)

    store = ObservationStore(path)
    assert len(store.observations("beacon.test", now - 3600)[0]) == 2


def test_the_store_can_filter_by_client(tmp_path):
    from storage.models import hash_client

    path = str(tmp_path / "clients.sqlite3")
    now = time.time()
    seed(path, "shared.test", [0, 300], client="192.0.2.1", now=now)
    seed(path, "shared.test", [60, 360, 660], client="192.0.2.2", now=now)

    store = ObservationStore(path)
    assert len(store.observations("shared.test", now - 3600)[0]) == 5
    scoped = store.observations(
        "shared.test", now - 3600,
        client_hash=hash_client("192.0.2.2", "test-salt"))[0]
    assert len(scoped) == 3


def test_the_store_normalises_the_domain(tmp_path):
    path = str(tmp_path / "case.sqlite3")
    now = time.time()
    seed(path, "beacon.test", [0, 300], now=now)

    store = ObservationStore(path)
    assert len(store.observations("BEACON.TEST.", now - 3600)[0]) == 2


def test_the_store_opens_read_only(tmp_path):
    import sqlite3

    path = str(tmp_path / "ro.sqlite3")
    seed(path, "a.test", [0])
    conn = ObservationStore(path)._connect()
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM queries")
    finally:
        conn.close()


def test_a_missing_database_raises_rather_than_returning_nothing(tmp_path):
    with pytest.raises(HistoryUnavailable, match="no history database"):
        ObservationStore(str(tmp_path / "absent.sqlite3")).observations(
            "a.test", 0)


def test_an_empty_domain_short_circuits(tmp_path):
    assert ObservationStore(str(tmp_path / "never.sqlite3")).observations(
        "", 0) == ([], 0)


@pytest.mark.parametrize("value,expected", [
    ("", None), ("not a date", None), (None, None),
])
def test_malformed_timestamps_are_discarded_not_raised(value, expected):
    assert parse_timestamp(value) is expected


def test_a_naive_timestamp_is_treated_as_utc():
    assert parse_timestamp("2026-09-05T00:00:00") == \
        parse_timestamp("2026-09-05T00:00:00+00:00")


def test_the_composite_index_exists(tmp_path):
    """Beaconing reads on the query path; it must not scan the table."""
    path = str(tmp_path / "idx.sqlite3")
    database = Database(path)
    try:
        names = {row[0] for row in database.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_queries_qname_ts" in names
        assert "idx_queries_client_qname_ts" in names

        plan = database.conn.execute(
            "EXPLAIN QUERY PLAN SELECT ts FROM queries "
            "WHERE qname = ? AND ts >= ? ORDER BY ts DESC",
            ("a.test", "2026-01-01")).fetchall()
        # row_factory is sqlite3.Row, whose repr says nothing; read the
        # plan's own text column.
        detail = " ".join(str(tuple(row)) for row in plan)
        assert "idx_queries_qname" in detail, \
            f"the lookup is not using an index: {detail}"
    finally:
        database.close()


def test_an_existing_database_gains_the_index_on_reopen(tmp_path):
    """Backward compatible: no version bump, no migration step."""
    import sqlite3

    path = str(tmp_path / "old.sqlite3")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE queries (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
            client_hash TEXT, qname TEXT, qtype TEXT, latency_total_ms REAL,
            latency_upstream_ms REAL, added_latency_ms REAL,
            latency_json TEXT, error TEXT);
        CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_id INTEGER, engine TEXT, aggregate_score REAL,
            verdict TEXT, rcode TEXT);
        INSERT INTO queries VALUES (1,'t','h','old.test','A',1.0,0.5,0.5,'{}',NULL);
    """)
    conn.execute("PRAGMA user_version=1")
    conn.commit()
    conn.close()

    database = Database(path)
    try:
        names = {row[0] for row in database.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_queries_qname_ts" in names
        assert database.count("queries") == 1, "the migration lost rows"
    finally:
        database.close()


# =========================================================================
# Registration and integration
# =========================================================================

def test_the_module_is_registered():
    assert REGISTRY["beaconing"] is BeaconingModule
    assert BeaconingModule.name == "beaconing"


def test_the_module_builds_through_the_startup_path(tmp_path):
    engine = build_engine(Settings(engine_modules="beaconing",
                                   db_enabled=False,
                                   db_path=str(tmp_path / "x.sqlite3")))
    try:
        assert engine.name == "engine[beaconing]"
        assert engine.modules[0].window_s == 3600.0
    finally:
        engine.close()


def test_beaconing_takes_the_default_weight():
    from engine.aggregator import DEFAULT_WEIGHTS, RiskAggregator

    assert "beaconing" not in DEFAULT_WEIGHTS
    assert RiskAggregator().weight_for("beaconing") == 0.5


def test_a_disabled_module_is_reported_not_run():
    history = FakeHistory(PERIODIC)
    engine = DecisionEngine([BeaconingModule(history=history)])
    engine.set_enabled("beaconing", False)

    result = engine.evaluate(ctx())[0]
    assert result.status == "disabled"
    assert history.calls == [], "a disabled module still read history"


@pytest.mark.parametrize("other", ["ti", "nrd", "typosquat", "dga"])
def test_beaconing_aggregates_with_each_other_module(other):
    engine = DecisionEngine([FixedScoreModule(other, 1.0),
                             module(LONG_PERIODIC)])
    results = engine.evaluate(ctx())

    assert [r.module for r in results] == [other, "beaconing"]
    assert all(r.status == STATUS_OK for r in results)
    assert 0.0 <= engine.aggregator.aggregate(results)["score"] <= 1.0


def test_all_five_modules_run_together():
    from feeds.base import FeedSnapshot
    from feeds.cache import IndicatorCache
    from feeds.first_seen import FirstSeenStore
    from engine.modules.dga import DGAModule
    from engine.modules.nrd import NewDomainModule
    from engine.modules.ti import ThreatIntelModule
    from engine.modules.typosquat import TyposquatModule

    from pathlib import Path
    artifact = (Path(__file__).resolve().parent.parent / "models" / "dga"
                / "dga_model.json")

    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"beacon.test"}))
    now = time.time()

    engine = DecisionEngine([
        ThreatIntelModule(cache),
        NewDomainModule(first_seen=FirstSeenStore(started_at=now - 60 * 86400)),
        TyposquatModule(brands=["spotify"]),
        DGAModule(model_path=str(artifact)),
        BeaconingModule(history=FakeHistory(LONG_PERIODIC)),
    ])
    results = engine.evaluate(QueryContext("beacon.test", "A", "cid", NOW))

    assert [r.module for r in results] == ["ti", "nrd", "typosquat", "dga",
                                           "beaconing"]
    assert all(r.status == STATUS_OK for r in results)

    aggregated = engine.aggregator.aggregate(results)
    assert 0.0 <= aggregated["score"] <= 1.0
    assert aggregated["explanation"]["counted_weight"] == pytest.approx(
        1.0 + 0.4 + 0.5 + 0.5 + 0.5)


def test_a_broken_history_backend_does_not_stop_other_modules():
    class Exploding:
        def observations(self, *_args, **_kwargs):
            raise HistoryUnavailable("database is on fire")

    engine = DecisionEngine([BeaconingModule(history=Exploding()),
                             FixedScoreModule("ti", 1.0)])
    results = engine.evaluate(ctx())

    assert results[0].status == STATUS_ERROR
    assert results[1].status == STATUS_OK
    assert engine.aggregator.aggregate(results)["score"] == 1.0
