"""Stage 7 tests: risk aggregation and the decision trace.

The arithmetic is a weighted mean and is not interesting. What these tests
protect is the three things that make the number defensible: a failed module
never becomes a zero, "we do not know" is never reported as "allow", and a
decision is never silently enforced.
"""

import json
import struct
import threading
import time

import pytest

from config.settings import Settings
from engine.aggregator import (
    DEFAULT_WEIGHTS,
    VERDICT_ALLOW,
    VERDICT_BLOCK,
    VERDICT_FLAG,
    VERDICT_UNKNOWN,
    RiskAggregator,
    parse_weights,
)
from engine.decision import DecisionEngine
from engine.modules.base import (
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_INVALID,
    STATUS_OK,
    STATUS_SKIPPED,
    DetectionModule,
    ModuleResult,
    ModuleScore,
    QueryContext,
)
from engine.modules.null import FixedScoreModule, NullModule
from proxy.dns_proxy import DNSProxy, build_engine
from proxy.packet import parse_query
from proxy.timing import Stopwatch
from storage.db import Database
from storage.models import QueryRecord
from tests.test_packet import make_query
from tests.test_proxy_integration import StubUpstream, ask


def result(module, score, status=STATUS_OK):
    return ModuleResult(module, score, {}, 0.1, status)


def ctx(qname="x.test"):
    return QueryContext(qname=qname, qtype="A", client_id="cid",
                        timestamp=time.time())


# -- weight parsing -------------------------------------------------------

def test_default_weights_are_used_when_unconfigured():
    assert parse_weights("") == DEFAULT_WEIGHTS


def test_weights_can_be_overridden():
    weights = parse_weights("ti=0.9,nrd=0.7")
    assert weights["ti"] == 0.9 and weights["nrd"] == 0.7


def test_an_unknown_module_gets_the_default_weight():
    assert RiskAggregator().weight_for("typosquat") == 0.5


@pytest.mark.parametrize("spec", ["ti", "ti=abc", "ti=-1"])
def test_malformed_weights_are_rejected(spec):
    """A silently dropped weight would change an ablation's results while the
    run still looked successful."""
    with pytest.raises(ValueError):
        parse_weights(spec)


# -- threshold validation -------------------------------------------------

def test_block_below_flag_is_rejected():
    """Otherwise the FLAG band is empty and nothing can be flagged only."""
    with pytest.raises(ValueError, match="below flag_at"):
        RiskAggregator(flag_at=0.8, block_at=0.5)


@pytest.mark.parametrize("kwargs", [{"flag_at": -0.1}, {"block_at": 1.5}])
def test_thresholds_outside_the_range_are_rejected(kwargs):
    with pytest.raises(ValueError, match="within"):
        RiskAggregator(**kwargs)


def test_an_unknown_fail_mode_is_rejected():
    with pytest.raises(ValueError, match="fail_mode"):
        RiskAggregator(fail_mode="maybe")


# -- the weighted mean ----------------------------------------------------

def test_a_single_clean_module_gives_its_own_score():
    out = RiskAggregator().aggregate([result("ti", 1.0)])
    assert out["score"] == 1.0


def test_scores_are_weighted_not_averaged_flat():
    """ti=1.0 and nrd=0.4: a hit on ti alone must outweigh a hit on nrd."""
    agg = RiskAggregator()
    ti_only = agg.aggregate([result("ti", 1.0), result("nrd", 0.0)])
    nrd_only = agg.aggregate([result("ti", 0.0), result("nrd", 1.0)])
    assert ti_only["score"] > nrd_only["score"]


def test_the_weighted_mean_is_arithmetically_correct():
    out = RiskAggregator().aggregate([result("ti", 1.0), result("nrd", 0.5)])
    # (1.0*1.0 + 0.5*0.4) / (1.0 + 0.4)
    assert out["score"] == pytest.approx(1.2 / 1.4, abs=1e-6)


def test_the_score_never_leaves_the_valid_range():
    agg = RiskAggregator()
    for scores in [(0.0, 0.0), (1.0, 1.0), (1.0, 0.0), (0.3, 0.7)]:
        out = agg.aggregate([result("ti", scores[0]), result("nrd", scores[1])])
        assert 0.0 <= out["score"] <= 1.0


def test_nrd_alone_cannot_reach_the_block_threshold_in_a_hybrid_config():
    """Most malicious domains are young; most young domains are not malicious.

    A correlate must not block on its own *when a stronger signal is also
    running and disagrees*. Note the qualifier: because the mean normalises by
    contributing weight, a module configured as the only enabled signal does
    produce its own score. That is correct — an operator running nrd-only has
    asked for exactly that — but it means the weighting protects against a
    weak signal dominating, not against a weak signal being used alone.
    """
    out = RiskAggregator().aggregate([result("ti", 0.0), result("nrd", 1.0)])

    assert out["explanation"]["policy_verdict"] == VERDICT_ALLOW
    assert out["score"] == pytest.approx(0.4 / 1.4, abs=1e-6)


def test_a_single_module_configuration_scores_on_that_module_alone():
    """The consequence of normalising by contributing weight, stated openly."""
    out = RiskAggregator().aggregate([result("nrd", 1.0)])
    assert out["score"] == 1.0
    assert out["explanation"]["counted_weight"] == 0.4


# -- verdict bands --------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (0.0, VERDICT_ALLOW), (0.49, VERDICT_ALLOW),
    (0.5, VERDICT_FLAG), (0.79, VERDICT_FLAG),
    (0.8, VERDICT_BLOCK), (1.0, VERDICT_BLOCK),
])
def test_verdict_bands_including_their_boundaries(score, expected):
    out = RiskAggregator().aggregate([result("solo", score)])
    assert out["explanation"]["policy_verdict"] == expected


def test_thresholds_are_configurable():
    agg = RiskAggregator(flag_at=0.2, block_at=0.3)
    assert agg.aggregate([result("solo", 0.25)])["explanation"][
        "policy_verdict"] == VERDICT_FLAG


# -- excluded modules are not zeros ---------------------------------------

@pytest.mark.parametrize("status", [STATUS_ERROR, STATUS_INVALID,
                                    STATUS_SKIPPED, STATUS_DISABLED])
def test_an_excluded_module_is_not_averaged_in_as_zero(status):
    """Averaging a failure in as 0.0 would drag the score down on exactly the
    queries where something went wrong."""
    out = RiskAggregator().aggregate([
        result("ti", 1.0), result("nrd", 0.0, status)])

    assert out["score"] == 1.0, "the excluded module diluted the score"
    assert out["explanation"]["excluded"] == ["nrd"]
    assert out["explanation"]["counted_weight"] == 1.0


def test_excluding_a_module_changes_the_denominator_not_just_the_numerator():
    agg = RiskAggregator()
    both = agg.aggregate([result("ti", 1.0), result("nrd", 1.0)])
    one = agg.aggregate([result("ti", 1.0),
                         result("nrd", 1.0, STATUS_ERROR)])
    assert both["score"] == 1.0 and one["score"] == 1.0


def test_all_modules_failing_is_unknown_not_allow():
    """'We could not find out' is a different claim from 'this is fine'."""
    out = RiskAggregator().aggregate([
        result("ti", 0.0, STATUS_ERROR), result("nrd", 0.0, STATUS_ERROR)])

    assert out["explanation"]["policy_verdict"] == VERDICT_UNKNOWN
    assert out["explanation"]["reason"] == "no module produced a usable score"


def test_no_modules_registered_is_allow_not_unknown():
    """An operator who configured no detection got exactly what they asked."""
    out = RiskAggregator().aggregate([])
    assert out["verdict"] == VERDICT_ALLOW
    assert out["explanation"]["reason"] == "no modules registered"


def test_all_weights_zero_is_allow_not_unknown():
    """'We were told not to care' is not 'we could not find out'."""
    out = RiskAggregator(weights={"a": 0.0}).aggregate([result("a", 1.0)])
    assert out["verdict"] == VERDICT_ALLOW
    assert out["explanation"]["reason"] == \
        "all contributing modules are weighted zero"


# -- decision versus enforcement ------------------------------------------

def test_a_block_is_not_enforced_by_default():
    """Stage 8 changed this deliberately.

    Stage 7 downgraded a non-enforced BLOCK to FLAG in the returned verdict.
    That made an observation run indistinguishable in the database from a
    genuine borderline FLAG, which would corrupt the Stage 16 counts: an
    observed BLOCK is a detection, not a middling score. The verdict is now
    always the policy decision, and a separate enforcement block says what
    actually happens to the query.
    """
    out = RiskAggregator().aggregate([result("ti", 1.0)])

    assert out["verdict"] == VERDICT_BLOCK, "the policy verdict was altered"
    assert out["enforcement"]["would_block"] is True
    assert out["enforcement"]["enabled"] is False
    assert out["enforcement"]["applied"] is False
    assert out["enforcement"]["action"] == "forward"
    assert "not_applied_reason" in out["enforcement"]


def test_enforcement_can_be_switched_on():
    out = RiskAggregator(enforce=True).aggregate([result("ti", 1.0)])
    assert out["verdict"] == VERDICT_BLOCK
    assert out["enforcement"]["applied"] is True
    assert out["enforcement"]["action"] == "block"
    assert out["explanation"]["enforced"] is True


def test_a_flag_is_never_escalated_to_a_block():
    """FLAG must forward whether or not enforcement is on."""
    for enforce in (False, True):
        out = RiskAggregator(enforce=enforce).aggregate([result("solo", 0.6)])
        assert out["verdict"] == VERDICT_FLAG
        assert out["enforcement"]["would_block"] is False
        assert out["enforcement"]["action"] == "forward"


def test_allow_never_blocks():
    for enforce in (False, True):
        out = RiskAggregator(enforce=enforce).aggregate([result("solo", 0.1)])
        assert out["verdict"] == VERDICT_ALLOW
        assert out["enforcement"]["action"] == "forward"


def test_fail_closed_blocks_the_unassessable_only_when_enforcing():
    unknown = [result("ti", 0.0, STATUS_ERROR)]

    strict = RiskAggregator(fail_mode="closed", enforce=True).aggregate(unknown)
    assert strict["verdict"] == VERDICT_UNKNOWN, \
        "fail-closed rewrote the verdict instead of the enforcement action"
    assert strict["enforcement"]["action"] == "block"
    assert "could not be assessed" in strict["enforcement"]["reason"]

    observing = RiskAggregator(fail_mode="closed").aggregate(unknown)
    assert observing["enforcement"]["would_block"] is True
    assert observing["enforcement"]["action"] == "forward", \
        "fail-closed blocked while enforcement was off"


def test_fail_open_resolves_the_unassessable():
    out = RiskAggregator(fail_mode="open").aggregate(
        [result("ti", 0.0, STATUS_ERROR)])
    assert out["verdict"] == VERDICT_UNKNOWN
    assert out["enforcement"]["would_block"] is False
    assert out["enforcement"]["action"] == "forward"


# -- the explanation is the contribution ----------------------------------

def test_every_module_appears_in_the_explanation():
    out = RiskAggregator().aggregate([
        result("ti", 1.0), result("nrd", 0.5, STATUS_ERROR)])
    modules = [c["module"] for c in out["explanation"]["contributions"]]
    assert modules == ["ti", "nrd"], "an excluded module vanished from the trace"


def test_each_contribution_shows_score_weight_and_product():
    out = RiskAggregator().aggregate([result("ti", 0.5)])
    entry = out["explanation"]["contributions"][0]
    assert entry["score"] == 0.5
    assert entry["weight"] == 1.0
    assert entry["weighted"] == 0.5
    assert entry["counted"] is True


def test_the_explanation_records_the_thresholds_used():
    """A score is uninterpretable without the thresholds it was judged against."""
    out = RiskAggregator(flag_at=0.3, block_at=0.6).aggregate([result("a", 0.1)])
    assert out["explanation"]["thresholds"] == {"flag_at": 0.3, "block_at": 0.6}


def test_the_explanation_states_the_weights_are_untuned():
    """Guards against the report claiming an optimisation that has not happened."""
    out = RiskAggregator().aggregate([result("ti", 1.0)])
    assert out["explanation"]["weights_are_tuned"] is False


def test_the_explanation_is_json_serialisable():
    out = RiskAggregator().aggregate([result("ti", 1.0), result("nrd", 0.2)])
    assert json.loads(json.dumps(out["explanation"]))["method"] == "weighted_mean"


# -- through the engine ---------------------------------------------------

def test_the_engine_returns_a_real_verdict_and_score():
    engine = DecisionEngine([FixedScoreModule("ti", 1.0)])
    decision = engine.decide(parse_query(make_query("bad.test")), Stopwatch())

    assert decision["score"] == 1.0
    assert decision["explanation"]["policy_verdict"] == VERDICT_BLOCK
    assert decision["verdict"] == VERDICT_BLOCK
    assert decision["enforcement"]["action"] == "forward"


def test_aggregation_time_is_measured_separately():
    """RQ2 needs aggregation cost separable from detection cost."""
    stopwatch = Stopwatch()
    DecisionEngine([NullModule()]).decide(
        parse_query(make_query("t.test")), stopwatch)
    assert "aggregate" in stopwatch.as_dict()


def test_a_broken_module_does_not_poison_the_verdict():
    class Exploding(DetectionModule):
        name = "exploding"

        def evaluate(self, c):
            raise RuntimeError("broken")

    engine = DecisionEngine([Exploding(), FixedScoreModule("ti", 1.0)])
    decision = engine.decide(parse_query(make_query("x.test")), Stopwatch())

    assert decision["score"] == 1.0
    assert decision["explanation"]["excluded"] == ["exploding"]


def test_disabling_a_module_changes_the_score_predictably():
    """The ablation control surface, end to end."""
    engine = DecisionEngine([FixedScoreModule("ti", 0.0),
                             FixedScoreModule("nrd", 1.0)])
    with_both = engine.decide(parse_query(make_query("a.test")), Stopwatch())
    engine.set_enabled("ti", False)
    nrd_only = engine.decide(parse_query(make_query("a.test")), Stopwatch())

    assert with_both["score"] < nrd_only["score"]
    assert nrd_only["explanation"]["excluded"] == ["ti"]


# -- configuration --------------------------------------------------------

def test_the_aggregator_is_built_from_settings(tmp_path):
    engine = build_engine(Settings(
        engine_modules="null", db_enabled=False,
        aggregator_flag_at=0.25, aggregator_block_at=0.75,
        aggregator_weights="null=1.0", aggregator_enforce=True))
    try:
        assert engine.aggregator.flag_at == 0.25
        assert engine.aggregator.block_at == 0.75
        assert engine.aggregator.enforce is True
        assert engine.aggregator.weights["null"] == 1.0
    finally:
        engine.close()


def test_enforcement_is_off_by_default():
    assert Settings().aggregator_enforce is False
    assert RiskAggregator.from_settings(Settings()).enforce is False


# -- persistence ----------------------------------------------------------

def test_the_explanation_is_persisted(tmp_path):
    db = Database(str(tmp_path / "s7.sqlite3"))
    try:
        assert db.schema_version == 2
        payload = {
            "client": "192.0.2.1", "qname": "bad.test", "qtype": "A",
            "verdict": "FLAG", "rcode": "NOERROR", "score": 0.86,
            "evidence": [], "latency_ms": {"total": 1.0}, "added_latency_ms": 0.5,
            "engine": "engine[ti,nrd]",
            "explanation": {"method": "weighted_mean", "policy_verdict": "BLOCK",
                            "contributions": [{"module": "ti", "weight": 1.0}]},
        }
        db.insert_record(QueryRecord.from_log_payload(payload, "salt"))

        row = db.recent_queries()[0]
        stored = json.loads(row["explanation_json"])
        assert stored["policy_verdict"] == "BLOCK"
        assert stored["contributions"][0]["module"] == "ti"
    finally:
        db.close()


def test_a_decision_without_an_explanation_stores_null(tmp_path):
    """AllowAllEngine does not aggregate; that must be distinguishable from
    an aggregation that explained nothing."""
    db = Database(str(tmp_path / "none.sqlite3"))
    try:
        db.insert_record(QueryRecord.from_log_payload({
            "client": "192.0.2.1", "qname": "x.test", "qtype": "A",
            "verdict": "ALLOW", "rcode": "NOERROR", "score": 0.0,
            "evidence": [], "latency_ms": {"total": 1.0},
            "added_latency_ms": 0.1, "engine": "allow-all"}, "salt"))
        assert db.recent_queries()[0]["explanation_json"] is None
    finally:
        db.close()


def test_a_v1_database_is_migrated_in_place(tmp_path):
    """An existing Stage 3-6 database must keep its rows and gain the column."""
    import sqlite3

    path = str(tmp_path / "v1.sqlite3")
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
        INSERT INTO decisions VALUES (1,1,'allow-all',0.0,'ALLOW','NOERROR');
    """)
    conn.execute("PRAGMA user_version=1")
    conn.commit()
    conn.close()

    db = Database(path)
    try:
        assert db.schema_version == 2
        assert db.count("queries") == 1, "migration destroyed existing rows"
        row = db.recent_queries()[0]
        assert row["qname"] == "old.test"
        assert row["explanation_json"] is None
    finally:
        db.close()


# -- end to end -----------------------------------------------------------

def test_a_detected_query_still_resolves_when_not_enforcing():
    """Detection without enforcement: the resolver keeps working."""
    upstream = StubUpstream("answer").start()
    recorder = _Capturing()
    engine = DecisionEngine([FixedScoreModule("ti", 1.0)])
    settings = Settings(listen_host="127.0.0.1", listen_port=0,
                        upstream_host="127.0.0.1", upstream_port=upstream.port,
                        workers=4)
    proxy = DNSProxy(settings, engine=engine, recorder=recorder)
    thread = threading.Thread(target=proxy.start, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            _ = proxy.port
            break
        except RuntimeError:
            time.sleep(0.01)

    try:
        reply = ask(proxy.port, make_query("flagged.test", txid=0x0F0F))
        _txid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", reply[:12])
        assert flags & 0xF == 0, "an unenforced BLOCK interrupted resolution"
        assert an == 1

        payload = recorder.wait_for(1)[0]
        assert payload["verdict"] == "BLOCK"
        assert payload["score"] == 1.0
        assert payload["rcode"] == "NOERROR", "the query did not resolve"
        assert payload["explanation"]["policy_verdict"] == "BLOCK"
        assert payload["explanation"]["enforced"] is False
        assert payload["enforcement"]["applied"] is False
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


class _Capturing:
    def __init__(self):
        self._lock = threading.Lock()
        self.payloads = []

    def record(self, payload):
        with self._lock:
            self.payloads.append(payload)

    def wait_for(self, n, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if len(self.payloads) >= n:
                    return list(self.payloads)
            time.sleep(0.01)
        raise AssertionError(f"only {len(self.payloads)} payload(s) recorded")
