"""Stage 4 tests: the module contract and the decision engine.

What these have to prove is not that a no-op module returns zero. It is that
a badly behaved module cannot corrupt a decision, cannot be mistaken for a
clean one, and cannot take DNS resolution down.
"""

import struct
import threading
import time

import pytest

from config.settings import Settings
from engine.decision import DecisionEngine
from engine.modules import REGISTRY
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
from tests.test_packet import make_query
from tests.test_proxy_integration import StubUpstream, ask


def ctx(qname="example.com"):
    return QueryContext(qname=qname, qtype="A", client_id="abc123",
                        timestamp=time.time())


# -- the contract ---------------------------------------------------------

def test_null_module_satisfies_the_contract():
    result = NullModule().evaluate(ctx())
    assert isinstance(result, ModuleScore)
    assert result.score == 0.0
    assert result.is_valid()
    assert result.features["detects"] == "nothing"


def test_null_module_declares_that_it_detects_nothing():
    """Nobody reading a stored row should mistake it for a detector."""
    assert NullModule().name == "null"
    assert NullModule().evaluate(ctx()).features["detects"] == "nothing"


@pytest.mark.parametrize("score", [0.0, 0.5, 1.0])
def test_scores_in_range_are_valid(score):
    assert ModuleScore(score).is_valid()


@pytest.mark.parametrize("score", [-0.1, 1.1, 2.0, float("nan"),
                                   float("inf"), float("-inf"),
                                   "0.5", None, True])
def test_scores_out_of_range_or_wrong_type_are_invalid(score):
    """NaN matters most: it fails every comparison silently."""
    assert not ModuleScore(score).is_valid()


def test_a_module_must_declare_a_name():
    class Nameless(DetectionModule):
        def evaluate(self, c):
            return ModuleScore(0.0)

    with pytest.raises(ValueError, match="must define a name"):
        DecisionEngine([Nameless()])


def test_duplicate_module_names_are_rejected():
    """Two modules with one name would make evidence unattributable."""
    with pytest.raises(ValueError, match="duplicate"):
        DecisionEngine([FixedScoreModule("dup", 0.1),
                        FixedScoreModule("dup", 0.2)])


def test_the_registry_exposes_the_null_module():
    assert REGISTRY["null"] is NullModule


# -- evaluation and fault isolation ---------------------------------------

class ExplodingModule(DetectionModule):
    name = "exploding"

    def evaluate(self, c):
        raise RuntimeError("module is broken")


class WrongTypeModule(DetectionModule):
    name = "wrongtype"

    def evaluate(self, c):
        return {"score": 0.9}          # a dict, not a ModuleScore


class OutOfRangeModule(DetectionModule):
    name = "outofrange"

    def evaluate(self, c):
        return ModuleScore(7.5)


class SlowModule(DetectionModule):
    name = "slow"

    def __init__(self, delay=0.08):
        self.delay = delay

    def evaluate(self, c):
        time.sleep(self.delay)
        return ModuleScore(0.1)


def test_every_module_produces_exactly_one_result():
    engine = DecisionEngine([NullModule(), FixedScoreModule("fixed", 0.4)])
    results = engine.evaluate(ctx())
    assert [r.module for r in results] == ["null", "fixed"]
    assert all(r.status == STATUS_OK for r in results)


def test_a_raising_module_is_recorded_not_propagated():
    engine = DecisionEngine([ExplodingModule(), NullModule()])
    results = engine.evaluate(ctx())

    broken = results[0]
    assert broken.status == STATUS_ERROR
    assert broken.features["error"] == "RuntimeError"
    assert "broken" in broken.features["detail"]
    assert results[1].status == STATUS_OK, "the next module did not run"


def test_a_failed_module_does_not_count_as_scoring_zero():
    """Zero means 'ran, found nothing'. Failure means 'we do not know'."""
    engine = DecisionEngine([ExplodingModule(), NullModule()])
    results = engine.evaluate(ctx())

    assert results[0].score == 0.0
    assert results[0].counts_toward_score is False
    assert results[1].score == 0.0
    assert results[1].counts_toward_score is True


def test_a_module_returning_the_wrong_type_is_marked_invalid():
    results = DecisionEngine([WrongTypeModule()]).evaluate(ctx())
    assert results[0].status == STATUS_INVALID
    assert results[0].features["returned"] == "dict"


def test_an_out_of_range_score_is_rejected_not_clamped():
    """Clamping would invent a score no module computed."""
    results = DecisionEngine([OutOfRangeModule()]).evaluate(ctx())
    assert results[0].status == STATUS_INVALID
    assert results[0].score == 0.0
    assert "7.5" in results[0].features["returned"]


def test_every_result_carries_a_measured_latency():
    results = DecisionEngine([SlowModule(0.02), NullModule()]).evaluate(ctx())
    assert results[0].latency_ms >= 15.0, "the slow module was not timed"
    assert results[1].latency_ms >= 0.0


def test_a_failing_module_is_still_timed():
    results = DecisionEngine([ExplodingModule()]).evaluate(ctx())
    assert results[0].latency_ms >= 0.0


# -- latency budget -------------------------------------------------------

def test_modules_past_the_budget_are_skipped_not_run():
    engine = DecisionEngine([SlowModule(0.08), NullModule()], budget_ms=10.0)
    results = engine.evaluate(ctx())

    assert results[0].status == STATUS_OK
    assert results[1].status == STATUS_SKIPPED
    assert results[1].features["reason"] == "latency budget exhausted"
    assert results[1].features["budget_ms"] == 10.0


def test_a_generous_budget_runs_everything():
    engine = DecisionEngine([SlowModule(0.01), NullModule()], budget_ms=5000.0)
    assert all(r.status == STATUS_OK for r in engine.evaluate(ctx()))


# -- ablation control -----------------------------------------------------

def test_a_disabled_module_is_reported_not_omitted():
    """A missing row and a zero score must never be confusable."""
    engine = DecisionEngine([NullModule(), FixedScoreModule("fixed", 0.4)])
    assert engine.set_enabled("fixed", False)

    results = engine.evaluate(ctx())
    assert len(results) == 2, "the disabled module vanished from the evidence"
    assert results[1].status == STATUS_DISABLED
    assert results[1].counts_toward_score is False


def test_set_enabled_reports_an_unknown_module():
    assert DecisionEngine([NullModule()]).set_enabled("nope", False) is False


def test_engine_name_records_the_active_configuration():
    """Stage 16 must identify a configuration from the database alone."""
    engine = DecisionEngine([NullModule(), FixedScoreModule("fixed", 0.4)])
    assert engine.name == "engine[null,fixed]"

    engine.set_enabled("fixed", False)
    assert engine.name == "engine[null]"

    engine.set_enabled("null", False)
    assert engine.name == "engine[none]"


def test_disabling_a_module_does_not_change_the_code_path():
    """Ablation must compare configurations, not implementations."""
    engine = DecisionEngine([NullModule(), FixedScoreModule("fixed", 0.4)])
    with_both = engine.evaluate(ctx())
    engine.set_enabled("fixed", False)
    with_one = engine.evaluate(ctx())

    assert [r.module for r in with_both] == [r.module for r in with_one]
    assert with_one[0].status == STATUS_OK


# -- the proxy-facing interface -------------------------------------------

def test_decide_returns_the_frozen_shape():
    """Stage 7 added `explanation`; Stage 8 added `enforcement`.

    Additive, not a break: the proxy reads the result by key, so
    AllowAllEngine's three-key return still works. The three original keys
    are still required, which is what this asserts.
    """
    engine = DecisionEngine([NullModule()])
    query = parse_query(make_query("shape.test"))
    decision = engine.decide(query, Stopwatch(), client_id="cid")

    assert {"verdict", "score", "evidence"} <= set(decision)
    assert set(decision) == {"verdict", "score", "evidence", "explanation",
                             "enforcement"}
    assert decision["verdict"] == "ALLOW"
    assert decision["score"] == 0.0
    assert isinstance(decision["evidence"], list)


def test_evidence_matches_the_storage_row_shape():
    """storage.models.EvidenceRow reads these keys with no translation."""
    engine = DecisionEngine([NullModule()])
    query = parse_query(make_query("evidence.test"))
    item = engine.decide(query, Stopwatch())["evidence"][0]

    assert set(item) == {"module", "score", "features", "latency_ms", "status"}
    from storage.models import EvidenceRow
    row = EvidenceRow.from_payload(item)
    assert row.module == "null"
    assert row.status == STATUS_OK


def test_decide_adds_a_modules_entry_to_the_stopwatch():
    """RQ2 needs detection time separable from the rest of the query path."""
    engine = DecisionEngine([SlowModule(0.02)])
    stopwatch = Stopwatch()
    engine.decide(parse_query(make_query("timed.test")), stopwatch)

    latency = stopwatch.as_dict()
    assert "modules" in latency
    assert latency["modules"] >= 15.0


def test_decide_passes_the_client_id_to_modules():
    """Stage 13 beaconing is defined over (client, domain) pairs."""
    seen = {}

    class Capturing(DetectionModule):
        name = "capturing"

        def evaluate(self, c):
            seen["client_id"] = c.client_id
            seen["qname"] = c.qname
            return ModuleScore(0.0)

    engine = DecisionEngine([Capturing()])
    engine.decide(parse_query(make_query("ctx.test")), Stopwatch(),
                  client_id="hashed-client")

    assert seen == {"client_id": "hashed-client", "qname": "ctx.test"}


def test_an_engine_with_no_modules_still_answers():
    decision = DecisionEngine([]).decide(parse_query(make_query("empty.test")),
                                         Stopwatch())
    assert decision["verdict"] == "ALLOW"
    assert decision["evidence"] == []


# -- configuration --------------------------------------------------------

def test_no_configured_modules_keeps_the_stage_2_engine():
    engine = build_engine(Settings())
    assert engine.name == "allow-all"


def test_configured_modules_build_a_decision_engine():
    engine = build_engine(Settings(engine_modules="null"))
    assert engine.name == "engine[null]"


def test_an_unknown_module_name_is_fatal_at_startup():
    """Silently skipping it would produce an ablation that looks valid."""
    with pytest.raises(SystemExit, match="unknown module"):
        build_engine(Settings(engine_modules="null,does-not-exist"))


def test_module_names_are_parsed_tolerantly():
    assert Settings(engine_modules=" null , , null2 ").module_names == \
        ["null", "null2"]


# -- end to end through the proxy -----------------------------------------

def test_the_proxy_resolves_with_the_engine_attached():
    """Fault isolation, proven through the real query path."""
    upstream = StubUpstream("answer").start()
    engine = DecisionEngine([ExplodingModule(), NullModule()])
    settings = Settings(listen_host="127.0.0.1", listen_port=0,
                        upstream_host="127.0.0.1", upstream_port=upstream.port,
                        workers=4)
    proxy = DNSProxy(settings, engine=engine)
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
        reply = ask(proxy.port, make_query("engine.test", txid=0x0E0E))
        txid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", reply[:12])
        assert txid == 0x0E0E
        assert flags & 0xF == 0, "a broken module broke DNS resolution"
        assert an == 1
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()
