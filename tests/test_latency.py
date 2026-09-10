"""Stage 18 tests: latency measurement.

The measurement itself is not run here. Mode B spawns real proxy processes
and sends thousands of queries; putting that in the suite would make every
`pytest` invocation minutes long and would produce timings under whatever
load the test runner happens to be creating — which is the opposite of a
controlled measurement. `tools/run_latency.py` performs the run.

What is tested here is the apparatus: that the percentiles are arithmetically
right against values worked out by hand, that a missing phase is never
silently counted as zero, that warm-up discard behaves at the edges, and that
the runner is structured so it cannot stall or mislabel a result.
"""

import inspect
import json
from pathlib import Path

import pytest

from experiments.latency import (
    DEFAULT_REPEATS,
    DEFAULT_WARMUP,
    PHASES,
    Distribution,
    added_latency,
    collect,
    discard_warmup,
    summarise_phases,
    time_engine,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# =========================================================================
# Distributions
# =========================================================================

def test_percentiles_of_a_known_series():
    """Hand-checked against a series whose order statistics are obvious."""
    distribution = Distribution("t", [float(n) for n in range(1, 101)])

    assert distribution.count == 100
    assert distribution.p50 == 50.0
    assert distribution.p90 == 90.0
    assert distribution.p99 == 99.0


def test_percentiles_are_real_observations_not_interpolations():
    """Nearest-rank: every reported figure is a timing that occurred.

    An interpolated p99 of four samples would be an average of two numbers,
    which is a value nothing measured.
    """
    samples = [1.0, 2.0, 3.0, 4.0]
    distribution = Distribution("t", samples)

    for value in (distribution.p50, distribution.p90, distribution.p99):
        assert value in samples


def test_ordering_does_not_affect_the_result():
    ascending = Distribution("t", [1.0, 2.0, 3.0, 4.0, 5.0])
    shuffled = Distribution("t", [4.0, 1.0, 5.0, 2.0, 3.0])
    assert ascending.as_dict() == shuffled.as_dict()


def test_a_single_sample_reports_itself():
    distribution = Distribution("t", [7.5])
    assert distribution.p50 == distribution.p90 == distribution.p99 == 7.5
    assert distribution.as_dict()["stdev"] == 0.0


def test_an_empty_distribution_reports_nothing_rather_than_zero():
    """Zero milliseconds is a measurement; no measurement is not."""
    payload = Distribution("t", []).as_dict()
    assert payload["count"] == 0
    for key in ("min", "p50", "p90", "p99", "max", "mean"):
        assert payload[key] is None


def test_the_summary_carries_every_reported_field():
    payload = Distribution("t", [1.0, 2.0, 3.0]).as_dict()
    assert set(payload) == {"label", "count", "min", "p50", "p90", "p99",
                            "max", "mean", "stdev"}
    assert json.loads(json.dumps(payload))["count"] == 3


def test_the_tail_is_visible_where_a_mean_would_hide_it():
    """The reason percentiles are reported at all.

    A 5-in-100 tail shows at p99. Note the neighbouring case: with exactly
    one outlier in 100, the 99th percentile is correctly the *fast* value and
    only `max` exposes the slow one — which is why max is reported alongside
    the percentiles rather than instead of them.
    """
    frequent_tail = Distribution("t", [0.4] * 95 + [40.0] * 5)
    assert frequent_tail.as_dict()["mean"] < 5.0
    assert frequent_tail.p50 == 0.4
    assert frequent_tail.p99 == 40.0

    single_outlier = Distribution("t", [0.4] * 99 + [40.0])
    assert single_outlier.p99 == 0.4
    assert single_outlier.as_dict()["max"] == 40.0


# =========================================================================
# Warm-up
# =========================================================================

def test_warmup_discards_the_leading_samples():
    assert discard_warmup([1.0, 2.0, 3.0, 4.0, 5.0], warmup=2) == [3.0, 4.0, 5.0]


def test_a_run_shorter_than_the_warmup_is_kept_not_emptied():
    """A short run is better shown as a small sample than as no sample."""
    assert discard_warmup([1.0, 2.0], warmup=10) == [1.0, 2.0]


@pytest.mark.parametrize("warmup", [0, -1])
def test_no_warmup_keeps_everything(warmup):
    assert discard_warmup([1.0, 2.0, 3.0], warmup=warmup) == [1.0, 2.0, 3.0]


def test_the_defaults_are_the_documented_ones():
    assert DEFAULT_WARMUP == 20
    assert DEFAULT_REPEATS == 3


# =========================================================================
# Collecting phases
# =========================================================================

def test_a_missing_phase_is_skipped_not_counted_as_zero():
    """`upstream` is absent on a blocked query, `enforce` on a forwarded one.

    Counting either as 0.0 would invent a measurement of a phase that never
    ran, and would drag the reported percentile towards zero.
    """
    records = [{"total": 1.0, "upstream": 0.5},
               {"total": 2.0},                     # blocked: no upstream
               {"total": 3.0, "upstream": 1.5}]

    assert collect(records, "upstream") == [0.5, 1.5]
    assert len(collect(records, "total")) == 3


def test_unparseable_values_are_skipped():
    records = [{"total": "not a number"}, {"total": None}, {"total": 2.0}]
    assert collect(records, "total") == [2.0]


def test_every_phase_appears_in_a_summary():
    records = [{"parse": 0.1, "decide": 0.2, "total": 0.3} for _ in range(5)]
    summary = summarise_phases(records, warmup=0)

    assert set(summary) == set(PHASES)
    assert summary["parse"]["count"] == 5
    # A phase nothing recorded is reported as absent, not as zero.
    assert summary["enforce"]["count"] == 0
    assert summary["enforce"]["p50"] is None


def test_the_phase_list_matches_what_the_proxy_times():
    """Guards against a phase being renamed in the proxy and silently lost."""
    source = (REPO_ROOT / "proxy" / "dns_proxy.py").read_text(encoding="utf-8")
    source += (REPO_ROOT / "engine" / "decision.py").read_text(encoding="utf-8")

    for phase in ("parse", "decide", "enforce", "upstream", "modules",
                  "aggregate"):
        assert phase in PHASES
        assert f'"{phase}"' in source, f"the proxy no longer times {phase!r}"


# =========================================================================
# Added latency — the RQ2 figure
# =========================================================================

def test_added_latency_is_total_minus_upstream():
    records = [{"total": 10.0, "upstream": 9.0},
               {"total": 12.0, "upstream": 10.0}]
    payload = added_latency(records, warmup=0)

    assert payload["count"] == 2
    assert payload["p50"] in (1.0, 2.0)
    assert payload["min"] == 1.0
    assert payload["max"] == 2.0


def test_a_blocked_query_counts_its_whole_total_as_added():
    """No upstream call happened, so none of the time was the network's."""
    payload = added_latency([{"total": 0.5}], warmup=0)
    assert payload["p50"] == 0.5


def test_added_latency_is_never_negative_on_real_records():
    records = [{"total": 5.0, "upstream": 4.9}, {"total": 5.0, "upstream": 0.1}]
    assert added_latency(records, warmup=0)["min"] >= 0.0


# =========================================================================
# Mode A, on a trivial engine
# =========================================================================

class _StubModule:
    name = "stub"
    enabled = True

    def evaluate(self, ctx):
        from engine.modules.base import ModuleScore
        return ModuleScore(0.0, {})

    def close(self):
        return


def test_timing_an_engine_produces_per_module_and_phase_figures():
    import time as clock

    from engine.decision import DecisionEngine
    from engine.modules.base import QueryContext

    engine = DecisionEngine([_StubModule()])
    contexts = [QueryContext(qname=f"d{i}.test", qtype="A", client_id="c",
                             timestamp=clock.time()) for i in range(30)]

    measured = time_engine(engine, contexts, repeats=2, warmup=5)

    assert measured["queries_timed"] == 60
    assert measured["phases"]["modules"]["count"] == 55
    assert measured["phases"]["total"]["p50"] >= 0.0
    assert "stub" in measured["per_module"]
    assert len(measured["per_run"]) == 2


def test_mode_a_touches_no_socket_and_no_database():
    """It isolates detection cost from network cost, so it must do neither."""
    # The docstring says "no socket is opened", so compare the code only.
    source = inspect.getsource(time_engine).replace(time_engine.__doc__ or "", "")
    for forbidden in ("socket", "sqlite3", "requests", "urlopen"):
        assert forbidden not in source


# =========================================================================
# The runner's structure
# =========================================================================

def test_the_runner_drains_the_proxy_output_on_a_thread():
    """Regression for a stall found during the first Mode B run.

    Reading the proxy's stdout only until "listening on" and then stopping
    fills the pipe buffer after a few hundred logged queries, at which point
    the proxy blocks writing its own log and the measurement stalls. A
    dedicated reader must own the pipe for the process's lifetime.
    """
    source = inspect.getsource(
        __import__("tools.run_latency", fromlist=["run_proxy_case"])
        .run_proxy_case)

    assert "threading.Thread" in source
    assert "for line in process.stdout" in source
    assert "readline()" not in source, "the readline loop would stall again"


def test_the_runner_measures_the_three_required_paths():
    import tools.run_latency as runner

    source = inspect.getsource(runner.run_mode_b)
    assert "enforced_block" in source
    assert "module_unavailable" in source
    assert "baseline_no_modules" in source
    assert "DNSF_AGGREGATOR_ENFORCE" in source


def test_the_runner_is_not_collected_by_pytest():
    """The long measurement must stay out of the normal suite."""
    assert not (REPO_ROOT / "tests" / "run_latency.py").exists()
    assert (REPO_ROOT / "tools" / "run_latency.py").is_file()


def test_the_caveat_states_the_figures_are_machine_specific():
    import tools.run_latency as runner

    assert "one machine" in runner.CAVEAT
    assert "hardware-specific" in runner.CAVEAT
    assert "loopback stub" in runner.CAVEAT


def test_mode_a_configurations_cover_each_module_and_the_fusion():
    from experiments.harness import ALL_MODULES
    from tools.run_latency import MODE_A_CONFIGS

    names = {name for name, _ in MODE_A_CONFIGS}
    assert "none" in names, "no baseline for the engine's own overhead"
    assert "all" in names, "the fusion is not measured"
    for module in ALL_MODULES:
        assert module in names
