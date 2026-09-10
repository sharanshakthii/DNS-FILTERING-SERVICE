"""Stage 16 tests: the evaluation harness.

An evaluation harness that is wrong produces numbers nobody can check, which
is worse than having none. Most of what follows verifies the measurement
apparatus itself: that the metrics are arithmetically right against
hand-computed values, that the harness gives modules the inputs the dataset
declares, that unavailable modules are excluded rather than scored zero, and
that nothing in `experiments/` can change a project default.
"""

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

from engine.aggregator import DEFAULT_WEIGHTS, RiskAggregator
from engine.modules.base import STATUS_OK, STATUS_UNAVAILABLE
from experiments.ablation import (
    configurations,
    deltas_against_baseline,
    per_category_recall,
    run_ablation,
)
from experiments.harness import (
    ALL_MODULES,
    PATTERNS,
    POSITIVE_VERDICTS,
    FixtureHistory,
    Harness,
    Row,
    dataset_checksum,
    load_rows,
)
from experiments.metrics import Metrics, confusion
from experiments.sweep import (
    THRESHOLD_GRID,
    WEIGHT_GRID,
    sweep_thresholds,
    sweep_weights,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET = REPO_ROOT / "datasets" / "eval_dev.csv"
MODEL = REPO_ROOT / "models" / "dga" / "dga_model.json"
FIXED_NOW = 2_000_000_000.0


def small_rows() -> list[Row]:
    """A hand-built dataset, so expected outcomes can be reasoned about."""
    return [
        Row("listed-one.test", 1, "listed", True, 500_000, "none"),
        Row("listed-two.test", 1, "listed", True, 500_000, "none"),
        Row("xkwqvbzmrtplfjdh.test", 1, "dga", False, 3600, "none"),
        Row("examplebrandlogin.test", 1, "typosquat", False, 3600, "none"),
        Row("harborworks.test", 1, "beacon", False, 500_000, "periodic"),
        Row("meadowgroup.test", 0, "benign", False, 40_000_000, "none"),
        Row("cedarlabs.test", 0, "benign", False, 40_000_000, "irregular"),
        Row("silverstudio.test", 0, "benign_new", False, 600, "none"),
    ]


def harness(rows=None) -> Harness:
    return Harness(rows or small_rows(), model_path=str(MODEL), now=FIXED_NOW)


# =========================================================================
# Metrics
# =========================================================================

def test_confusion_counts_are_correct():
    labels = [1, 1, 1, 0, 0, 0]
    predictions = [1, 1, 0, 1, 0, 0]
    metrics = confusion(labels, predictions)

    assert metrics.true_positive == 2
    assert metrics.false_negative == 1
    assert metrics.false_positive == 1
    assert metrics.true_negative == 2
    assert metrics.total == 6


def test_metrics_match_values_computed_by_hand():
    metrics = Metrics(true_positive=8, false_positive=2,
                      true_negative=6, false_negative=4)

    assert metrics.accuracy == pytest.approx(14 / 20)
    assert metrics.precision == pytest.approx(8 / 10)
    assert metrics.recall == pytest.approx(8 / 12)
    assert metrics.f1 == pytest.approx(2 * 0.8 * (2 / 3) / (0.8 + 2 / 3))
    assert metrics.false_positive_rate == pytest.approx(2 / 8)
    assert metrics.false_negative_rate == pytest.approx(4 / 12)


def test_a_perfect_classifier_scores_one():
    metrics = confusion([1, 1, 0, 0], [1, 1, 0, 0])
    assert metrics.precision == metrics.recall == metrics.f1 == 1.0
    assert metrics.false_positive_rate == 0.0


def test_a_configuration_that_flags_nothing_is_reported_as_such():
    """Precision is undefined there; the count distinguishes the cases."""
    metrics = confusion([1, 1, 0, 0], [0, 0, 0, 0])
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.predicted_positive == 0


def test_metrics_handle_an_empty_evaluation():
    metrics = confusion([], [])
    assert metrics.total == 0
    assert metrics.accuracy == 0.0


def test_mismatched_lengths_are_rejected():
    with pytest.raises(ValueError, match="labels but"):
        confusion([1, 0], [1])


@pytest.mark.parametrize("labels,predictions", [
    ([2], [1]), ([1], [2]), ([-1], [0]),
])
def test_non_binary_values_are_rejected(labels, predictions):
    with pytest.raises(ValueError, match="must be 0 or 1"):
        confusion(labels, predictions)


def test_metrics_serialise_for_the_report():
    payload = confusion([1, 0], [1, 1]).as_dict()
    for key in ["true_positive", "false_positive", "accuracy", "precision",
                "recall", "f1", "false_positive_rate", "predicted_positive"]:
        assert key in payload
    assert json.loads(json.dumps(payload))["true_positive"] == 1


# =========================================================================
# The dataset
# =========================================================================

def test_the_dataset_exists_and_validates():
    rows = load_rows(DATASET)
    assert len(rows) > 100
    assert {r.label for r in rows} == {0, 1}


def test_the_dataset_contains_the_deliberately_hard_categories():
    """Benign rows that trip the heuristics keep the evaluation honest.

    Without them the modules score near-perfectly against labels derived
    from the same assumptions they encode, and the numbers measure nothing.
    """
    categories = {r.category for r in load_rows(DATASET)}
    assert "benign_new" in categories, "no benign newly-seen domains"
    assert "benign_periodic" in categories, "no benign periodic domains"


def test_benign_hard_rows_are_labelled_negative():
    for row in load_rows(DATASET):
        if row.category in {"benign_new", "benign_periodic"}:
            assert row.label == 0


def test_malicious_rows_are_not_all_on_the_feed():
    """Otherwise threat intelligence alone would catch everything."""
    positives = [r for r in load_rows(DATASET) if r.label == 1]
    assert any(not r.ti_listed for r in positives)


def test_a_malformed_dataset_is_rejected(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("domain,label,category,ti_listed,first_seen_age_s,"
                   "observation_pattern\na.test,2,benign,0,0,none\n",
                   encoding="utf-8")
    with pytest.raises(SystemExit, match="label must be 0 or 1"):
        load_rows(bad)


def test_an_unknown_observation_pattern_is_rejected(tmp_path):
    bad = tmp_path / "pattern.csv"
    bad.write_text("domain,label,category,ti_listed,first_seen_age_s,"
                   "observation_pattern\na.test,1,x,0,0,chaotic\n",
                   encoding="utf-8")
    with pytest.raises(SystemExit, match="unknown pattern"):
        load_rows(bad)


def test_a_missing_dataset_is_reported(tmp_path):
    with pytest.raises(SystemExit, match="dataset not found"):
        load_rows(tmp_path / "absent.csv")


def test_missing_columns_are_reported(tmp_path):
    bad = tmp_path / "cols.csv"
    bad.write_text("domain,label\na.test,1\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="missing columns"):
        load_rows(bad)


def test_the_checksum_is_stable_and_input_dependent(tmp_path):
    one = tmp_path / "a.csv"
    one.write_text("x", encoding="utf-8")
    two = tmp_path / "b.csv"
    two.write_text("y", encoding="utf-8")

    assert dataset_checksum(one) == dataset_checksum(one)
    assert dataset_checksum(one) != dataset_checksum(two)


def test_the_generator_is_deterministic():
    from tools.make_eval_dataset import make_rows

    assert make_rows(20, seed=20260906) == make_rows(20, seed=20260906)
    assert make_rows(20, seed=1) != make_rows(20, seed=2)


# =========================================================================
# The harness
# =========================================================================

def test_the_harness_gives_modules_the_declared_inputs():
    """A row on the feed must reach threat intelligence as listed."""
    results = harness().run(("ti",))
    by_domain = {r.domain: r for r in results}

    assert by_domain["listed-one.test"].module_scores["ti"] == 1.0
    assert by_domain["meadowgroup.test"].module_scores["ti"] == 0.0


def test_a_periodic_row_reaches_the_beaconing_module():
    results = {r.domain: r for r in harness().run(("beaconing",))}

    beacon = results["harborworks.test"]
    assert beacon.module_statuses["beaconing"] == STATUS_OK
    assert beacon.module_scores["beaconing"] > 0.5

    # A row with no declared pattern has no history to judge.
    quiet = results["meadowgroup.test"]
    assert quiet.module_statuses["beaconing"] == STATUS_UNAVAILABLE


def test_an_unavailable_module_is_excluded_not_scored_zero():
    """The property that keeps a null result honest."""
    results = {r.domain: r for r in harness().run(("beaconing",))}
    quiet = results["meadowgroup.test"]

    assert "beaconing" not in quiet.module_scores, \
        "an unavailable module was recorded with a score"
    assert quiet.module_statuses["beaconing"] == STATUS_UNAVAILABLE


def test_a_newly_seen_row_reaches_the_domain_age_module():
    results = {r.domain: r for r in harness().run(("nrd",))}
    assert results["silverstudio.test"].module_scores["nrd"] > 0.5
    assert results["meadowgroup.test"].module_scores["nrd"] == 0.0


def test_the_dga_module_separates_generated_labels():
    results = {r.domain: r for r in harness().run(("dga",))}
    assert results["xkwqvbzmrtplfjdh.test"].module_scores["dga"] > 0.5
    assert results["meadowgroup.test"].module_scores["dga"] < 0.5


def test_the_typosquat_module_matches_the_configured_brands():
    results = {r.domain: r for r in harness().run(("typosquat",))}
    assert results["examplebrandlogin.test"].module_scores["typosquat"] > 0.5
    assert results["meadowgroup.test"].module_scores["typosquat"] == 0.0


def test_the_harness_is_deterministic():
    first = harness().run(ALL_MODULES)
    second = harness().run(ALL_MODULES)
    assert [(r.domain, r.verdict, r.score) for r in first] == \
        [(r.domain, r.verdict, r.score) for r in second]


def test_modules_run_in_canonical_order_regardless_of_request_order():
    """So an ablation arm cannot differ from another by ordering alone."""
    engine = harness().build_engine(("beaconing", "ti"))
    assert [m.name for m in engine.modules] == ["ti", "beaconing"]


def test_an_unknown_module_is_rejected():
    with pytest.raises(ValueError, match="unknown module"):
        harness().build_engine(("nope",))


def test_the_prediction_follows_the_systems_own_decision_rule():
    """Not a threshold invented for the report."""
    assert POSITIVE_VERDICTS == {"FLAG", "BLOCK"}
    for result in harness().run(ALL_MODULES):
        assert result.predicted == (1 if result.verdict in POSITIVE_VERDICTS
                                    else 0)


def test_the_fixture_history_respects_the_window():
    rows = small_rows()
    history = FixtureHistory(rows, FIXED_NOW)

    stamps, discarded = history.observations("harborworks.test",
                                             FIXED_NOW - 3600)
    assert len(stamps) == len(PATTERNS["periodic"])
    assert discarded == 0
    assert history.observations("harborworks.test", FIXED_NOW - 100)[0] != stamps


def test_the_fixture_history_is_empty_for_an_unknown_domain():
    assert FixtureHistory(small_rows(), FIXED_NOW).observations(
        "never.test", 0) == ([], 0)


# =========================================================================
# Ablation
# =========================================================================

def test_every_module_gets_an_individual_and_a_leave_one_out_arm():
    names = {name for name, _, _, _ in configurations()}
    for module in ALL_MODULES:
        assert f"only_{module}" in names
        assert f"without_{module}" in names
    assert {"baseline_all", "ti_only", "ml_only", "hybrid"} <= names


def test_leave_one_out_arms_omit_exactly_one_module():
    for name, family, modules, _note in configurations():
        if family == "leave_one_out":
            assert len(modules) == len(ALL_MODULES) - 1


def test_the_ti_arm_carries_its_circularity_warning():
    """Its precision is 1.0 by construction; that must be stated, not hidden."""
    note = next(n for name, _, _, n in configurations() if name == "only_ti")
    assert "by construction" in note


def test_the_ablation_produces_one_arm_per_configuration():
    arms = run_ablation(harness())
    assert len(arms) == len(configurations())
    assert all(0.0 <= a.metrics.f1 <= 1.0 for a in arms)


def test_the_ablation_records_module_availability_per_arm():
    """So a null result caused by a missing model is explicable."""
    arms = {a.name: a for a in run_ablation(harness())}
    statuses = arms["only_beaconing"].module_status["beaconing"]
    assert STATUS_UNAVAILABLE in statuses


def test_per_category_recall_separates_the_row_kinds():
    results = harness().run(ALL_MODULES)
    tally = per_category_recall(results)
    assert "benign" in tally and "dga" in tally
    for entry in tally.values():
        assert 0.0 <= entry["detected_fraction"] <= 1.0


def test_deltas_are_measured_against_the_full_configuration():
    arms = run_ablation(harness())
    deltas = deltas_against_baseline(arms)

    assert len(deltas) == len(ALL_MODULES)
    assert {d["removed_module"] for d in deltas} == set(ALL_MODULES)
    for row in deltas:
        assert row["delta_f1"] == pytest.approx(
            row["arm_f1"] - row["baseline_f1"], abs=1e-9)


def test_the_arm_serialises_for_the_report():
    arm = run_ablation(harness())[0]
    payload = arm.as_dict()
    assert payload["arm"] == "baseline_all"
    assert payload["modules"] == ",".join(ALL_MODULES)
    assert json.loads(json.dumps(payload))["module_count"] == 5


# =========================================================================
# Sweeps report; they never tune
# =========================================================================

def test_the_threshold_grid_includes_the_project_default():
    """The table must contain the baseline it is compared against."""
    assert (0.5, 0.8) in THRESHOLD_GRID


def test_the_threshold_sweep_marks_the_current_setting():
    rows = sweep_thresholds(harness(), ("ti", "nrd"))
    marked = [r for r in rows if r["is_project_default"]]
    assert len(marked) == 1
    assert (marked[0]["flag_at"], marked[0]["block_at"]) == (0.5, 0.8)


def test_the_threshold_sweep_reports_the_verdict_distribution():
    rows = sweep_thresholds(harness(), ("ti", "nrd"))
    for row in rows:
        counted = (row["verdict_allow"] + row["verdict_flag"]
                   + row["verdict_block"] + row["verdict_unknown"])
        assert counted == len(small_rows())


def test_the_weight_sweep_varies_one_module_at_a_time():
    rows = sweep_weights(harness(), ("ti", "nrd"))
    assert {r["varied_module"] for r in rows} == {"ti", "nrd"}
    assert len(rows) == 2 * len(WEIGHT_GRID)


def test_the_weight_sweep_records_the_project_default():
    rows = sweep_weights(harness(), ("ti",))
    defaults = [r for r in rows if r["is_project_default"]]
    assert len(defaults) == 1
    assert defaults[0]["weight"] == DEFAULT_WEIGHTS["ti"]


def test_no_sweep_mutates_the_project_defaults():
    """Stage 16 reports; it does not tune."""
    before = dict(DEFAULT_WEIGHTS)
    baseline = RiskAggregator()
    flag_before, block_before = baseline.flag_at, baseline.block_at

    sweep_thresholds(harness(), ("ti",))
    sweep_weights(harness(), ("ti",))

    assert dict(DEFAULT_WEIGHTS) == before, "DEFAULT_WEIGHTS was mutated"
    after = RiskAggregator()
    assert (after.flag_at, after.block_at) == (flag_before, block_before)
    assert after.weights == before


def test_the_ablation_does_not_mutate_the_project_defaults():
    before = dict(DEFAULT_WEIGHTS)
    run_ablation(harness())
    assert dict(DEFAULT_WEIGHTS) == before


def test_experiments_expose_no_best_configuration_helper():
    """Picking the top F1 on synthetic data is overfitting, not tuning."""
    import experiments.sweep as sweep_module

    assert not hasattr(sweep_module, "best")
    assert not hasattr(sweep_module, "best_configuration")


# =========================================================================
# Artifacts
# =========================================================================

@pytest.mark.slow
def test_the_entry_point_writes_every_artifact(tmp_path):
    result = subprocess.run(
        [sys.executable, "tools/run_experiments.py",
         "--dataset", str(DATASET), "--out", str(tmp_path)],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=1800)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]

    for name in ["ablation.csv", "ablation.json", "ablation_deltas.csv",
                 "sweep.csv", "sweep.json", "metadata.json"]:
        assert (tmp_path / name).is_file(), f"{name} was not written"

    with (tmp_path / "ablation.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(configurations())
    assert {"arm", "precision", "recall", "f1",
            "false_positive_rate"} <= set(rows[0])


@pytest.mark.slow
def test_the_metadata_pins_the_run_to_its_input(tmp_path):
    subprocess.run(
        [sys.executable, "tools/run_experiments.py", "--ablation-only",
         "--dataset", str(DATASET), "--out", str(tmp_path)],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=1800,
        check=True)

    metadata = json.loads((tmp_path / "metadata.json").read_text(
        encoding="utf-8"))
    assert metadata["dataset"]["sha256"] == dataset_checksum(DATASET)
    assert metadata["fixed_now"] == FIXED_NOW
    assert metadata["project_defaults_unchanged"] is True


@pytest.mark.slow
def test_the_caveat_travels_with_the_numbers(tmp_path):
    """It must live in the artifact, not only in a README."""
    subprocess.run(
        [sys.executable, "tools/run_experiments.py", "--ablation-only",
         "--dataset", str(DATASET), "--out", str(tmp_path)],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=1800,
        check=True)

    caveat = json.loads((tmp_path / "metadata.json").read_text(
        encoding="utf-8"))["caveat"]
    assert "SYNTHETIC" in caveat
    assert "NOT detection accuracy" in caveat
    assert "by construction" in caveat


@pytest.mark.slow
def test_two_runs_produce_identical_results(tmp_path):
    """Reproducible for anyone with the same repository."""
    command = [sys.executable, "tools/run_experiments.py", "--ablation-only",
               "--dataset", str(DATASET)]
    first, second = tmp_path / "one", tmp_path / "two"

    for out in (first, second):
        subprocess.run(command + ["--out", str(out)], cwd=str(REPO_ROOT),
                       capture_output=True, text=True, timeout=1800, check=True)

    assert (first / "ablation.csv").read_text(encoding="utf-8") == \
        (second / "ablation.csv").read_text(encoding="utf-8")


def test_an_output_directory_outside_the_repository_works(tmp_path):
    """Found by the artifact tests: --out may point anywhere.

    The run wrote every file and then crashed while printing the summary,
    because a path outside the repository has no relative form.
    """
    from tools.run_experiments import display

    inside = REPO_ROOT / "experiments" / "results" / "ablation.csv"
    assert not display(inside).startswith("/")
    assert display(Path("/tmp/elsewhere/ablation.csv")) == \
        "/tmp/elsewhere/ablation.csv"
