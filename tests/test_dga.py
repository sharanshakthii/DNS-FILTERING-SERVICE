"""Stage 13 tests: the DGA detection pipeline.

Covers the whole chain — features, dataset, training, artifact, inference,
evidence, aggregation — with the training step skipped when scikit-learn is
absent, since it is a training-only dependency and the committed artifact
means nothing else needs it.

The tests that matter most are the ones about honesty: that a missing model is
an error rather than a score of zero, that the exported artifact reproduces
what scikit-learn actually fitted, and that the evidence never calls the score
a probability of maliciousness.
"""

import json
import math
import subprocess
import sys
import time
from pathlib import Path

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
from engine.modules.dga import (
    DEFAULT_MODEL_PATH,
    DGAModel,
    DGAModule,
    ModelUnavailable,
)
from engine.modules.dga_features import (
    FEATURE_NAMES,
    extract_features,
    feature_vector,
    longest_run,
    registrable_label,
    shannon_entropy,
)
from engine.modules.null import FixedScoreModule
from proxy.dns_proxy import build_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET = REPO_ROOT / "datasets" / "dga_dev.csv"
ARTIFACT = REPO_ROOT / "models" / "dga" / "dga_model.json"
METADATA = REPO_ROOT / "models" / "dga" / "dga_model.meta.json"

BENIGN = ["google.com", "bluegarden.com", "coffee-labs.io", "example.org"]
DGA_LIKE = ["kq3xvbnz7wplmr.com", "xkwqvbzmrtplfjdh.org", "a1b2c3d4e5f6g7h8.net"]


def ctx(qname: str) -> QueryContext:
    return QueryContext(qname=qname, qtype="A", client_id="cid",
                        timestamp=time.time())


# =========================================================================
# Feature extraction
# =========================================================================

def test_features_for_an_ordinary_domain():
    features = extract_features("google.com")
    assert features["length"] == 6.0
    assert features["digit_ratio"] == 0.0
    assert features["vowel_ratio"] == pytest.approx(3 / 6)   # o, o, e
    assert features["hyphen_count"] == 0.0
    assert features["label_count"] == 2.0


def test_features_for_a_random_looking_label():
    """The vector must separate on the properties it was designed around."""
    random_like = extract_features("xkwqvbzmrtplfjdh.com")
    ordinary = extract_features("bluegarden.com")

    assert random_like["vowel_ratio"] < ordinary["vowel_ratio"]
    assert random_like["max_consonant_run"] > ordinary["max_consonant_run"]
    assert random_like["entropy"] > ordinary["entropy"]


@pytest.mark.parametrize("qname,expected", [
    ("abc123.com", 0.5),
    ("abcdef.com", 0.0),
    ("123456.com", 1.0),
])
def test_digit_ratio(qname, expected):
    assert extract_features(qname)["digit_ratio"] == pytest.approx(expected)


@pytest.mark.parametrize("qname,expected", [
    ("aeiou.com", 1.0),
    ("bcdfg.com", 0.0),
    ("abcd.com", 0.25),
])
def test_vowel_ratio(qname, expected):
    assert extract_features(qname)["vowel_ratio"] == pytest.approx(expected)


def test_entropy_is_zero_for_a_repeated_character():
    assert shannon_entropy("aaaa") == 0.0


def test_entropy_is_maximal_for_all_distinct_characters():
    assert shannon_entropy("abcd") == pytest.approx(2.0)   # log2(4)


def test_entropy_of_an_empty_string():
    assert shannon_entropy("") == 0.0


@pytest.mark.parametrize("qname,expected", [
    ("abcd.com", 1.0),           # 4 distinct / 4
    ("aabb.com", 0.5),
    ("aaaa.com", 0.25),
])
def test_unique_character_ratio(qname, expected):
    assert extract_features(qname)["unique_char_ratio"] == pytest.approx(expected)


def test_longest_consonant_run():
    from engine.modules.dga_features import CONSONANTS

    assert longest_run("abcdfge", CONSONANTS) == 5     # bcdfg
    assert longest_run("aeiou", CONSONANTS) == 0
    assert longest_run("", CONSONANTS) == 0


def test_longest_digit_run():
    assert extract_features("ab123cd45.com")["max_digit_run"] == 3.0


@pytest.mark.parametrize("qname", ["", "   ", ".", "..", None])
def test_malformed_input_yields_a_zero_vector_without_raising(qname):
    """This runs on the DNS query path; an exception there is an outage."""
    features = extract_features(qname)
    assert set(features) == set(FEATURE_NAMES)
    assert all(value == 0.0 for value in features.values())


@pytest.mark.parametrize("qname", [
    "GOOGLE.COM", "Google.Com", "google.com.", "  google.com  ",
])
def test_case_and_whitespace_are_normalised(qname):
    assert extract_features(qname) == extract_features("google.com")


def test_the_registrable_label_is_analysed_not_the_whole_name():
    """The TLD is not chosen by the generator and the subdomain often is not."""
    assert registrable_label("mail.google.com") == ("google", 3)
    assert registrable_label("google.com") == ("google", 2)
    assert registrable_label("localhost") == ("localhost", 1)


def test_the_vector_matches_the_declared_order():
    vector = feature_vector("google.com")
    features = extract_features("google.com")
    assert len(vector) == len(FEATURE_NAMES)
    assert vector == [features[name] for name in FEATURE_NAMES]


def test_features_are_deterministic():
    assert extract_features("kq3xvbnz.com") == extract_features("kq3xvbnz.com")


# =========================================================================
# Dataset
# =========================================================================

def test_the_dataset_exists():
    assert DATASET.is_file(), (
        f"no dataset at {DATASET}; generate it with "
        f"python tools/make_dga_dataset.py")


def test_the_dataset_has_the_expected_columns_and_valid_labels():
    import csv

    with DATASET.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == ["domain", "label"]
        rows = list(reader)

    assert rows, "the dataset is empty"
    for number, row in enumerate(rows, start=2):
        assert row["domain"].strip(), f"row {number} has an empty domain"
        assert row["label"] in {"0", "1"}, \
            f"row {number} has label {row['label']!r}"


def test_the_dataset_contains_both_classes_and_no_duplicates():
    import csv

    with DATASET.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    labels = [row["label"] for row in rows]
    assert labels.count("0") > 0 and labels.count("1") > 0

    domains = [row["domain"] for row in rows]
    assert len(domains) == len(set(domains)), "the dataset contains duplicates"


def test_the_dataset_generator_is_deterministic():
    """Regenerating must produce a byte-identical file on any machine."""
    from tools.make_dga_dataset import build

    assert build(50, seed=20260904) == build(50, seed=20260904)
    assert build(50, seed=1) != build(50, seed=2)


def test_the_generator_produces_balanced_classes():
    from tools.make_dga_dataset import build

    rows = build(40, seed=20260904)
    assert sum(1 for _, label in rows if label == 0) == 40
    assert sum(1 for _, label in rows if label == 1) == 40


def test_the_dataset_is_labelled_synthetic_in_its_metadata():
    """It must never be mistaken for a corpus of real malware domains."""
    metadata = json.loads(METADATA.read_text(encoding="utf-8"))
    assert "SYNTHETIC" in metadata["dataset"]["kind"].upper()


# =========================================================================
# Model artifact
# =========================================================================

def test_the_artifact_exists_and_is_small():
    assert ARTIFACT.is_file(), (
        f"no artifact at {ARTIFACT}; train one with "
        f"python tools/train_dga.py")
    assert ARTIFACT.stat().st_size < 50_000, "the artifact is unexpectedly large"


def test_the_artifact_loads():
    model = DGAModel.load(str(ARTIFACT))
    assert model.model_name == "logistic_regression"
    assert model.feature_names == FEATURE_NAMES
    assert len(model.coefficients) == len(FEATURE_NAMES)


def test_the_metadata_records_what_is_needed_to_reproduce_training():
    metadata = json.loads(METADATA.read_text(encoding="utf-8"))
    for key in ["model", "library", "random_seed", "feature_names", "dataset",
                "split", "metrics", "caveat"]:
        assert key in metadata, f"metadata is missing {key!r}"

    assert metadata["split"]["stratified"] is True
    assert metadata["dataset"]["rows"] == (metadata["split"]["train_rows"]
                                           + metadata["split"]["test_rows"])


def test_the_metadata_reports_real_measured_metrics():
    metrics = json.loads(METADATA.read_text(encoding="utf-8"))["metrics"]
    for key in ["accuracy", "precision", "recall", "f1", "confusion_matrix"]:
        assert key in metrics

    matrix = metrics["confusion_matrix"]
    assert sum(matrix.values()) > 0
    for key in ["accuracy", "precision", "recall", "f1"]:
        assert 0.0 <= metrics[key] <= 1.0


def test_the_metadata_states_the_metrics_are_not_an_evaluation():
    """Guards against the report quoting these as detection performance."""
    caveat = json.loads(METADATA.read_text(encoding="utf-8"))["caveat"]
    assert "SYNTHETIC" in caveat
    assert "NOT an evaluation" in caveat


def test_a_mismatched_feature_list_is_rejected():
    """A reordered vector would produce confident nonsense, not an error."""
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    artifact["feature_names"] = list(reversed(artifact["feature_names"]))
    with pytest.raises(ModelUnavailable, match="do not match"):
        DGAModel(artifact)


def test_an_unsupported_artifact_version_is_rejected():
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    artifact["artifact_version"] = 99
    with pytest.raises(ModelUnavailable, match="not supported"):
        DGAModel(artifact)


@pytest.mark.parametrize("removed", ["coefficients", "intercept",
                                     "scaler_mean", "scaler_scale"])
def test_a_malformed_artifact_is_rejected(removed):
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    del artifact[removed]
    with pytest.raises(ModelUnavailable, match="malformed"):
        DGAModel(artifact)


def test_a_zero_scaler_scale_is_rejected():
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    artifact["scaler_scale"][0] = 0.0
    with pytest.raises(ModelUnavailable, match="zero scaler scale"):
        DGAModel(artifact)


def test_a_missing_artifact_file_raises(tmp_path):
    with pytest.raises(ModelUnavailable, match="no model artifact"):
        DGAModel.load(str(tmp_path / "absent.json"))


def test_an_unreadable_artifact_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("this is not json", encoding="utf-8")
    with pytest.raises(ModelUnavailable, match="cannot read"):
        DGAModel.load(str(bad))


# =========================================================================
# Inference
# =========================================================================

def test_inference_is_deterministic():
    model = DGAModel.load(str(ARTIFACT))
    features = extract_features("kq3xvbnz7wplmr.com")
    assert model.probability(features) == model.probability(features)


@pytest.mark.parametrize("qname", BENIGN + DGA_LIKE + [
    "a.com", "x" * 60 + ".com", "0.com", "-.com",
])
def test_the_probability_is_always_within_range(qname):
    model = DGAModel.load(str(ARTIFACT))
    probability = model.probability(extract_features(qname))
    assert 0.0 <= probability <= 1.0
    assert not math.isnan(probability)


def test_extreme_inputs_do_not_overflow():
    """The sigmoid is guarded; an extreme vector saturates rather than raising."""
    model = DGAModel.load(str(ARTIFACT))
    absurd = {name: 1e12 for name in FEATURE_NAMES}
    assert 0.0 <= model.probability(absurd) <= 1.0


def test_top_contributions_explain_the_score():
    """Available because the model is linear; a forest could not do this."""
    model = DGAModel.load(str(ARTIFACT))
    contributions = model.top_contributions(
        extract_features("xkwqvbzmrtplfjdh.com"))

    assert len(contributions) == 3
    assert {"feature", "value", "contribution"} == set(contributions[0])
    magnitudes = [abs(c["contribution"]) for c in contributions]
    assert magnitudes == sorted(magnitudes, reverse=True)


# =========================================================================
# The module
# =========================================================================

def module() -> DGAModule:
    return DGAModule(model_path=str(ARTIFACT))


@pytest.mark.parametrize("qname", BENIGN)
def test_benign_looking_domains_score_low(qname):
    assert module().evaluate(ctx(qname)).score < 0.5


@pytest.mark.parametrize("qname", DGA_LIKE)
def test_random_looking_domains_score_high(qname):
    assert module().evaluate(ctx(qname)).score > 0.5


def test_a_dga_like_domain_scores_above_a_benign_one():
    assert (module().evaluate(ctx("xkwqvbzmrtplfjdh.com")).score
            > module().evaluate(ctx("bluegarden.com")).score)


@pytest.mark.parametrize("qname", ["", "   ", "."])
def test_an_unusable_name_is_reported_not_scored(qname):
    result = module().evaluate(ctx(qname))
    assert result.score == 0.0
    assert result.features["scored"] is False
    assert "no usable label" in result.features["reason"]


def test_a_missing_model_raises_rather_than_scoring_zero(tmp_path):
    """Zero means 'the model said benign'; no model means nothing ran."""
    with pytest.raises(ModelUnavailable):
        DGAModule(model_path=str(tmp_path / "absent.json")).evaluate(
            ctx("example.com"))


def test_the_engine_records_a_missing_model_as_unavailable(tmp_path):
    """Stage 15: a missing artifact is "cannot assess", not a crash."""
    engine = DecisionEngine([DGAModule(model_path=str(tmp_path / "absent.json"))])
    result = engine.evaluate(ctx("example.com"))[0]

    assert result.status == STATUS_UNAVAILABLE
    assert result.features["unavailable"] == "ModelUnavailable"
    assert result.counts_toward_score is False


def test_a_missing_model_does_not_stop_other_modules(tmp_path):
    engine = DecisionEngine([
        DGAModule(model_path=str(tmp_path / "absent.json")),
        FixedScoreModule("ti", 1.0)])
    results = engine.evaluate(ctx("example.com"))

    assert results[0].status == STATUS_UNAVAILABLE
    assert results[1].status == STATUS_OK
    assert engine.aggregator.aggregate(results)["score"] == 1.0


def test_the_threshold_labels_the_score_without_changing_it():
    """Changing the threshold must not silently alter a risk score."""
    low = DGAModule(model_path=str(ARTIFACT), threshold=0.1)
    high = DGAModule(model_path=str(ARTIFACT), threshold=0.99)

    # A name whose score falls between the two thresholds, so the label
    # differs while the score cannot.
    a = low.evaluate(ctx("quartzlabs.net"))
    b = high.evaluate(ctx("quartzlabs.net"))
    assert 0.1 < a.score < 0.99, f"the fixture no longer straddles the thresholds: {a.score}"
    assert a.score == b.score
    assert a.features["verdict_hint"] != b.features["verdict_hint"]


def test_an_out_of_range_threshold_is_rejected():
    with pytest.raises(ValueError, match="within"):
        DGAModule(threshold=1.5)


def test_the_model_is_loaded_once_not_per_query():
    """Training or loading per query would dominate the latency measurement."""
    instance = module()
    instance.evaluate(ctx("example.com"))
    first = instance._model
    instance.evaluate(ctx("other.com"))
    assert instance._model is first


def test_constructing_the_module_does_not_touch_the_disk(tmp_path):
    """A missing artifact must not stop the proxy booting."""
    built = DGAModule(model_path=str(tmp_path / "absent.json"))
    assert built._model is None


# =========================================================================
# Evidence
# =========================================================================

def test_the_evidence_contains_the_documented_fields():
    features = module().evaluate(ctx("kq3xvbnz7wplmr.com")).features
    for key in ["model", "artifact", "artifact_version", "qname", "scored",
                "dga_score", "threshold", "verdict_hint", "feature_names",
                "feature_values", "top_contributions", "reason"]:
        assert key in features, f"evidence is missing {key!r}"

    assert features["model"] == "logistic_regression"
    assert set(features["feature_values"]) == set(FEATURE_NAMES)


def test_the_evidence_calls_the_score_a_dga_likelihood_not_maliciousness():
    """The wording is deliberate and the report must keep it."""
    reason = module().evaluate(ctx("kq3xvbnz7wplmr.com")).features["reason"]
    assert "DGA likelihood" in reason
    assert "not whether the domain is malicious" in reason
    assert "probability of malicious" not in reason.lower()


def test_the_evidence_is_json_serialisable():
    from storage.models import EvidenceRow

    result = module().evaluate(ctx("kq3xvbnz7wplmr.com"))
    row = EvidenceRow.from_payload({
        "module": "dga", "score": result.score, "features": result.features,
        "latency_ms": 0.1, "status": "ok"})
    restored = json.loads(row.features_json())
    assert restored["model"] == "logistic_regression"
    assert "_unserialisable" not in restored


# =========================================================================
# Registration and configuration
# =========================================================================

def test_the_module_is_registered():
    assert REGISTRY["dga"] is DGAModule
    assert DGAModule.name == "dga"


def test_the_module_builds_through_the_startup_path():
    engine = build_engine(Settings(engine_modules="dga", db_enabled=False))
    try:
        assert engine.name == "engine[dga]"
        assert engine.modules[0].model_path == DEFAULT_MODEL_PATH
    finally:
        engine.close()


def test_the_module_works_on_its_own():
    engine = build_engine(Settings(engine_modules="dga", db_enabled=False,
                                   dga_model_path=str(ARTIFACT)))
    try:
        result = engine.evaluate(ctx("xkwqvbzmrtplfjdh.com"))[0]
        assert result.status == STATUS_OK
        assert result.score > 0.5
    finally:
        engine.close()


def test_settings_expose_the_model_path_and_threshold():
    assert Settings().dga_model_path == DEFAULT_MODEL_PATH
    assert Settings().dga_threshold == 0.5

    built = DGAModule.from_settings(
        Settings(dga_model_path="/tmp/x.json", dga_threshold=0.7))
    assert built.model_path == "/tmp/x.json"
    assert built.threshold == 0.7


def test_dga_takes_the_default_weight():
    """Left out of DEFAULT_WEIGHTS: Stage 13 has no evidence to justify one."""
    from engine.aggregator import DEFAULT_WEIGHTS, RiskAggregator

    assert "dga" not in DEFAULT_WEIGHTS
    assert RiskAggregator().weight_for("dga") == 0.5


# =========================================================================
# Integration with the other modules
# =========================================================================

def test_dga_and_ti_aggregate_together():
    engine = DecisionEngine([FixedScoreModule("ti", 1.0), module()])
    results = engine.evaluate(ctx("bluegarden.com"))

    assert [r.module for r in results] == ["ti", "dga"]
    assert all(r.status == STATUS_OK for r in results)
    assert engine.aggregator.aggregate(results)["explanation"][
        "counted_weight"] == 1.5


def test_dga_and_nrd_aggregate_together():
    from feeds.first_seen import FirstSeenStore
    from engine.modules.nrd import NewDomainModule

    now = time.time()
    nrd = NewDomainModule(first_seen=FirstSeenStore(started_at=now - 60 * 86400))
    engine = DecisionEngine([nrd, module()])
    results = engine.evaluate(QueryContext("xkwqvbzmrtplfjdh.com", "A", "c", now))

    assert [r.module for r in results] == ["nrd", "dga"]
    assert all(r.status == STATUS_OK for r in results)


def test_dga_and_typosquat_aggregate_together():
    from engine.modules.typosquat import TyposquatModule

    typo = TyposquatModule(brands=["spotify"], official_domains=["spotify.com"])
    engine = DecisionEngine([typo, module()])
    results = engine.evaluate(ctx("spotifyapk.com"))

    assert [r.module for r in results] == ["typosquat", "dga"]
    assert all(r.status == STATUS_OK for r in results)


def test_all_four_modules_run_together():
    from feeds.base import FeedSnapshot
    from feeds.cache import IndicatorCache
    from feeds.first_seen import FirstSeenStore
    from engine.modules.nrd import NewDomainModule
    from engine.modules.ti import ThreatIntelModule
    from engine.modules.typosquat import TyposquatModule

    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"xkwqvbzmrtplfjdh.com"}))
    now = time.time()

    engine = DecisionEngine([
        ThreatIntelModule(cache),
        NewDomainModule(first_seen=FirstSeenStore(started_at=now - 60 * 86400)),
        TyposquatModule(brands=["spotify"]),
        module(),
    ])
    results = engine.evaluate(QueryContext("xkwqvbzmrtplfjdh.com", "A", "c", now))

    assert [r.module for r in results] == ["ti", "nrd", "typosquat", "dga"]
    assert all(r.status == STATUS_OK for r in results)

    aggregated = engine.aggregator.aggregate(results)
    assert 0.0 <= aggregated["score"] <= 1.0
    assert aggregated["explanation"]["counted_weight"] == pytest.approx(
        1.0 + 0.4 + 0.5 + 0.5)


def test_disabling_dga_restores_the_previous_aggregate():
    engine = DecisionEngine([FixedScoreModule("ti", 1.0), module()])
    engine.set_enabled("dga", False)

    aggregated = engine.aggregator.aggregate(engine.evaluate(ctx("a.com")))
    assert aggregated["score"] == 1.0
    assert aggregated["explanation"]["excluded"] == ["dga"]


# =========================================================================
# The training pipeline itself
# =========================================================================

def test_the_trainer_rejects_an_invalid_label(tmp_path):
    from tools.train_dga import load_dataset

    bad = tmp_path / "bad.csv"
    bad.write_text("domain,label\nexample.com,2\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="label must be 0 or 1"):
        load_dataset(bad)


def test_the_trainer_rejects_a_single_class_dataset(tmp_path):
    from tools.train_dga import load_dataset

    bad = tmp_path / "one.csv"
    bad.write_text("domain,label\na.com,0\nb.com,0\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="only one class"):
        load_dataset(bad)


def test_the_trainer_rejects_wrong_columns(tmp_path):
    from tools.train_dga import load_dataset

    bad = tmp_path / "cols.csv"
    bad.write_text("name,klass\na.com,0\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="expected columns"):
        load_dataset(bad)


def test_the_trainer_reports_a_missing_dataset(tmp_path):
    from tools.train_dga import load_dataset

    with pytest.raises(SystemExit, match="dataset not found"):
        load_dataset(tmp_path / "absent.csv")


@pytest.mark.slow
def test_training_is_reproducible_and_produces_a_working_artifact(tmp_path):
    """The whole pipeline, end to end.

    Skipped when scikit-learn is absent: it is a training-only dependency and
    the committed artifact means nothing else needs it.
    """
    pytest.importorskip("sklearn",
                        reason="training needs requirements-train.txt")

    out = tmp_path / "model"
    command = [sys.executable, "tools/train_dga.py",
               "--dataset", str(DATASET), "--out", str(out)]
    first = subprocess.run(command, cwd=str(REPO_ROOT), capture_output=True,
                           text=True, timeout=600)
    assert first.returncode == 0, first.stdout + first.stderr

    artifact = out / "dga_model.json"
    assert artifact.is_file(), "training produced no artifact"
    assert (out / "dga_model.meta.json").is_file()

    # A fixed seed must give a byte-identical model on a second run.
    body = artifact.read_text(encoding="utf-8")
    second = subprocess.run(command, cwd=str(REPO_ROOT), capture_output=True,
                            text=True, timeout=600)
    assert second.returncode == 0
    assert artifact.read_text(encoding="utf-8") == body, \
        "training is not reproducible with a fixed seed"

    # And the freshly trained artifact must load and score.
    trained = DGAModel.load(str(artifact))
    assert trained.probability(extract_features("xkwqvbzmrtplfjdh.com")) > 0.5


@pytest.mark.slow
def test_the_exported_artifact_matches_scikit_learn(tmp_path):
    """The trainer asserts this before writing; this proves the check runs."""
    pytest.importorskip("sklearn",
                        reason="training needs requirements-train.txt")

    result = subprocess.run(
        [sys.executable, "tools/train_dga.py", "--dataset", str(DATASET),
         "--out", str(tmp_path / "m")],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=600)

    assert result.returncode == 0
    assert "export check" in result.stdout
