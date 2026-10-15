"""DGA feature set v2 and model selection.

v1 remains the default and the published model; v2 is chosen only by an
artifact whose recorded feature list is the v2 list.
"""

import json
from pathlib import Path

import pytest

from config.settings import Settings
from engine.modules.base import QueryContext
from engine.modules.dga import DGAModel, DGAModule, ModelUnavailable
from engine.modules.dga_features import (FEATURE_NAMES, FEATURE_NAMES_V2,
                                         extract_features, feature_set_for)

ROOT = Path(__file__).resolve().parent.parent
V1 = ROOT / "models/dga/dga_model.json"
V2 = ROOT / "models/dga/dga_model_v2.json"


def score(path, name):
    return DGAModule(str(path)).evaluate(
        QueryContext(qname=name, qtype="A", client_id="c", timestamp=0)).score


def test_v1_is_still_the_default_everywhere():
    assert Settings().dga_model_path == "models/dga/dga_model.json"
    assert DGAModule().model_path == "models/dga/dga_model.json"
    assert extract_features("mail.google.com")["label_count"] == 3.0


def test_v2_drops_label_count_and_nothing_else():
    assert FEATURE_NAMES_V2 == tuple(n for n in FEATURE_NAMES
                                     if n != "label_count")
    assert "label_count" not in extract_features("x.com", "v2")


@pytest.mark.parametrize("base", ["google.com", "bbc.co.uk", "wikipedia.org",
                                  "xk2qvz9pl3mwt8.com", "flybuysinfo.com"])
def test_v2_scores_do_not_depend_on_subdomain_depth(base):
    """Acceptance criterion C1."""
    scores = {score(V2, n) for n in (base, "www." + base, "a.b." + base)}
    assert len(scores) == 1


def test_v2_analyses_the_label_under_a_multi_label_suffix():
    assert extract_features("xk2qvz9pl3.co.uk", "v2")["length"] == 10.0
    assert extract_features("xk2qvz9pl3.co.uk", "v1")["length"] == 2.0  # "co"


def test_v2_analyses_the_customer_label_on_a_platform():
    assert (extract_features("my-shop.pages.dev", "v2")
            == extract_features("my-shop.com", "v2"))


def test_the_artifact_chooses_the_feature_set():
    assert DGAModel.load(str(V1)).feature_set == "v1"
    assert DGAModel.load(str(V2)).feature_set == "v2"
    assert feature_set_for(["length"]) is None


def test_an_artifact_with_an_unknown_feature_list_is_refused(tmp_path):
    artifact = json.loads(V2.read_text(encoding="utf-8"))
    artifact["feature_names"] = list(reversed(artifact["feature_names"]))
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    with pytest.raises(ModelUnavailable, match="do not match"):
        DGAModel.load(str(path))


def test_the_v1_artifact_reproduces_the_published_scores():
    """mail.google.com scored 0.83 under v1; the published model must not
    change, so this artefact stays pinned by a test."""
    assert score(V1, "mail.google.com") == pytest.approx(0.832508, abs=1e-6)


def test_v2_metadata_records_its_evaluation_basis():
    meta = json.loads((ROOT / "models/dga/dga_model_v2.meta.json")
                      .read_text(encoding="utf-8"))
    assert meta["feature_set"] == "v2"
    assert meta["metrics"]["f1"] >= 0.90                  # criterion C2
    assert meta["dataset"]["kind"] == "SYNTHETIC development fixture"
