"""Stage 15 tests: hybrid integration and explainable evidence.

Stage 15 adds no detector. It adds two things: a status that separates "this
module could not assess the query" from "this module broke", and a sentence
that renders the aggregation a person can read.

The sentence is the risky part. A summary is exactly the kind of artefact that
drifts away from the numbers it claims to describe, so most of what follows
checks that it cannot say anything the module results do not support — and
that when it disagrees with the contribution table, a test fails.
"""

import json
import time

import pytest

from config.settings import Settings
from engine.aggregator import RiskAggregator
from engine.decision import DecisionEngine
from engine.explain import ELEVATED_AT, FRIENDLY_NAMES, friendly, summarise
from engine.modules.base import (
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_INVALID,
    STATUS_OK,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    DetectionModule,
    ModuleResult,
    ModuleScore,
    ModuleUnavailable,
    QueryContext,
)
from engine.modules.null import FixedScoreModule
from proxy.packet import parse_query
from proxy.timing import Stopwatch
from tests.test_packet import make_query
from tests.conftest import auth_settings_kwargs, sign_in



def result(module, score, status=STATUS_OK, features=None):
    return ModuleResult(module, score, features or {}, 0.1, status)


def ctx(qname="checked.test"):
    return QueryContext(qname=qname, qtype="A", client_id="cid",
                        timestamp=time.time())


def decide(modules, qname="checked.test", **aggregator_kwargs):
    engine = DecisionEngine(modules,
                            aggregator=RiskAggregator(**aggregator_kwargs))
    return engine.decide(parse_query(make_query(qname)), Stopwatch())


# -- controlled modules ----------------------------------------------------

class Listed(DetectionModule):
    name = "ti"

    def evaluate(self, c):
        return ModuleScore(1.0, {"listed": True, "indicator": "checked.test",
                                 "feed": "controlled-fixture",
                                 "match_type": "exact"})


class Beacon(DetectionModule):
    name = "beaconing"

    def evaluate(self, c):
        return ModuleScore(0.98, {"observations": 12, "median_interval_s": 300.0,
                                  "coefficient_of_variation": 0.02})


class Squat(DetectionModule):
    name = "typosquat"

    def evaluate(self, c):
        return ModuleScore(0.75, {"matched_brand": "examplebrand",
                                  "signals": ["brand_with_keyword"]})


class Cannot(DetectionModule):
    """A module that reports it has nothing to go on."""

    name = "dga"

    def evaluate(self, c):
        raise ModuleUnavailable("no model artifact is loaded")


class Broken(DetectionModule):
    """A module with an actual bug."""

    name = "nrd"

    def evaluate(self, c):
        raise RuntimeError("index out of range")


# =========================================================================
# The unavailable status
# =========================================================================

def test_unavailable_is_distinct_from_error():
    """Stage 15's contract extension.

    Both are excluded from aggregation, so no arithmetic changed. What
    changed is that the evidence can now say which happened.
    """
    assert STATUS_UNAVAILABLE == "unavailable"
    assert STATUS_UNAVAILABLE != STATUS_ERROR


def test_a_module_that_cannot_assess_is_reported_as_unavailable():
    engine = DecisionEngine([Cannot()])
    outcome = engine.evaluate(ctx())[0]

    assert outcome.status == STATUS_UNAVAILABLE
    assert outcome.features["unavailable"] == "ModuleUnavailable"
    assert "no model artifact" in outcome.features["detail"]


def test_a_module_with_a_bug_is_still_reported_as_an_error():
    """The distinction is only useful if genuine faults stay visible."""
    outcome = DecisionEngine([Broken()]).evaluate(ctx())[0]

    assert outcome.status == STATUS_ERROR
    assert outcome.features["error"] == "RuntimeError"


def test_every_cannot_assess_exception_maps_to_unavailable():
    from engine.modules.beaconing import InsufficientObservations
    from engine.modules.dga import ModelUnavailable
    from engine.modules.ti import FeedUnavailable
    from engine.modules.typosquat import BrandsUnavailable

    for exception in (FeedUnavailable, ModelUnavailable, BrandsUnavailable,
                      InsufficientObservations):
        assert issubclass(exception, ModuleUnavailable), \
            f"{exception.__name__} would still be reported as an error"


@pytest.mark.parametrize("status", [STATUS_UNAVAILABLE, STATUS_ERROR,
                                    STATUS_INVALID, STATUS_SKIPPED,
                                    STATUS_DISABLED])
def test_no_excluded_status_contributes_to_the_score(status):
    """Unavailable must never become a clean score of zero."""
    assert result("x", 0.0, status).counts_toward_score is False


def test_an_unavailable_module_does_not_dilute_the_aggregate():
    decision = decide([Listed(), Cannot()])

    assert decision["score"] == 1.0, "an unavailable module diluted the score"
    assert decision["explanation"]["excluded"] == ["dga"]
    assert decision["explanation"]["counted_weight"] == 1.0


def test_all_modules_unavailable_gives_unknown_not_allow():
    decision = decide([Cannot()])
    assert decision["verdict"] == "UNKNOWN"


# =========================================================================
# Contribution accounting
# =========================================================================

def test_a_single_signal_reports_score_weight_and_contribution():
    decision = decide([Listed()])
    contributions = decision["explanation"]["contributions"]

    assert len(contributions) == 1
    entry = contributions[0]
    assert entry["module"] == "ti"
    assert entry["score"] == 1.0
    assert entry["weight"] == 1.0
    assert entry["weighted"] == 1.0
    assert entry["counted"] is True
    assert decision["score"] == 1.0


def test_every_module_appears_in_the_contribution_table():
    """Including the ones that contributed nothing."""
    decision = decide([Listed(), Squat(), Cannot(), Broken()])
    modules = [c["module"] for c in decision["explanation"]["contributions"]]

    assert modules == ["ti", "typosquat", "dga", "nrd"]
    by_name = {c["module"]: c for c in decision["explanation"]["contributions"]}
    assert by_name["dga"]["counted"] is False
    assert by_name["dga"]["status"] == STATUS_UNAVAILABLE
    assert by_name["nrd"]["status"] == STATUS_ERROR


def test_contributions_use_the_existing_aggregation_formula():
    """Stage 15 must not have changed any arithmetic."""
    decision = decide([Listed(), Squat()])
    explanation = decision["explanation"]

    weighted = sum(c["weighted"] for c in explanation["contributions"]
                   if c["counted"])
    counted_weight = sum(c["weight"] for c in explanation["contributions"]
                         if c["counted"])
    assert explanation["weighted_sum"] == pytest.approx(weighted)
    assert explanation["counted_weight"] == pytest.approx(counted_weight)
    assert decision["score"] == pytest.approx(weighted / counted_weight)


def test_the_unlisted_weight_policy_is_unchanged():
    """typosquat, dga and beaconing still take the fallback weight."""
    aggregator = RiskAggregator()
    assert aggregator.weight_for("ti") == 1.0
    assert aggregator.weight_for("nrd") == 0.4
    for unlisted in ("typosquat", "dga", "beaconing"):
        assert aggregator.weight_for(unlisted) == 0.5


def test_the_explanation_still_says_the_weights_are_untuned():
    assert decide([Listed()])["explanation"]["weights_are_tuned"] is False


# =========================================================================
# Multi-signal evidence is retained
# =========================================================================

def test_multiple_signals_are_kept_separate():
    """Never collapsed into one generic verdict."""
    decision = decide([Listed(), Squat(), Beacon()])

    evidence = {e["module"]: e for e in decision["evidence"]}
    assert set(evidence) == {"ti", "typosquat", "beaconing"}
    assert evidence["ti"]["features"]["indicator"] == "checked.test"
    assert evidence["typosquat"]["features"]["matched_brand"] == "examplebrand"
    assert evidence["beaconing"]["features"]["observations"] == 12


def test_each_module_keeps_its_own_feature_vocabulary():
    decision = decide([Listed(), Beacon()])
    evidence = {e["module"]: e["features"] for e in decision["evidence"]}

    assert "match_type" in evidence["ti"]
    assert "match_type" not in evidence["beaconing"]
    assert "coefficient_of_variation" in evidence["beaconing"]


# =========================================================================
# The human-readable summary
# =========================================================================

def test_every_decision_carries_a_summary():
    decision = decide([Listed()])
    assert "summary" in decision["explanation"]
    assert decision["explanation"]["summary"].endswith(".")


def test_the_summary_names_the_signals_that_drove_a_block():
    summary = decide([Listed(), Beacon()])["explanation"]["summary"]

    assert summary.startswith("Blocked because")
    assert "threat intelligence" in summary
    assert "query periodicity" in summary
    assert "checked.test" in summary, "the matched indicator is not quoted"


def test_the_summary_quotes_real_evidence_not_a_generic_phrase():
    """'High risk.' is not an explanation."""
    summary = decide([Beacon()])["explanation"]["summary"]

    assert "12 queries" in summary
    assert "300s apart" in summary
    assert summary.strip() not in {"High risk.", "Blocked.", "Flagged."}


def test_the_summary_explains_a_clean_decision():
    summary = decide([FixedScoreModule("ti", 0.0),
                      FixedScoreModule("nrd", 0.0)])["explanation"]["summary"]

    assert summary.startswith("Allowed because no usable signal was elevated")
    assert "2 modules ran" in summary


def test_the_summary_explains_a_flag():
    decision = decide([FixedScoreModule("ti", 0.6)])
    assert decision["verdict"] == "FLAG"
    summary = decision["explanation"]["summary"]

    assert summary.startswith("Flagged because")
    assert "flag threshold" in summary


def test_the_summary_reports_an_unavailable_module_separately():
    summary = decide([Listed(), Cannot()])["explanation"]["summary"]

    assert "could not assess this query" in summary
    assert "did not contribute" in summary


def test_the_summary_reports_a_failed_module_separately():
    summary = decide([Listed(), Broken()])["explanation"]["summary"]
    assert "failed" in summary


def test_the_summary_when_nothing_could_be_assessed():
    summary = decide([Cannot()])["explanation"]["summary"]

    assert summary.startswith("No verdict could be reached")
    assert "no signal contributed" in summary


def test_the_summary_when_no_modules_are_configured():
    summary = decide([])["explanation"]["summary"]
    assert "No detection modules are configured" in summary


def test_the_summary_agrees_with_the_contribution_table():
    """If these ever disagree, the table is right and the summary is broken."""
    decision = decide([Listed(), Squat(), Cannot()])
    explanation = decision["explanation"]
    summary = explanation["summary"]

    counted = [c for c in explanation["contributions"] if c["counted"]]
    elevated = [c for c in counted if c["score"] >= ELEVATED_AT]

    assert f"{len(elevated)} of {len(counted)} usable signal" in summary
    assert f"{explanation['aggregate_score']:.2f}" in summary


def test_the_summary_never_names_a_module_that_did_not_fire():
    summary = decide([Listed(), FixedScoreModule("nrd", 0.0)])[
        "explanation"]["summary"]

    assert "threat intelligence" in summary
    assert "domain age" not in summary, \
        "a module that scored zero was named as a reason"


def test_the_summary_is_deterministic():
    first = decide([Listed(), Beacon()])["explanation"]["summary"]
    second = decide([Listed(), Beacon()])["explanation"]["summary"]
    assert first == second


def test_the_summary_makes_no_claim_of_maliciousness():
    """It renders evidence; it does not diagnose."""
    summary = decide([Listed(), Beacon(), Squat()])["explanation"]["summary"]
    for word in ["malicious", "malware", "infected", "confirmed", "c2"]:
        assert word not in summary.lower()


def test_summarise_reads_only_the_results_it_is_given():
    """It has no other input, so it cannot invent a signal."""
    aggregation = {"policy_verdict": "ALLOW", "aggregate_score": 0.0,
                   "thresholds": {"flag_at": 0.5, "block_at": 0.8}}
    assert "threat intelligence" not in summarise([], aggregation)


def test_friendly_names_fall_back_to_the_module_identifier():
    assert friendly("ti") == "threat intelligence"
    assert friendly("a-module-added-later") == "a-module-added-later"
    assert set(FRIENDLY_NAMES) >= {"ti", "nrd", "typosquat", "dga", "beaconing"}


# =========================================================================
# Enforcement remains separate from detection
# =========================================================================

def test_the_decision_still_separates_policy_from_enforcement():
    decision = decide([Listed()])

    assert decision["verdict"] == "BLOCK"
    assert decision["enforcement"]["would_block"] is True
    assert decision["enforcement"]["applied"] is False
    assert decision["enforcement"]["action"] == "forward"


def test_enforcement_does_not_change_the_summary():
    observing = decide([Listed()], enforce=False)["explanation"]["summary"]
    enforcing = decide([Listed()], enforce=True)["explanation"]["summary"]
    assert observing == enforcing, "the summary described enforcement, not risk"


# =========================================================================
# Persistence and the API
# =========================================================================

def test_the_summary_survives_persistence(tmp_path):
    from storage.db import Database
    from storage.models import QueryRecord

    decision = decide([Listed(), Beacon(), Cannot()])
    database = Database(str(tmp_path / "s15.sqlite3"))
    try:
        database.insert_record(QueryRecord.from_log_payload({
            "client": "192.0.2.1", "qname": "checked.test", "qtype": "A",
            "verdict": decision["verdict"], "rcode": "NOERROR",
            "score": decision["score"], "engine": "engine[test]",
            "evidence": decision["evidence"],
            "explanation": decision["explanation"],
            "latency_ms": {"total": 1.0}, "added_latency_ms": 0.1,
        }, "salt"))

        row = database.recent_queries()[0]
        stored = json.loads(row["explanation_json"])
        assert stored["summary"] == decision["explanation"]["summary"]
        assert len(stored["contributions"]) == 3

        evidence = database.evidence_for_query(row["id"])
        assert {e["module"] for e in evidence} == {"ti", "beaconing", "dga"}
        assert {e["status"] for e in evidence} == {"ok", "unavailable"}
    finally:
        database.close()


def test_no_schema_change_was_needed(tmp_path):
    """The summary rides inside the existing explanation_json column."""
    from storage.db import Database, SCHEMA_VERSION

    database = Database(str(tmp_path / "v.sqlite3"))
    try:
        assert database.schema_version == SCHEMA_VERSION == 2
    finally:
        database.close()


def test_the_api_exposes_the_summary_and_the_contributions(tmp_path,
                                                           monkeypatch):
    from fastapi.testclient import TestClient

    import api.main as api_main
    from api.repository import DecisionRepository
    from storage.db import Database
    from storage.models import QueryRecord

    decision = decide([Listed(), Beacon(), Cannot()])
    db_path = str(tmp_path / "api15.sqlite3")
    database = Database(db_path)
    try:
        database.insert_record(QueryRecord.from_log_payload({
            "client": "192.0.2.1", "qname": "checked.test", "qtype": "A",
            "verdict": decision["verdict"], "rcode": "NXDOMAIN",
            "score": decision["score"], "engine": "engine[test]",
            "evidence": decision["evidence"],
            "explanation": decision["explanation"],
            "latency_ms": {"total": 1.0}, "added_latency_ms": 0.1,
        }, "salt"))
    finally:
        database.close()

    monkeypatch.setattr(api_main, "repository", DecisionRepository(db_path))
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_path=db_path, engine_modules="null",
                                 db_enabled=False, **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    client = sign_in(TestClient(api_main.app))

    body = client.get("/decisions/1/evidence").json()
    assert body["explanation"]["summary"] == decision["explanation"]["summary"]
    assert len(body["explanation"]["contributions"]) == 3
    assert {m["module"] for m in body["modules"]} == {"ti", "beaconing", "dga"}

    unavailable = [m for m in body["modules"] if m["status"] == "unavailable"]
    assert len(unavailable) == 1
    assert unavailable[0]["module"] == "dga"


def test_the_existing_endpoints_still_answer(tmp_path, monkeypatch):
    """Stage 15 extended responses; it must not have broken any."""
    from fastapi.testclient import TestClient

    import api.main as api_main
    from api.repository import DecisionRepository
    from storage.db import Database

    db_path = str(tmp_path / "compat.sqlite3")
    Database(db_path).close()
    monkeypatch.setattr(api_main, "repository", DecisionRepository(db_path))
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_path=db_path, engine_modules="null",
                                 db_enabled=False, **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    client = sign_in(TestClient(api_main.app))

    assert client.get("/health").status_code == 200
    assert client.get("/decisions").status_code == 200
    assert client.get("/stats").status_code == 200
    assert client.get("/mode").status_code == 200
    assert client.put("/mode", json={"enforce": False}).status_code == 200
    assert client.post("/lookup",
                       json={"domain": "example.com"}).status_code == 200


def test_lookup_returns_the_summary(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import api.main as api_main

    monkeypatch.setattr(api_main, "settings",
                        Settings(db_enabled=False, engine_modules="null", **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)

    body = sign_in(TestClient(api_main.app)).post(
        "/lookup", json={"domain": "example.com"}).json()
    assert "summary" in body["explanation"]


def test_an_elevated_signal_on_an_allowed_query_says_despite_not_because():
    """Found in live testing.

    "Allowed because domain age has never seen this domain" is a
    contradiction: the signal fired and the query was allowed anyway,
    because its weighted share never reached the threshold.
    """
    decision = decide([FixedScoreModule("ti", 0.0),
                       FixedScoreModule("nrd", 1.0)])
    summary = decision["explanation"]["summary"]

    assert decision["verdict"] == "ALLOW"
    assert summary.startswith("Allowed despite")
    assert "Allowed because" not in summary
    assert "below the flag threshold" in summary


def test_a_block_still_reads_as_because():
    assert decide([Listed()])["explanation"]["summary"].startswith(
        "Blocked because")
