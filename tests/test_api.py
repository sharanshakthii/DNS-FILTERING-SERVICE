"""Stage 10 tests: the FastAPI layer.

Every test runs against a real SQLite database built by the project's own
`storage` write path, so what the API returns is provably what the DNS proxy
would have stored. No fixture hand-writes a response body, and nothing here
touches the network.
"""

import json

import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from api.repository import DatabaseUnavailable, DecisionRepository
from config.settings import Settings
from storage.db import Database
from storage.models import QueryRecord
from tests.conftest import auth_settings_kwargs, sign_in



def payload(qname="example.com", verdict="BLOCK", rcode="NXDOMAIN", score=1.0,
            client="192.0.2.10", evidence=None, explanation=None, **over):
    """A decision payload in exactly the shape the proxy emits."""
    base = {
        "client": client,
        "qname": qname,
        "qtype": "A",
        "verdict": verdict,
        "rcode": rcode,
        "score": score,
        "engine": "engine[ti]",
        "latency_ms": {"parse": 0.03, "modules": 0.02, "total": 0.26},
        "added_latency_ms": 0.26,
        "evidence": evidence if evidence is not None else [{
            "module": "ti", "score": score,
            "features": {"listed": True, "indicator": qname,
                         "feed": "checkpoint-fixture", "match_type": "exact"},
            "latency_ms": 0.02, "status": "ok"}],
        "explanation": explanation if explanation is not None else {
            "method": "weighted_mean",
            "policy_verdict": verdict,
            "aggregate_score": score,
            "thresholds": {"flag_at": 0.5, "block_at": 0.8},
            "contributions": [{"module": "ti", "score": score, "weight": 1.0,
                               "weighted": score, "status": "ok",
                               "counted": True}],
            "enforcement": {"enabled": True, "would_block": True,
                            "applied": True, "action": "block"},
        },
    }
    base.update(over)
    return base


def seed(db_path, records):
    db = Database(db_path)
    try:
        for record in records:
            db.insert_record(QueryRecord.from_log_payload(record, "test-salt"))
        db.upsert_feed_state("checkpoint-fixture", "2026-09-03T00:00:00Z",
                             385659, 42.0)
    finally:
        db.close()


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient wired to a fresh database with three known decisions."""
    db_path = str(tmp_path / "api.sqlite3")
    seed(db_path, [
        payload("blocked-one.test", "BLOCK", "NXDOMAIN", 1.0),
        payload("flagged.test", "FLAG", "NOERROR", 0.6),
        payload("clean.test", "ALLOW", "NOERROR", 0.0,
                evidence=[{"module": "ti", "score": 0.0,
                           "features": {"listed": False}, "latency_ms": 0.01,
                           "status": "ok"}]),
    ])
    monkeypatch.setattr(api_main, "repository", DecisionRepository(db_path))
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_path=db_path, engine_modules="null",
                                 db_enabled=False, **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    return sign_in(TestClient(api_main.app))


@pytest.fixture
def empty_client(tmp_path, monkeypatch):
    """A client whose database exists but holds no decisions."""
    db_path = str(tmp_path / "empty.sqlite3")
    Database(db_path).close()
    monkeypatch.setattr(api_main, "repository", DecisionRepository(db_path))
    monkeypatch.setattr(api_main, "settings", Settings(db_path=db_path,
                                                       engine_modules="null",
                                                       db_enabled=False, **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    return sign_in(TestClient(api_main.app))


@pytest.fixture
def broken_client(tmp_path, monkeypatch):
    """A client whose database file does not exist at all."""
    monkeypatch.setattr(api_main, "repository",
                        DecisionRepository(str(tmp_path / "missing.sqlite3")))
    monkeypatch.setattr(api_main, "_engine", None)
    return sign_in(TestClient(api_main.app))


# -- /health ---------------------------------------------------------------

def test_health_reports_ok_and_a_readable_database(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["database"]["available"] is True
    assert body["database"]["schema_version"] == 2
    # Stage 17 trimmed this public endpoint: no filesystem path, no error
    # detail, because an unauthenticated caller should learn neither.
    assert "path" not in body["database"]
    assert "error" not in body["database"]


def test_health_reports_an_unreadable_database_without_failing(broken_client):
    """Liveness and database reachability are different questions."""
    response = broken_client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"]["available"] is False
    # The reason is deliberately withheld from this public endpoint.
    assert "error" not in body["database"]


def test_health_does_not_claim_to_check_the_proxy(client):
    assert "does not check the DNS proxy" in client.get("/health").json()["note"]


# -- /decisions ------------------------------------------------------------

def test_decisions_returns_real_stored_rows(client):
    body = client.get("/decisions").json()
    assert body["total"] == 3
    assert body["count"] == 3
    names = [d["qname"] for d in body["decisions"]]
    assert names == ["clean.test", "flagged.test", "blocked-one.test"], \
        "decisions are not newest first"


def test_a_decision_carries_its_verdict_score_and_latency(client):
    top = client.get("/decisions?qname=blocked-one").json()["decisions"][0]
    assert top["verdict"] == "BLOCK"
    assert top["rcode"] == "NXDOMAIN"
    assert top["score"] == 1.0
    assert top["latency_ms"]["total"] == 0.26
    assert top["latency_ms"]["breakdown"]["modules"] == 0.02
    assert top["enforcement"]["applied"] is True


def test_pagination_walks_the_result_set(client):
    first = client.get("/decisions?limit=2&offset=0").json()
    second = client.get("/decisions?limit=2&offset=2").json()

    assert first["count"] == 2 and second["count"] == 1
    assert first["total"] == second["total"] == 3
    assert not ({d["id"] for d in first["decisions"]}
                & {d["id"] for d in second["decisions"]}), "pages overlap"


def test_decisions_can_be_filtered_by_verdict(client):
    body = client.get("/decisions?verdict=BLOCK").json()
    assert body["total"] == 1
    assert body["decisions"][0]["qname"] == "blocked-one.test"


def test_verdict_filtering_is_case_insensitive(client):
    assert client.get("/decisions?verdict=block").json()["total"] == 1


def test_an_unknown_verdict_is_rejected_not_silently_empty(client):
    """An empty page would read as 'nothing matched', which is misleading."""
    response = client.get("/decisions?verdict=BANANA")
    assert response.status_code == 422
    assert "unknown verdict" in response.json()["detail"]


def test_decisions_can_be_filtered_by_name_prefix(client):
    assert client.get("/decisions?qname=blocked").json()["total"] == 1
    assert client.get("/decisions?qname=nothing-like-this").json()["total"] == 0


def test_a_like_wildcard_in_the_filter_is_escaped(client):
    """'%' must be a literal, not a caller-supplied pattern."""
    assert client.get("/decisions?qname=%").json()["total"] == 0


def test_sql_metacharacters_in_the_filter_are_harmless(client):
    response = client.get("/decisions?qname=' OR 1=1--")
    assert response.status_code == 200
    assert response.json()["total"] == 0
    assert client.get("/decisions").json()["total"] == 3, "the table survived"


@pytest.mark.parametrize("query", ["limit=0", "limit=501", "offset=-1"])
def test_out_of_range_pagination_is_rejected(client, query):
    assert client.get(f"/decisions?{query}").status_code == 422


def test_an_empty_database_returns_an_empty_page_not_an_error(empty_client):
    body = empty_client.get("/decisions").json()
    assert body == {"decisions": [], "count": 0, "total": 0,
                    "limit": 50, "offset": 0}


def test_an_unreadable_database_is_503_not_an_empty_page(broken_client):
    """'No data' and 'cannot read the data' must not look alike."""
    response = broken_client.get("/decisions")
    assert response.status_code == 503
    assert "no database at" in response.json()["detail"]


# -- privacy ---------------------------------------------------------------

def test_no_raw_client_address_is_ever_returned(client):
    raw = client.get("/decisions").text
    assert "192.0.2.10" not in raw, "a raw client IP reached the API response"


def test_the_client_field_is_the_stored_pseudonym(client):
    decision = client.get("/decisions").json()["decisions"][0]
    assert "client_ip" not in decision
    assert decision["client_hash"] and decision["client_hash"] != "192.0.2.10"
    assert len(decision["client_hash"]) == 16


def test_evidence_responses_carry_no_client_identifier(client):
    decision_id = client.get("/decisions").json()["decisions"][0]["id"]
    raw = client.get(f"/decisions/{decision_id}/evidence").text
    assert "192.0.2.10" not in raw


# -- /decisions/{id}/evidence ---------------------------------------------

def test_evidence_returns_the_stored_decision_trace(client):
    decision_id = client.get(
        "/decisions?verdict=BLOCK").json()["decisions"][0]["id"]
    body = client.get(f"/decisions/{decision_id}/evidence").json()

    assert body["qname"] == "blocked-one.test"
    assert body["verdict"] == "BLOCK"
    assert len(body["modules"]) == 1
    module = body["modules"][0]
    assert module["module"] == "ti"
    assert module["status"] == "ok"
    assert module["features"]["match_type"] == "exact"
    assert body["explanation"]["contributions"][0]["weight"] == 1.0


def test_evidence_for_a_missing_decision_is_404(client):
    response = client.get("/decisions/999999/evidence")
    assert response.status_code == 404
    assert "999999" in response.json()["detail"]


def test_a_non_numeric_decision_id_is_422(client):
    assert client.get("/decisions/not-a-number/evidence").status_code == 422


def test_evidence_on_an_unreadable_database_is_503(broken_client):
    assert broken_client.get("/decisions/1/evidence").status_code == 503


# -- /stats ----------------------------------------------------------------

def test_stats_are_computed_from_the_real_database(client):
    body = client.get("/stats").json()
    assert body["totals"]["queries"] == 3
    assert body["totals"]["decisions"] == 3
    assert body["verdicts"] == {"BLOCK": 1, "FLAG": 1, "ALLOW": 1}


def test_stats_include_feed_state_from_the_database(client):
    feeds = client.get("/stats").json()["feeds"]
    assert len(feeds) == 1
    assert feeds[0]["feed"] == "checkpoint-fixture"
    assert feeds[0]["entries"] == 385659


def test_stats_list_the_flagged_and_blocked_names(client):
    top = client.get("/stats").json()["top_flagged_or_blocked"]
    assert {entry["qname"] for entry in top} == {"blocked-one.test",
                                                 "flagged.test"}


def test_stats_carry_the_accuracy_disclaimer(client):
    """These are operational counts, not evaluation metrics."""
    assert "NOT YET MEASURED" in client.get("/stats").json()["note"]


def test_stats_on_an_empty_database_are_zeros_not_an_error(empty_client):
    body = empty_client.get("/stats").json()
    assert body["totals"] == {"queries": 0, "decisions": 0, "evidence": 0}
    assert body["verdicts"] == {}
    assert body["latency_ms"]["avg_total"] is None


def test_stats_on_an_unreadable_database_are_503(broken_client):
    assert broken_client.get("/stats").status_code == 503


# -- /lookup ---------------------------------------------------------------

def test_lookup_performs_a_live_evaluation(client):
    body = client.post("/lookup", json={"domain": "example.com"}).json()

    assert body["source"] == "live"
    assert body["qname"] == "example.com"
    assert body["verdict"] in {"ALLOW", "FLAG", "BLOCK", "UNKNOWN"}
    assert body["modules"][0]["module"] == "null"
    assert body["explanation"]["method"] == "weighted_mean"


def test_lookup_says_it_enforced_nothing(client):
    """It cannot block: no DNS response is sent from this endpoint."""
    body = client.post("/lookup", json={"domain": "example.com"}).json()
    assert "nothing was enforced" in body["note"]
    assert "independent of the running" in body["note"]


def test_lookup_normalises_the_domain(client):
    body = client.post("/lookup", json={"domain": "  EXAMPLE.COM.  "}).json()
    assert body["qname"] == "example.com"


@pytest.mark.parametrize("domain", [
    "", "   ", "not a domain", "localhost", "-bad.test", "bad-.test",
    "http://example.com", "example.com/path", "a" * 300 + ".test",
])
def test_lookup_rejects_invalid_domains(client, domain):
    assert client.post("/lookup", json={"domain": domain}).status_code == 422


@pytest.mark.parametrize("body", [{}, {"domain": 123}, {"domain": None},
                                  {"name": "example.com"}])
def test_lookup_rejects_a_malformed_body(client, body):
    assert client.post("/lookup", json=body).status_code == 422


def test_lookup_reports_its_own_evaluation_time(client):
    body = client.post("/lookup", json={"domain": "example.com"}).json()
    assert body["evaluation_ms"] >= 0


# -- /mode -----------------------------------------------------------------

def test_get_mode_reports_this_process_configuration(client):
    body = client.get("/mode").json()
    assert body["engine"] == "engine[null]"
    assert body["modules"] == [{"name": "null", "enabled": True}]
    assert body["enforcement"]["enabled"] is False
    assert body["block_response"] == "nxdomain"


def test_mode_states_that_it_does_not_reach_the_proxy(client):
    """The single most important field on this endpoint."""
    body = client.get("/mode").json()
    assert body["affects_running_proxy"] is False
    assert "runs separately" in body["scope"]


def test_put_mode_disables_a_module(client):
    response = client.put("/mode", json={"modules": {"null": False}})
    assert response.status_code == 200

    body = response.json()
    assert body["changed"] == ["module null=False"]
    assert body["modules"] == [{"name": "null", "enabled": False}]
    assert client.get("/mode").json()["engine"] == "engine[none]"


def test_put_mode_toggles_enforcement(client):
    body = client.put("/mode", json={"enforce": True}).json()
    assert body["enforcement"]["enabled"] is True
    assert client.get("/mode").json()["enforcement"]["enabled"] is True


def test_a_mode_change_affects_the_next_lookup(client):
    """Proves the change reached the engine rather than only the response."""
    before = client.post("/lookup", json={"domain": "example.com"}).json()
    assert before["modules"][0]["status"] == "ok"

    client.put("/mode", json={"modules": {"null": False}})
    after = client.post("/lookup", json={"domain": "example.com"}).json()
    assert after["modules"][0]["status"] == "disabled"


def test_put_mode_still_reports_that_it_does_not_reach_the_proxy(client):
    assert client.put("/mode",
                      json={"enforce": True}).json()["affects_running_proxy"] \
        is False


def test_put_mode_rejects_an_unknown_module(client):
    response = client.put("/mode", json={"modules": {"typosquat": True}})
    assert response.status_code == 422
    assert "unknown module" in response.json()["detail"]


@pytest.mark.parametrize("body", [
    {"modules": {"null": "yes"}},
    {"modules": ["null"]},
    {"enforce": "true"},
    {"flag_at": 0.3},
    {"weights": {"ti": 1.0}},
])
def test_put_mode_rejects_unsupported_or_malformed_changes(client, body):
    assert client.put("/mode", json=body).status_code == 422


def test_thresholds_cannot_be_changed_at_runtime(client):
    """Changing them mid-run would make stored decisions incomparable."""
    response = client.put("/mode", json={"block_at": 0.2})
    assert response.status_code == 422
    assert "Only 'modules' and 'enforce'" in response.json()["detail"]


# -- the repository in isolation ------------------------------------------

def test_the_repository_opens_the_database_read_only(tmp_path):
    """A presentation layer must not be able to corrupt the decision record."""
    import sqlite3

    db_path = str(tmp_path / "ro.sqlite3")
    seed(db_path, [payload()])
    repo = DecisionRepository(db_path)
    conn = repo._connect()
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM queries")
    finally:
        conn.close()


def test_the_repository_reports_a_missing_database(tmp_path):
    with pytest.raises(DatabaseUnavailable):
        DecisionRepository(str(tmp_path / "nope.sqlite3")).list_decisions()


def test_the_limit_is_capped(tmp_path):
    db_path = str(tmp_path / "many.sqlite3")
    seed(db_path, [payload(f"d{i}.test") for i in range(10)])
    decisions, total = DecisionRepository(db_path).list_decisions(limit=10_000)
    assert total == 10 and len(decisions) == 10


def test_unparseable_stored_json_does_not_break_a_response(tmp_path,
                                                           monkeypatch):
    """A corrupt column must degrade to null, not 500 the endpoint."""
    import sqlite3

    db_path = str(tmp_path / "corrupt.sqlite3")
    seed(db_path, [payload()])
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE decisions SET explanation_json = 'not json'")
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setattr(api_main, "repository", DecisionRepository(db_path))
    response = sign_in(TestClient(api_main.app)).get("/decisions")
    assert response.status_code == 200
    assert response.json()["decisions"][0]["enforcement"] is None


def test_stored_rows_come_from_the_projects_own_write_path(tmp_path):
    """The fixture is built by storage.QueryRecord, not hand-written JSON."""
    db_path = str(tmp_path / "provenance.sqlite3")
    seed(db_path, [payload("provenance.test")])

    decisions, _ = DecisionRepository(db_path).list_decisions()
    stored = decisions[0]
    assert stored["qname"] == "provenance.test"
    assert json.loads(
        Database(db_path).recent_queries()[0]["explanation_json"]
    )["method"] == "weighted_mean"


# -- regression: /lookup with the default allow-all engine ----------------

@pytest.fixture
def allow_all_client(tmp_path, monkeypatch):
    """A client whose engine is the default AllowAllEngine.

    `engine_modules` is empty, which is what `build_engine` treats as "no
    detection configured" — the state a freshly started API process is in
    unless DNSF_ENGINE_MODULES is set.
    """
    db_path = str(tmp_path / "allowall.sqlite3")
    seed(db_path, [payload("stored.test", "BLOCK", "NXDOMAIN", 1.0)])
    monkeypatch.setattr(api_main, "repository", DecisionRepository(db_path))
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_path=db_path, engine_modules="",
                                 db_enabled=False, **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    return sign_in(TestClient(api_main.app))


def test_the_default_engine_is_allow_all(allow_all_client):
    """Establishes the precondition the rest of these tests depend on."""
    assert allow_all_client.get("/mode").json()["engine"] == "allow-all"


def test_lookup_works_with_the_default_allow_all_engine(allow_all_client):
    """Regression for a 500.

    /lookup called `engine.evaluate()` and `engine.aggregator`, which only
    DecisionEngine has. AllowAllEngine exposes `decide` and `name` and nothing
    else, so the endpoint raised AttributeError on any API process started
    without DNSF_ENGINE_MODULES — which is the default.
    """
    response = allow_all_client.post("/lookup", json={"domain": "example.com"})
    assert response.status_code == 200, response.text

    body = response.json()
    assert body["qname"] == "example.com"
    assert body["source"] == "live"
    assert body["verdict"] == "ALLOW"
    assert body["score"] == 0.0


def make_client(tmp_path, monkeypatch, modules: str) -> TestClient:
    """Build a client with a specific engine configuration.

    A helper rather than a second fixture: both fixtures patch the same module
    globals, so requesting two of them in one test silently leaves whichever
    ran last in place — which would make a comparison between two engines
    compare one engine with itself.
    """
    db_path = str(tmp_path / f"engine-{modules or 'default'}.sqlite3")
    seed(db_path, [payload("stored.test", "BLOCK", "NXDOMAIN", 1.0)])
    monkeypatch.setattr(api_main, "repository", DecisionRepository(db_path))
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_path=db_path, engine_modules=modules,
                                 db_enabled=False, **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    return sign_in(TestClient(api_main.app))


def test_lookup_response_shape_is_the_same_for_both_engines(tmp_path,
                                                            monkeypatch):
    """The schema must not depend on which engine answered."""
    required = {"qname", "source", "engine", "verdict", "score", "enforcement",
                "modules", "explanation", "evaluation_ms", "note"}

    allow_all = make_client(tmp_path, monkeypatch, "").post(
        "/lookup", json={"domain": "example.com"}).json()
    assert allow_all["engine"] == "allow-all"
    assert required <= set(allow_all)

    configured = make_client(tmp_path, monkeypatch, "null").post(
        "/lookup", json={"domain": "example.com"}).json()
    assert configured["engine"] == "engine[null]"
    assert required <= set(configured)

    assert set(allow_all) == set(configured)


def test_the_allow_all_engine_reports_no_derivation_rather_than_a_fake_one(
        allow_all_client):
    """An engine that detects nothing must say so, not manufacture a trace."""
    body = allow_all_client.post("/lookup", json={"domain": "example.com"}).json()

    assert body["modules"] == []
    assert body["explanation"] is None
    assert body["enforcement"] is None
    assert "performs no detection" in body["note"]


def test_lookup_names_the_engine_that_answered(tmp_path, monkeypatch):
    """Makes an empty result self-explanatory instead of looking broken."""
    assert make_client(tmp_path, monkeypatch, "").post(
        "/lookup", json={"domain": "example.com"}).json()["engine"] == "allow-all"
    assert make_client(tmp_path, monkeypatch, "null").post(
        "/lookup", json={"domain": "example.com"}).json()["engine"] == "engine[null]"


def test_lookup_uses_the_interface_every_engine_implements():
    """`decide` is the contract; `evaluate` is a DecisionEngine detail.

    Guards against the endpoint reaching back into engine internals, which is
    exactly how the original defect arose.
    """
    from proxy.dns_proxy import AllowAllEngine
    from engine.decision import DecisionEngine

    common = {name for name in dir(AllowAllEngine)
              if not name.startswith("_")} & {name for name in dir(DecisionEngine)
                                              if not name.startswith("_")}
    assert "decide" in common
    assert "evaluate" not in common, \
        "evaluate is not part of the common engine interface"

    import inspect

    import api.main as module
    source = inspect.getsource(module.lookup)
    assert "engine.decide(" in source
    assert "engine.evaluate(" not in source
    assert "engine.aggregator" not in source


def test_lookup_still_scores_through_a_configured_engine(client):
    """The configured path must keep working unchanged."""
    body = client.post("/lookup", json={"domain": "example.com"}).json()
    assert body["modules"][0]["module"] == "null"
    assert body["explanation"]["method"] == "weighted_mean"
    assert body["enforcement"] is not None


def test_lookup_rejects_an_unencodable_label(allow_all_client):
    """A label over 63 bytes cannot exist on the wire and is refused here."""
    response = allow_all_client.post(
        "/lookup", json={"domain": ("a" * 70) + ".test"})
    assert response.status_code == 422


def test_lookup_sends_no_dns_response(allow_all_client):
    """It builds and parses a packet; it never puts one on a socket."""
    import inspect

    source = inspect.getsource(api_main)
    assert "socket" not in source
    assert "sendto" not in source


# -- Stage 12: module availability ----------------------------------------

def test_mode_reports_which_modules_the_build_can_construct(client):
    """Distinguishes 'implemented but disabled' from 'not implemented'.

    Without this a client cannot tell a working module that is switched off
    from one that does not exist, and would mislabel it on the dashboard.
    """
    body = client.get("/mode").json()
    assert "available_modules" in body
    assert {"ti", "nrd", "typosquat", "null"} <= set(body["available_modules"])
    assert [m["name"] for m in body["modules"]] == ["null"]


def test_available_modules_matches_the_engine_registry(client):
    from engine.modules import REGISTRY

    assert client.get("/mode").json()["available_modules"] == sorted(REGISTRY)


def test_lookup_returns_typosquat_evidence(tmp_path, monkeypatch):
    """End to end through the API with the Stage 12 module enabled."""
    api_client = make_client(tmp_path, monkeypatch, "typosquat")
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_enabled=False, engine_modules="typosquat",
                                 typosquat_brands="spotify",
                                 typosquat_official_domains="spotify.com", **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    api_client = sign_in(TestClient(api_main.app))

    suspicious = api_client.post("/lookup",
                                 json={"domain": "spotifyapk.com"}).json()
    assert suspicious["modules"][0]["module"] == "typosquat"
    assert suspicious["modules"][0]["features"]["matched_brand"] == "spotify"
    assert suspicious["modules"][0]["features"]["suspicious_keyword"] == "apk"
    assert suspicious["score"] > 0

    legitimate = api_client.post("/lookup",
                                 json={"domain": "spotify.com"}).json()
    assert legitimate["score"] == 0.0
    assert legitimate["modules"][0]["features"]["matched_brand"] is None


# -- Stage 13: DGA evidence through the API -------------------------------

def test_dga_is_reported_as_an_available_module(client):
    assert "dga" in client.get("/mode").json()["available_modules"]


def test_lookup_returns_dga_evidence(tmp_path, monkeypatch):
    """The model's per-decision explanation must survive to the API."""
    from pathlib import Path

    artifact = (Path(api_main.__file__).resolve().parent.parent
                / "models" / "dga" / "dga_model.json")
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_enabled=False, engine_modules="dga",
                                 dga_model_path=str(artifact)))
    monkeypatch.setattr(api_main, "_engine", None)
    api_client = sign_in(TestClient(api_main.app))

    random_like = api_client.post(
        "/lookup", json={"domain": "xkwqvbzmrtplfjdh.com"}).json()
    module = random_like["modules"][0]
    assert module["module"] == "dga"
    assert module["features"]["model"] == "logistic_regression"
    assert module["features"]["verdict_hint"] == "DGA-like"
    assert module["score"] > 0.5
    assert module["features"]["top_contributions"]

    ordinary = api_client.post("/lookup", json={"domain": "bluegarden.com"}).json()
    assert ordinary["modules"][0]["score"] < 0.5
    assert ordinary["modules"][0]["features"]["verdict_hint"] == "benign-like"


def test_lookup_reports_a_missing_dga_model_as_a_module_error(tmp_path,
                                                              monkeypatch):
    """A broken deployment must not look like a clean verdict."""
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_enabled=False, engine_modules="dga",
                                 dga_model_path=str(tmp_path / "absent.json")))
    monkeypatch.setattr(api_main, "_engine", None)

    body = sign_in(TestClient(api_main.app)).post(
        "/lookup", json={"domain": "example.com"}).json()

    assert body["modules"][0]["status"] == "unavailable"
    assert body["modules"][0]["features"]["unavailable"] == "ModelUnavailable"
    assert body["verdict"] == "UNKNOWN", \
        "a module with no usable score was treated as a clean result"


# -- Stage 14: beaconing through the API ----------------------------------

def test_beaconing_is_reported_as_an_available_module(client):
    assert "beaconing" in client.get("/mode").json()["available_modules"]


def test_lookup_returns_beaconing_evidence_from_stored_history(tmp_path,
                                                               monkeypatch):
    """/lookup reads the same history table the proxy writes."""
    import time
    from datetime import datetime, timezone

    from storage.db import Database
    from storage.models import QueryRecord

    db_path = str(tmp_path / "beacon.sqlite3")
    now = time.time()
    database = Database(db_path)
    try:
        for offset in [i * 300 for i in range(12)]:
            record = QueryRecord.from_log_payload({
                "client": "192.0.2.1", "qname": "beacon-demo.test",
                "qtype": "A", "verdict": "ALLOW", "rcode": "NOERROR",
                "score": 0.0, "engine": "seeded-fixture", "evidence": [],
                "latency_ms": {"total": 1.0}, "added_latency_ms": 0.1,
            }, "salt")
            record.ts = datetime.fromtimestamp(now - offset,
                                               tz=timezone.utc).isoformat()
            database.insert_record(record)
    finally:
        database.close()

    monkeypatch.setattr(api_main, "settings",
                        Settings(db_enabled=False, engine_modules="beaconing",
                                 db_path=db_path, **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    api_client = sign_in(TestClient(api_main.app))

    body = api_client.post("/lookup", json={"domain": "beacon-demo.test"}).json()
    module = body["modules"][0]
    assert module["module"] == "beaconing"
    assert module["status"] == "ok"
    assert module["features"]["observations"] == 12
    assert module["features"]["coefficient_of_variation"] < 0.01
    assert module["score"] > 0.7

    # A domain with no history must not be reported as non-beaconing.
    thin = api_client.post("/lookup", json={"domain": "unseen.test"}).json()
    assert thin["modules"][0]["status"] == "unavailable"
    assert thin["modules"][0]["features"]["unavailable"] == \
        "InsufficientObservations"
    assert thin["verdict"] == "UNKNOWN"
