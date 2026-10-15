"""Registration age (RDAP), operator allowlist, device alerts, and the
threat-intelligence defaults (extra feeds, decisive listing).

Everything here runs offline: RDAP is exercised through an injected fetch
function, feeds are not fetched, and the API reads a temporary database.
"""

import time

import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from api.module_presentation import classify
from api.repository import DecisionRepository
from config.settings import Settings
from engine.aggregator import RiskAggregator
from engine.allowlist import Allowlist
from engine.decision import DecisionEngine
from engine.modules import REGISTRY
from engine.modules.base import (STATUS_OK, STATUS_UNAVAILABLE, ModuleResult,
                                 QueryContext)
from engine.modules.null import FixedScoreModule
from engine.modules.rdap import RdapAgeModule, parse_registration
from proxy.timing import Stopwatch
from tests.conftest import auth_settings_kwargs, sign_in
from tests.test_api import payload, seed

DAY = 86400.0


def ctx(qname, ts=None):
    return QueryContext(qname=qname, qtype="A", client_id="c",
                        timestamp=ts if ts is not None else time.time())


class _Q:
    """The minimal query shape DecisionEngine.decide reads."""

    class question:
        pass

    def __init__(self, qname):
        self.question = type("Qn", (), {"qname": qname, "qtype_name": "A"})()


# -- RDAP registration age -----------------------------------------------

def make_rdap(ages: dict, **kw):
    """An RDAP module whose 'network' answers from `ages` (days old)."""
    calls = []

    def fetch(domain):
        calls.append(domain)
        value = ages[domain]
        if isinstance(value, Exception):
            raise value
        return None if value is None else time.time() - value * DAY

    module = RdapAgeModule(fetch=fetch, **kw)
    return module, calls


def test_rdap_is_registered_under_its_own_name():
    assert REGISTRY["rdap"] is RdapAgeModule


def test_first_query_is_pending_and_never_a_zero():
    module, _ = make_rdap({"fresh.example-new.com": 2})
    engine = DecisionEngine([module])
    first = engine.evaluate(ctx("www.fresh.example-new.com"))[0]
    assert first.status == STATUS_UNAVAILABLE
    assert first.features["unavailable"] == "RegistrationPending"
    assert classify(first.status, first.score, first.features)["state"] == \
        "insufficient_observations"


def test_a_recent_registration_scores_high_once_looked_up():
    module, calls = make_rdap({"fresh-site.com": 3})
    engine = DecisionEngine([module])
    engine.evaluate(ctx("login.fresh-site.com"))
    assert module.wait_idle()
    result = engine.evaluate(ctx("login.fresh-site.com"))[0]
    assert result.status == STATUS_OK
    assert result.score == 1.0
    assert result.features["age_source"] == "rdap"
    assert result.features["registrable"] == "fresh-site.com"
    assert calls == ["fresh-site.com"], "one lookup per registration, cached"


def test_an_old_registration_scores_zero_and_decay_is_linear():
    module, _ = make_rdap({"old.com": 9000})
    assert module.score_for_age(10 * DAY) == 1.0
    assert module.score_for_age(400 * DAY) == 0.0
    mid = module.score_for_age((30 + 365) / 2 * DAY)
    assert 0.49 < mid < 0.51
    with pytest.raises(Exception):
        module.evaluate(ctx("old.com"))      # first query starts the lookup
    assert module.wait_idle()
    assert module.evaluate(ctx("old.com")).score == 0.0


def test_a_failed_lookup_is_unavailable_not_clean():
    module, _ = make_rdap({"broken.com": OSError("network down")})
    engine = DecisionEngine([module])
    engine.evaluate(ctx("broken.com"))
    module.wait_idle()
    result = engine.evaluate(ctx("broken.com"))[0]
    assert result.status == STATUS_UNAVAILABLE
    assert result.features["unavailable"] == "RegistrationUnknown"


@pytest.mark.parametrize("name", ["printer.local", "router.lan", "box.home",
                                  "x.test", "localhost", "10.0.0.1"])
def test_private_names_are_never_sent_to_rdap(name):
    module, calls = make_rdap({})
    with pytest.raises(Exception):
        module.evaluate(ctx(name))
    module.wait_idle()
    assert calls == []


def test_parse_registration_reads_the_registration_event():
    body = {"events": [
        {"eventAction": "expiration", "eventDate": "2027-09-08T08:09:14.0Z"},
        {"eventAction": "registration", "eventDate": "2026-09-08T08:09:14.0Z"}]}
    ts = parse_registration(body)
    assert time.strftime("%Y-%m-%d", time.gmtime(ts)) == "2026-09-08"
    assert parse_registration({"events": []}) is None


def test_rdap_builds_from_settings_without_touching_the_network():
    module = RdapAgeModule.from_settings(Settings())
    assert module.new_within_s == 30 * DAY
    module.close()


# -- allowlist -------------------------------------------------------------

def test_allowlist_covers_a_name_and_its_subdomains_only():
    allow = Allowlist(["Partner.Example.com.", "intranet.org"])
    assert allow.match("partner.example.com") == "partner.example.com"
    assert allow.match("api.partner.example.com") == "partner.example.com"
    assert allow.match("example.com") is None
    assert allow.match("notpartner.example.com") is None


def test_allowlist_reads_settings_and_file(tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("# comment\nfile-entry.com  # trailing\n\n", encoding="utf-8")
    allow = Allowlist.from_settings(Settings(allowlist="a.com, b.org",
                                             allowlist_file=str(f)))
    assert allow.domains == {"a.com", "b.org", "file-entry.com"}


def test_missing_allowlist_file_does_not_stop_the_engine(tmp_path):
    allow = Allowlist.from_settings(
        Settings(allowlist_file=str(tmp_path / "nope.txt")))
    assert len(allow) == 0


def test_an_allowlisted_block_is_forwarded_with_the_override_recorded():
    aggregator = RiskAggregator(enforce=True)
    engine = DecisionEngine([FixedScoreModule("ti", 1.0)],
                            aggregator=aggregator,
                            allowlist=Allowlist(["shared-host.example"]))
    decision = engine.decide(_Q("site.shared-host.example"), Stopwatch())
    assert decision["verdict"] == "ALLOW"
    assert decision["enforcement"]["action"] == "forward"
    assert decision["explanation"]["allowlisted"]["detector_verdict"] == "BLOCK"
    assert "allowlist" in decision["explanation"]["summary"]
    # The evidence is still there to review.
    assert decision["evidence"][0]["score"] == 1.0


def test_without_an_allowlist_the_engine_is_unchanged():
    engine = DecisionEngine([FixedScoreModule("ti", 1.0)],
                            aggregator=RiskAggregator(enforce=True))
    decision = engine.decide(_Q("site.shared-host.example"), Stopwatch())
    assert decision["verdict"] == "BLOCK"
    assert decision["enforcement"]["action"] == "block"
    assert "allowlisted" not in decision["explanation"]


# -- decisive threat intelligence -------------------------------------------

def _results(ti_score):
    return [ModuleResult("ti", ti_score, {}, 0.0, STATUS_OK),
            ModuleResult("nrd", 0.0, {}, 0.0, STATUS_OK),
            ModuleResult("typosquat", 0.0, {}, 0.0, STATUS_OK),
            ModuleResult("dga", 0.1, {}, 0.0, STATUS_OK)]


def test_a_listed_domain_is_not_diluted_when_ti_is_decisive():
    out = RiskAggregator(decisive={"ti"}).aggregate(_results(1.0))
    assert out["verdict"] == "BLOCK" and out["score"] == 1.0
    assert out["explanation"]["decisive_hit"] == ["ti"]


def test_the_plain_weighted_mean_is_unchanged_by_default():
    """The constructor default keeps the paper's formula (2) exactly."""
    out = RiskAggregator().aggregate(_results(1.0))
    assert out["verdict"] == "ALLOW"
    assert "decisive_hit" not in out["explanation"]


def test_decisive_does_not_fire_without_a_listing():
    out = RiskAggregator(decisive={"ti"}).aggregate(_results(0.0))
    assert out["verdict"] == "ALLOW"


def test_settings_switch_decisive_on_and_off():
    assert RiskAggregator.from_settings(Settings()).decisive == {"ti"}
    off = Settings(aggregator_ti_decisive=False)
    assert RiskAggregator.from_settings(off).decisive == frozenset()


# -- extra feeds ---------------------------------------------------------

def _feed_names(**kw):
    from feeds import build_manager_from_settings
    manager = build_manager_from_settings(Settings(db_enabled=False, **kw))
    return [s.name for s in manager.sources]


def test_unconfigured_ti_uses_several_feeds():
    names = _feed_names()
    assert names[0] == "phishing-domains"
    assert {"urlhaus-filter", "openphish"} <= set(names)


def test_an_explicit_feed_choice_is_respected(tmp_path):
    f = tmp_path / "feed.txt"
    f.write_text("x.test\n", encoding="utf-8")
    assert _feed_names(feed_file=str(f)) == ["phishing-domains"]
    assert _feed_names(feed_url="https://feed.invalid/list.txt") == \
        ["phishing-domains"]
    assert _feed_names(feed_extra_defaults=False) == ["phishing-domains"]


# -- device alerts ---------------------------------------------------------

@pytest.fixture
def alert_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "alerts.sqlite3")
    infected = [payload(f"bad{i}.test", "BLOCK", "NXDOMAIN", 1.0,
                        client="192.0.2.50") for i in range(4)]
    infected += [payload("bad0.test", "BLOCK", "NXDOMAIN", 1.0,
                         client="192.0.2.50")]
    stray = [payload("oops.test", "BLOCK", "NXDOMAIN", 1.0, client="192.0.2.60")]
    clean = [payload("fine.test", "ALLOW", "NOERROR", 0.0, client="192.0.2.70")
             for _ in range(5)]
    seed(db_path, infected + stray + clean)
    monkeypatch.setattr(api_main, "repository", DecisionRepository(db_path))
    monkeypatch.setattr(api_main, "settings",
                        Settings(db_path=db_path, engine_modules="null",
                                 db_enabled=False, **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_engine", None)
    return sign_in(TestClient(api_main.app))


def test_alerts_name_only_the_device_reaching_many_risky_domains(alert_client):
    body = alert_client.get("/alerts").json()
    assert len(body["alerts"]) == 1
    alert = body["alerts"][0]
    assert alert["distinct_domains"] == 4
    assert alert["blocked_domains"] == 4
    assert alert["risky_queries"] == 5
    assert alert["top_domains"][0] == {"qname": "bad0.test", "count": 2}
    assert "not proof" in body["note"]


def test_alerts_threshold_is_adjustable(alert_client):
    body = alert_client.get("/alerts?min_domains=1").json()
    assert len(body["alerts"]) == 2


def test_alerts_never_expose_a_raw_address(alert_client):
    text = alert_client.get("/alerts?min_domains=1").text
    assert "192.0.2." not in text


def test_alerts_require_a_session(alert_client):
    fresh = TestClient(api_main.app)
    assert fresh.get("/alerts").status_code == 401


def test_an_empty_window_has_no_alerts(alert_client):
    from datetime import datetime, timedelta, timezone
    later = datetime.now(timezone.utc) + timedelta(days=2)
    body = api_main.repository.device_alerts(now=later)
    assert body["alerts"] == []
