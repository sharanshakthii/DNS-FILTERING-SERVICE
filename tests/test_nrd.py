"""Stage 6 tests: domain-age scoring.

The hard part of this signal is not the arithmetic, it is not lying. A cold
resolver has seen nothing, so a naive implementation flags every domain on
earth as new; and observation age is not registration age, so a database that
does not say which one produced a score invites a false claim in the report.
Most of these tests are about those two things.
"""

import time

import pytest

from engine.decision import DecisionEngine
from engine.modules.base import STATUS_OK, QueryContext
from engine.modules.nrd import NewDomainModule
from feeds.base import FeedSnapshot
from feeds.cache import IndicatorCache
from feeds.first_seen import FirstSeenStore
from feeds.nrd_source import build_nrd_cache, build_nrd_source
from config.settings import Settings

DAY = 24 * 3600.0


def ctx(qname, timestamp):
    return QueryContext(qname=qname, qtype="A", client_id="cid",
                        timestamp=timestamp)


def warm_module(now, **kwargs):
    """A module whose store has been observing long enough to have an opinion."""
    store = FirstSeenStore(started_at=now - 60 * DAY)
    return NewDomainModule(first_seen=store, **kwargs), store


# -- the first-seen store -------------------------------------------------

def test_first_observation_is_recorded_and_reported():
    store = FirstSeenStore(started_at=1000.0)
    ts, first = store.observe("example.com", now=2000.0)
    assert (ts, first) == (2000.0, True)

    ts2, first2 = store.observe("example.com", now=5000.0)
    assert ts2 == 2000.0, "the first-seen time was overwritten"
    assert first2 is False


def test_age_grows_from_the_first_observation():
    store = FirstSeenStore(started_at=0.0)
    store.observe("example.com", now=100.0)
    assert store.age_s("example.com", now=100.0 + 3 * DAY) == pytest.approx(3 * DAY)


def test_an_unseen_domain_has_no_age():
    assert FirstSeenStore().age_s("never.test") is None


def test_the_observation_window_is_reported():
    store = FirstSeenStore(started_at=1000.0)
    assert store.window_s(now=1000.0 + 5 * DAY) == pytest.approx(5 * DAY)


def test_the_store_is_bounded():
    store = FirstSeenStore(max_entries=100, started_at=0.0)
    for i in range(150):
        store.observe(f"d{i}.test", now=float(i))
    assert store.size <= 100
    assert store.evictions > 0


def test_eviction_drops_the_oldest_not_the_newest():
    """Evicting a recent entry would make a domain we just saw look new again."""
    store = FirstSeenStore(max_entries=20, started_at=0.0)
    for i in range(21):
        store.observe(f"d{i}.test", now=float(i))

    assert store.first_seen("d20.test") is not None, "the newest entry was evicted"
    assert store.first_seen("d0.test") is None, "the oldest entry survived"


def test_the_store_is_thread_safe():
    import threading
    store = FirstSeenStore(started_at=0.0)
    errors = []

    def worker(n):
        try:
            for i in range(200):
                store.observe(f"shared{i}.test", now=1000.0 + n)
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, errors
    assert store.size == 200, "concurrent observers created duplicates"


# -- the age-to-score curve -----------------------------------------------

def test_a_brand_new_domain_scores_one():
    module, _ = warm_module(1_000_000.0)
    assert module.score_for_age(0.0) == 1.0
    assert module.score_for_age(6 * DAY) == 1.0


def test_an_established_domain_scores_zero():
    module, _ = warm_module(1_000_000.0)
    assert module.score_for_age(30 * DAY) == 0.0
    assert module.score_for_age(365 * DAY) == 0.0


def test_the_score_decays_linearly_between_the_thresholds():
    """A step function would put ordinary domains either side of a cliff."""
    module, _ = warm_module(1_000_000.0)
    midpoint = module.score_for_age(18.5 * DAY)
    assert 0.4 < midpoint < 0.6
    assert module.score_for_age(10 * DAY) > module.score_for_age(20 * DAY)


def test_the_curve_never_leaves_the_valid_range():
    module, _ = warm_module(1_000_000.0)
    for days in [0, 1, 7, 7.001, 15, 29.999, 30, 100, 10_000]:
        assert 0.0 <= module.score_for_age(days * DAY) <= 1.0


def test_an_empty_decay_band_is_rejected():
    with pytest.raises(ValueError, match="must exceed"):
        NewDomainModule(new_within_s=30 * DAY, established_after_s=7 * DAY)


# -- the cold-start trap --------------------------------------------------

def test_a_cold_resolver_refuses_to_judge():
    """Otherwise every domain on earth is 'new' on the first morning."""
    now = 1_000_000.0
    store = FirstSeenStore(started_at=now - 3600)     # observing for one hour
    module = NewDomainModule(first_seen=store)

    score = module.evaluate(ctx("example.com", now))
    assert score.score == 0.0
    assert score.features["warming_up"] is True
    assert score.features["warmup_remaining_s"] > 0


def test_warmup_is_visible_in_the_evidence():
    now = 1_000_000.0
    module = NewDomainModule(first_seen=FirstSeenStore(started_at=now - 60))
    features = module.evaluate(ctx("example.com", now)).features
    assert "warmup_remaining_s" in features
    assert features["observation_window_s"] == pytest.approx(60, abs=1)


def test_once_warm_a_newly_observed_domain_scores_one():
    now = 1_000_000.0
    module, _ = warm_module(now)
    score = module.evaluate(ctx("brand-new.test", now))

    assert score.score == 1.0
    assert score.features["warming_up"] is False
    assert score.features["first_observation"] is True
    assert score.features["observed_age_s"] == 0.0


def test_a_long_observed_domain_scores_zero():
    now = 1_000_000.0
    module, store = warm_module(now)
    store.observe("old.test", now=now - 60 * DAY)

    score = module.evaluate(ctx("old.test", now))
    assert score.score == 0.0
    assert score.features["observed_age_s"] == pytest.approx(60 * DAY)


def test_a_recently_observed_domain_still_scores_one():
    now = 1_000_000.0
    module, store = warm_module(now)
    store.observe("recent.test", now=now - 2 * DAY)
    assert module.evaluate(ctx("recent.test", now)).score == 1.0


# -- honesty about what the age means -------------------------------------

def test_the_evidence_always_names_the_age_source():
    """Observation age is not registration age and must not be readable as it."""
    now = 1_000_000.0
    module, _ = warm_module(now)
    assert module.evaluate(ctx("x.test", now)).features["age_source"] == "first_seen"


def test_an_nrd_list_hit_is_labelled_as_such():
    now = 1_000_000.0
    cache = IndicatorCache(match_parents=False)
    cache.apply(FeedSnapshot(feed="nrd-list", domains={"fresh.test"}))
    module, _ = warm_module(now, nrd_list=cache)

    features = module.evaluate(ctx("fresh.test", now)).features
    assert features["age_source"] == "nrd_list"
    assert features["listed_as_new"] is True
    assert features["feed"] == "nrd-list"


def test_a_registry_list_outranks_our_own_observation():
    """A registry fact beats our inference when both are available."""
    now = 1_000_000.0
    cache = IndicatorCache(match_parents=False)
    cache.apply(FeedSnapshot(feed="nrd-list", domains={"fresh.test"}))
    module, store = warm_module(now, nrd_list=cache)
    store.observe("fresh.test", now=now - 60 * DAY)   # we saw it long ago

    score = module.evaluate(ctx("fresh.test", now))
    assert score.score == 1.0
    assert score.features["age_source"] == "nrd_list"


def test_an_empty_nrd_list_falls_back_to_observation():
    now = 1_000_000.0
    module, _ = warm_module(now, nrd_list=IndicatorCache())
    assert module.evaluate(ctx("x.test", now)).features["age_source"] == "first_seen"


# -- registrable-domain reduction -----------------------------------------

@pytest.mark.parametrize("qname,expected", [
    ("example.com", "example.com"),
    ("www.example.com", "example.com"),
    ("a.b.c.example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("example.com.", "example.com"),
])
def test_age_is_tracked_per_registration_not_per_hostname(qname, expected):
    """mail.x.com and www.x.com share one registration date."""
    assert NewDomainModule._registrable(qname) == expected


def test_a_new_subdomain_of_an_old_domain_is_not_flagged():
    """The regression this reduction exists to prevent."""
    now = 1_000_000.0
    module, store = warm_module(now)
    store.observe("example.com", now=now - 200 * DAY)

    score = module.evaluate(ctx("brand-new-host.example.com", now))
    assert score.score == 0.0, "a new hostname on an old domain was flagged"
    assert score.features["registrable"] == "example.com"


# -- configuration --------------------------------------------------------

def test_no_nrd_list_is_configured_by_default():
    """No verified public NRD list exists, so none is invented."""
    assert build_nrd_source(Settings()) is None
    assert build_nrd_cache(Settings()) is None


def test_a_local_nrd_file_is_used_when_configured(tmp_path):
    path = tmp_path / "nrd.txt"
    path.write_text("fresh.test\n", encoding="utf-8")

    cache = build_nrd_cache(Settings(nrd_file=str(path)))
    assert cache is not None and cache.ready
    assert cache.lookup("fresh.test") is not None


def test_the_nrd_list_does_not_match_parents(tmp_path):
    """Registration recency belongs to one domain and must not propagate."""
    path = tmp_path / "nrd.txt"
    path.write_text("fresh.test\n", encoding="utf-8")

    cache = build_nrd_cache(Settings(nrd_file=str(path)))
    assert cache.lookup("sub.fresh.test") is None


def test_an_unreachable_nrd_list_degrades_to_observation(tmp_path):
    cache = build_nrd_cache(Settings(nrd_file=str(tmp_path / "missing.txt")))
    assert cache is not None
    assert cache.ready is False


# -- through the engine ---------------------------------------------------

def test_the_module_runs_cleanly_through_the_engine():
    now = time.time()
    module, store = warm_module(now)
    store.observe("old.test", now=now - 90 * DAY)

    engine = DecisionEngine([module])
    fresh = engine.evaluate(ctx("brand-new.test", now))[0]
    old = engine.evaluate(ctx("old.test", now))[0]

    assert fresh.status == STATUS_OK and fresh.score == 1.0
    assert old.status == STATUS_OK and old.score == 0.0
    assert fresh.features["age_source"] == "first_seen"


def test_ti_and_nrd_produce_independent_evidence():
    """Both arms of the ablation must be separately attributable."""
    from engine.modules.ti import ThreatIntelModule

    now = time.time()
    ti_cache = IndicatorCache()
    ti_cache.apply(FeedSnapshot(feed="ti", domains={"evil.test"}))
    module, _ = warm_module(now)

    engine = DecisionEngine([ThreatIntelModule(ti_cache), module])
    results = engine.evaluate(ctx("evil.test", now))

    assert [r.module for r in results] == ["ti", "nrd"]
    assert results[0].score == 1.0     # listed
    assert results[1].score == 1.0     # and never seen before
    assert all(r.status == STATUS_OK for r in results)
