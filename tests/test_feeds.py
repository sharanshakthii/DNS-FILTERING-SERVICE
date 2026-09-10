"""Stage 5 tests: feed parsing, the indicator cache, and the TI module.

The bar is not "a listed domain scores 1.0". It is that junk in a feed
cannot become a false positive, that a feed outage cannot masquerade as a
clean verdict, and that a half-loaded feed is never visible to a query.
"""

import threading
import time

import pytest

from engine.decision import DecisionEngine
from engine.modules.base import (
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    QueryContext,
)
from engine.modules.ti import FeedUnavailable, ThreatIntelModule
from feeds.base import (
    FeedSnapshot,
    FeedSource,
    normalise_domain,
    parse_domain_list,
    parse_hosts_file,
    parse_url_list,
)
from feeds.cache import IndicatorCache
from feeds.manager import FeedManager
from feeds.sources import (
    DEFAULT_FEED_URL,
    HttpFeedSource,
    LocalFileSource,
    build_urlhaus_source,
)


def ctx(qname):
    return QueryContext(qname=qname, qtype="A", client_id="cid",
                        timestamp=time.time())


def loaded_cache(domains, feed="testfeed", **kwargs):
    cache = IndicatorCache(**kwargs)
    cache.apply(FeedSnapshot(feed=feed, domains=set(domains)))
    return cache


# -- normalisation --------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("Evil.Example.COM", "evil.example.com"),
    ("  evil.test  ", "evil.test"),
    ("evil.test.", "evil.test"),
    ("*.evil.test", "evil.test"),
    ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),
])
def test_domains_are_normalised(raw, expected):
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "# a comment", "localhost", "not a domain",
    "192.168.1.1", "10.0.0.1", "evil.test:8080", "http://evil.test/path",
    "-bad.test", "bad-.test", "a..b.test", "évil.test",
])
def test_junk_is_rejected(raw):
    """Anything that cannot be a qname must never enter the index."""
    assert normalise_domain(raw) is None


def test_bare_ip_addresses_are_dropped():
    """An IP indicator can never match a qname; loading it inflates counts."""
    assert normalise_domain("203.0.113.5") is None


def test_overlong_names_are_rejected():
    assert normalise_domain(".".join(["a" * 63] * 5)) is None


# -- parsers --------------------------------------------------------------

def test_parse_domain_list():
    text = "# header\nevil.test\n\ngood.test  # trailing comment\nBAD.TEST\n"
    assert parse_domain_list(text) == {"evil.test", "good.test", "bad.test"}


def test_parse_hosts_file_skips_localhost():
    text = ("127.0.0.1 localhost\n"
            "0.0.0.0 evil.test\n"
            "0.0.0.0 a.test b.test\n"
            "malformed\n")
    assert parse_hosts_file(text) == {"evil.test", "a.test", "b.test"}


def test_parse_url_list_extracts_hosts():
    text = ("http://evil.test/payload.exe\n"
            "https://sub.bad.test:8080/x\n"
            "evil.test/other\n"
            "http://192.0.2.1/dropper\n")
    assert parse_url_list(text) == {"evil.test", "sub.bad.test"}


def test_parsers_deduplicate():
    assert parse_domain_list("evil.test\nEVIL.TEST\nevil.test.\n") == {"evil.test"}


# -- sources --------------------------------------------------------------

def test_local_file_source_reads_a_snapshot(tmp_path):
    path = tmp_path / "feed.txt"
    path.write_text("evil.test\nbad.test\n", encoding="utf-8")

    snapshot = LocalFileSource("local", str(path)).fetch()
    assert snapshot.ok
    assert snapshot.domains == {"evil.test", "bad.test"}
    assert snapshot.entry_count == 2


def test_a_missing_file_is_an_error_not_an_exception(tmp_path):
    """A feed failure is an operating condition, not a crash."""
    snapshot = LocalFileSource("local", str(tmp_path / "nope.txt")).fetch()
    assert not snapshot.ok
    assert "FileNotFoundError" in snapshot.error
    assert snapshot.entry_count == 0


def test_an_unknown_format_is_rejected_at_construction():
    with pytest.raises(ValueError, match="unknown feed format"):
        LocalFileSource("x", "y", fmt="yaml")


def test_a_source_that_raises_yields_an_error_snapshot():
    class Broken(FeedSource):
        def _read(self):
            raise ConnectionError("network unreachable")

    snapshot = Broken("broken").fetch()
    assert not snapshot.ok
    assert "ConnectionError" in snapshot.error


def test_urlhaus_requires_an_auth_key():
    """Mandatory at abuse.ch since 30 June 2025."""
    with pytest.raises(ValueError, match="Auth-Key"):
        build_urlhaus_source(url="https://example.invalid/feed", auth_key="")


def test_urlhaus_requires_an_explicit_url():
    """The export URL is per-account; guessing it would fail silently."""
    with pytest.raises(ValueError, match="export URL"):
        build_urlhaus_source(url="", auth_key="key")


def test_auth_key_is_sent_as_a_header():
    source = HttpFeedSource("x", "https://example.invalid/f", auth_key="secret")
    assert source.auth_key == "secret"
    assert source.build_request().get_header("Auth-key") == "secret"


# -- credential placement -------------------------------------------------
#
# Every value below is a placeholder. No real Auth-Key appears in this file,
# and none should ever be committed.

PLACEHOLDER_KEY = "not-a-real-auth-key-0000"


def test_the_header_is_omitted_when_the_url_already_carries_the_key():
    """Regression: abuse.ch bulk exports embed the key in the path.

    The same URL returns 200 with no header and 401 with one, so presenting
    the credential twice is not more authenticated — it fails.
    """
    source = HttpFeedSource(
        "urlhaus",
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{PLACEHOLDER_KEY}/recent.csv",
        auth_key=PLACEHOLDER_KEY)

    assert source.key_is_in_url is True
    assert source.build_request().get_header("Auth-key") is None


def test_the_header_is_sent_when_the_url_does_not_carry_the_key():
    """An API endpoint that expects the header must still get it."""
    source = HttpFeedSource("api", "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                            auth_key=PLACEHOLDER_KEY)

    assert source.key_is_in_url is False
    assert source.build_request().get_header("Auth-key") == PLACEHOLDER_KEY


def test_an_unauthenticated_feed_sends_no_auth_header():
    """The default public feed must keep working untouched."""
    source = HttpFeedSource("public", DEFAULT_FEED_URL)

    assert source.key_is_in_url is False
    assert source.build_request().get_header("Auth-key") is None


def test_the_user_agent_is_always_sent():
    for source in (HttpFeedSource("a", "https://example.invalid/f"),
                   HttpFeedSource("b", "https://example.invalid/f",
                                  auth_key=PLACEHOLDER_KEY)):
        assert source.build_request().get_header("User-agent")


def test_a_url_without_a_key_configured_is_not_treated_as_carrying_one():
    """Guards against pattern-matching a URL that merely looks like it has one."""
    source = HttpFeedSource(
        "x", "https://example.invalid/exports/abcdef123456/recent.csv")
    assert source.key_is_in_url is False


def test_the_key_is_never_placed_in_the_request_url_by_this_project():
    """The project does not construct credentialed URLs; the operator supplies
    one. A key must never be appended to a URL that did not already have it."""
    source = HttpFeedSource("x", "https://example.invalid/feed",
                            auth_key=PLACEHOLDER_KEY)
    assert PLACEHOLDER_KEY not in source.build_request().full_url


# -- the cache ------------------------------------------------------------

def test_exact_match():
    match = loaded_cache(["evil.test"]).lookup("evil.test")
    assert match.indicator == "evil.test"
    assert match.match_type == "exact"
    assert match.feed == "testfeed"


def test_lookup_is_case_and_dot_insensitive():
    cache = loaded_cache(["evil.test"])
    assert cache.lookup("EVIL.TEST").match_type == "exact"
    assert cache.lookup("evil.test.").match_type == "exact"


def test_subdomain_matches_its_listed_parent():
    match = loaded_cache(["evil.test"]).lookup("login.evil.test")
    assert match.indicator == "evil.test"
    assert match.match_type == "parent"


def test_a_clean_domain_does_not_match():
    assert loaded_cache(["evil.test"]).lookup("example.com") is None


def test_a_parent_is_not_matched_by_its_child():
    """Listing `a.evil.test` must not block `evil.test`."""
    assert loaded_cache(["a.evil.test"]).lookup("evil.test") is None


def test_partial_label_is_not_a_match():
    """`notevil.test` must not match an indicator of `evil.test`."""
    assert loaded_cache(["evil.test"]).lookup("notevil.test") is None


def test_parent_matching_can_be_disabled():
    cache = loaded_cache(["evil.test"], match_parents=False)
    assert cache.lookup("evil.test") is not None
    assert cache.lookup("login.evil.test") is None


def test_a_single_label_indicator_can_never_block_everything():
    """A feed listing a TLD must not take the internet down."""
    cache = loaded_cache(["com"])
    assert cache.lookup("example.com") is None
    assert cache.lookup("a.b.example.com") is None


def test_two_label_indicators_still_match_subdomains():
    assert loaded_cache(["evil.com"]).lookup("a.b.evil.com").match_type == "parent"


def test_refresh_replaces_rather_than_accumulates():
    """A domain removed from a feed must stop matching."""
    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"old.test"}))
    cache.apply(FeedSnapshot(feed="f", domains={"new.test"}))

    assert cache.lookup("new.test") is not None
    assert cache.lookup("old.test") is None
    assert cache.size == 1


def test_multiple_feeds_are_merged_and_attributed():
    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="alpha", domains={"a.test"}))
    cache.apply(FeedSnapshot(feed="beta", domains={"b.test"}))

    assert cache.size == 2
    assert cache.lookup("a.test").feed == "alpha"
    assert cache.lookup("b.test").feed == "beta"


def test_a_failed_fetch_keeps_the_previous_indicators():
    """Stale intelligence beats none; the age is reported so it can be judged."""
    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"evil.test"}))
    assert cache.apply(FeedSnapshot(feed="f", error="network down")) is False

    assert cache.lookup("evil.test") is not None
    assert cache.ready


def test_an_empty_cache_is_not_ready():
    assert IndicatorCache().ready is False
    assert IndicatorCache().staleness_s() is None


def test_staleness_is_reported():
    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"a.test"},
                             fetched_at=time.time() - 500))
    assert 495 < cache.staleness_s() < 520


def test_lookups_are_safe_while_a_refresh_runs():
    """A query must never observe a half-loaded feed."""
    cache = loaded_cache([f"d{i}.test" for i in range(500)])
    errors = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                if cache.lookup("d250.test") is None:
                    errors.append("indicator vanished mid-refresh")
            except Exception as exc:
                errors.append(repr(exc))

    threads = [threading.Thread(target=reader, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    for _ in range(30):
        cache.apply(FeedSnapshot(feed="testfeed",
                                 domains={f"d{i}.test" for i in range(500)}))
    stop.set()
    for t in threads:
        t.join(timeout=3)

    assert not errors, errors[:3]


# -- the manager ----------------------------------------------------------

def test_manager_refreshes_into_the_cache(tmp_path):
    path = tmp_path / "f.txt"
    path.write_text("evil.test\n", encoding="utf-8")

    manager = FeedManager([LocalFileSource("local", str(path))], interval_s=0)
    assert manager.refresh() == 1
    assert manager.cache.lookup("evil.test") is not None


def test_manager_reports_snapshots_to_a_callback(tmp_path):
    path = tmp_path / "f.txt"
    path.write_text("evil.test\nbad.test\n", encoding="utf-8")
    seen = []

    manager = FeedManager([LocalFileSource("local", str(path))], interval_s=0,
                          on_snapshot=seen.append)
    manager.refresh()

    assert len(seen) == 1
    assert seen[0].entry_count == 2


def test_a_failing_callback_does_not_break_a_refresh(tmp_path):
    path = tmp_path / "f.txt"
    path.write_text("evil.test\n", encoding="utf-8")

    def explode(_snapshot):
        raise RuntimeError("database is down")

    manager = FeedManager([LocalFileSource("local", str(path))], interval_s=0,
                          on_snapshot=explode)
    assert manager.refresh() == 1
    assert manager.cache.lookup("evil.test") is not None


def test_manager_counts_failures(tmp_path):
    manager = FeedManager([LocalFileSource("gone", str(tmp_path / "x.txt"))],
                          interval_s=0)
    assert manager.refresh() == 0
    assert manager.failure_count == 1


# -- the module -----------------------------------------------------------

def test_a_listed_domain_scores_one():
    module = ThreatIntelModule(loaded_cache(["evil.test"]))
    score = module.evaluate(ctx("evil.test"))

    assert score.score == 1.0
    assert score.features["listed"] is True
    assert score.features["indicator"] == "evil.test"
    assert score.features["match_type"] == "exact"
    assert score.features["feed"] == "testfeed"


def test_a_clean_domain_scores_zero_with_evidence():
    score = ThreatIntelModule(loaded_cache(["evil.test"])).evaluate(
        ctx("example.com"))
    assert score.score == 0.0
    assert score.features["listed"] is False
    assert score.features["indicators"] == 1


def test_features_always_report_feed_age_and_size():
    """The evidence has to be interpretable without the feed in hand."""
    features = ThreatIntelModule(loaded_cache(["evil.test"])).evaluate(
        ctx("example.com")).features
    assert "feed_age_s" in features
    assert "indicators" in features
    assert features["stale"] is False


def test_staleness_is_flagged_in_the_evidence():
    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"evil.test"},
                             fetched_at=time.time() - 200_000))
    features = ThreatIntelModule(cache, stale_after_s=86400).evaluate(
        ctx("evil.test")).features
    assert features["stale"] is True


def test_a_parent_match_is_scored_separately():
    """Parent inference is ours, not the feed's, and must be distinguishable."""
    module = ThreatIntelModule(loaded_cache(["evil.test"]), parent_score=0.7)
    score = module.evaluate(ctx("login.evil.test"))
    assert score.score == 0.7
    assert score.features["match_type"] == "parent"


def test_an_empty_cache_raises_rather_than_scoring_zero():
    """A feed outage must not look identical to a clean verdict."""
    with pytest.raises(FeedUnavailable):
        ThreatIntelModule(IndicatorCache()).evaluate(ctx("anything.test"))


def test_the_engine_records_a_feed_outage_as_unavailable():
    """Stage 15 split "could not assess" out of "something went wrong".

    A feed that has not loaded is not a fault in this module, so it is now
    STATUS_UNAVAILABLE rather than STATUS_ERROR. The behaviour that matters
    is unchanged and still asserted: excluded from aggregation, never a
    score of 0.0.
    """
    engine = DecisionEngine([ThreatIntelModule(IndicatorCache())])
    result = engine.evaluate(ctx("anything.test"))[0]

    assert result.status == STATUS_UNAVAILABLE
    assert result.status != STATUS_ERROR
    assert result.features["unavailable"] == "FeedUnavailable"
    assert result.counts_toward_score is False


def test_the_module_returns_valid_scores_through_the_engine():
    engine = DecisionEngine([ThreatIntelModule(loaded_cache(["evil.test"]))])
    listed = engine.evaluate(ctx("evil.test"))[0]
    clean = engine.evaluate(ctx("example.com"))[0]

    assert listed.status == STATUS_OK and listed.score == 1.0
    assert clean.status == STATUS_OK and clean.score == 0.0
    assert listed.latency_ms >= 0.0


def test_lookup_stays_fast_on_a_large_feed():
    """Guards against anyone making this a network or database call.

    Not a performance result — a tripwire. A per-query round trip would
    dominate the latency figures RQ2 reports.
    """
    cache = loaded_cache([f"d{i}.test" for i in range(50_000)])
    module = ThreatIntelModule(cache)

    start = time.perf_counter()
    for i in range(1000):
        module.evaluate(ctx(f"d{i}.test"))
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < 500, f"1000 lookups took {elapsed_ms:.0f} ms"


# -- persistence ----------------------------------------------------------

def test_feed_state_is_persisted(tmp_path):
    from storage.db import Database

    db = Database(str(tmp_path / "f.sqlite3"))
    try:
        db.upsert_feed_state("testfeed", "2026-09-01T00:00:00Z", 1234, 60.0)
        rows = db.feed_states()
        assert len(rows) == 1
        assert rows[0]["feed"] == "testfeed"
        assert rows[0]["entry_count"] == 1234

        db.upsert_feed_state("testfeed", "2026-09-01T01:00:00Z", 5678, 30.0)
        rows = db.feed_states()
        assert len(rows) == 1, "upsert created a duplicate row"
        assert rows[0]["entry_count"] == 5678
    finally:
        db.close()


def test_an_outage_does_not_disable_a_loaded_signal():
    """Regression: `ready` once tracked the last fetch, so one failed refresh
    turned the TI module off entirely while good indicators were still held."""
    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"evil.test"}))
    cache.apply(FeedSnapshot(feed="f", error="network down"))

    module = ThreatIntelModule(cache)
    score = module.evaluate(ctx("evil.test"))
    assert score.score == 1.0, "a transient outage silenced a working signal"


def test_staleness_keeps_growing_through_an_outage():
    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"evil.test"},
                             fetched_at=time.time() - 1000))
    cache.apply(FeedSnapshot(feed="f", error="network down"))
    assert cache.staleness_s() > 990, "the age reset on a failed fetch"


# -- URLhaus CSV parsing --------------------------------------------------
#
# Every value below is fabricated. `*.test` is reserved by RFC 6761 and the
# IP addresses are RFC 5737 documentation ranges, so no real malicious host
# and no real credential appears in this file.

#: The classic abuse.ch database dump: comment block, then a header that is
#: itself a comment, then quoted rows. Confirmed layout.
FAKE_CLASSIC_CSV = '''\
# URLhaus database dump (CSV)
# Last updated: 2026-09-08 00:00:00 (UTC)
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-09-08 10:00:00","http://malware-demo.test/payload.bin","online","","malware_download","elf","https://urlhaus.abuse.ch/url/1/","reporter_one"
"2","2026-09-08 10:01:00","http://203.0.113.5/dropper.sh","online","","malware_download","","","reporter_two"
"3","2026-09-08 10:02:00","https://second-demo.test:8443/a","offline","","malware_download","","","reporter_one"
"4","2026-09-08 10:03:00","http://malware-demo.test/other.bin","online","","malware_download","","","reporter_one"
'''

#: The ASN feed: header as an ordinary row, with a separate Host column.
#: Confirmed layout.
FAKE_ASN_CSV = '''\
# URLhaus ASN CSV Feed
# Generated on 2026-09-08 00:00:00 UTC
Dateadded (UTC),URL,URL_status,Threat,Tags,Host,IPaddress,ASnumber,Country
"2026-09-08 10:00:00","http://asn-demo.test/p","online","malware_download","x","asn-demo.test","198.51.100.7","64500","XX"
"2026-09-08 10:01:00","http://198.51.100.9/q","offline","malware_download","","198.51.100.9","198.51.100.9","64500","XX"
'''


def test_the_csv_parser_is_registered():
    from feeds.base import PARSERS, parse_urlhaus_csv

    assert PARSERS["csv"] is parse_urlhaus_csv


def test_the_classic_dump_layout_is_parsed():
    """Header lives inside the comment block, so comments cannot just be
    discarded before looking at them."""
    from feeds.base import parse_urlhaus_csv

    assert parse_urlhaus_csv(FAKE_CLASSIC_CSV) == {
        "malware-demo.test", "second-demo.test"}


def test_the_asn_feed_layout_is_parsed():
    """Header is an ordinary row and a Host column exists."""
    from feeds.base import parse_urlhaus_csv

    assert parse_urlhaus_csv(FAKE_ASN_CSV) == {"asn-demo.test"}


def test_bare_ip_rows_are_dropped():
    """An IP indicator can never match a queried name.

    URLhaus is largely IP-based, so a large CSV legitimately yields far fewer
    domains than it has rows. That is correct, not a parsing failure.
    """
    from feeds.base import parse_urlhaus_csv

    domains = parse_urlhaus_csv(FAKE_CLASSIC_CSV)
    assert "203.0.113.5" not in domains
    assert not any(d.replace(".", "").isdigit() for d in domains)


def test_duplicate_urls_collapse_to_one_domain():
    from feeds.base import parse_urlhaus_csv

    # Rows 1 and 4 share a host.
    assert sum(1 for d in parse_urlhaus_csv(FAKE_CLASSIC_CSV)
               if d == "malware-demo.test") == 1


def test_a_port_in_the_url_does_not_leak_into_the_domain():
    from feeds.base import parse_urlhaus_csv

    assert "second-demo.test" in parse_urlhaus_csv(FAKE_CLASSIC_CSV)
    assert "second-demo.test:8443" not in parse_urlhaus_csv(FAKE_CLASSIC_CSV)


def test_an_unknown_header_falls_back_to_scanning_the_row():
    """A renamed column must degrade to a slower parse, not a silent nothing.

    The bug being fixed was exactly this shape: the download succeeded and
    produced an empty indicator set.
    """
    from feeds.base import parse_urlhaus_csv

    unknown = ('colA,colB,colC\n'
               '"2026-09-08","http://fallback-demo.test/z","note"\n')
    assert parse_urlhaus_csv(unknown) == {"fallback-demo.test"}


@pytest.mark.parametrize("text", [
    "", "\n\n", "# only comments\n#\n",
    "# id,dateadded,url\n", "not,a,real,row\n",
])
def test_empty_or_malformed_input_yields_an_empty_set_without_raising(text):
    from feeds.base import parse_urlhaus_csv

    assert parse_urlhaus_csv(text) == set()


def test_ragged_and_blank_rows_are_survived():
    from feeds.base import parse_urlhaus_csv

    ragged = ('# id,dateadded,url,url_status\n'
              '"1","2026-09-08","http://ragged-demo.test/a"\n'      # short row
              '\n'
              '"2"\n'                                               # one field
              '"3","2026-09-08","http://ragged-two.test/b","online","extra"\n')
    assert parse_urlhaus_csv(ragged) == {"ragged-demo.test", "ragged-two.test"}


def test_the_csv_parser_reaches_a_feed_source(tmp_path):
    """End to end through the existing source machinery, offline."""
    path = tmp_path / "urlhaus.csv"
    path.write_text(FAKE_CLASSIC_CSV, encoding="utf-8")

    snapshot = LocalFileSource("urlhaus", str(path), fmt="csv").fetch()
    assert snapshot.ok
    assert snapshot.domains == {"malware-demo.test", "second-demo.test"}
    assert snapshot.entry_count == 2


def test_the_existing_parsers_are_unchanged():
    """The csv parser is additive; nothing else may have moved."""
    from feeds.base import (
        PARSERS,
        parse_domain_list,
        parse_hosts_file,
        parse_url_list,
    )

    assert PARSERS["domains"] is parse_domain_list
    assert PARSERS["hosts"] is parse_hosts_file
    assert PARSERS["urls"] is parse_url_list
    assert parse_domain_list("evil.test\n") == {"evil.test"}
    assert parse_hosts_file("0.0.0.0 evil.test\n") == {"evil.test"}
    assert parse_url_list("http://evil.test/x\n") == {"evil.test"}


def test_no_real_credential_appears_in_these_fixtures():
    assert "abuse.ch/v2/files/exports" not in FAKE_CLASSIC_CSV
    for fixture in (FAKE_CLASSIC_CSV, FAKE_ASN_CSV):
        assert ".test" in fixture
