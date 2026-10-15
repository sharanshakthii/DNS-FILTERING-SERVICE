"""DNSF_PSL_MODE in each module.

`off` (the default) must reproduce the pre-PSL behaviour exactly — paper
mode and the Stage 16 harness depend on it. `icann` / `full` must fix the
cases the last-two-labels approximation got wrong.
"""

import time

import pytest

from config.settings import Settings
from engine.modules.base import QueryContext
from engine.modules.nrd import NewDomainModule
from engine.modules.rdap import RdapAgeModule, RegistrationShared
from engine.modules.typosquat import TyposquatModule
from feeds.base import FeedSnapshot
from feeds.cache import IndicatorCache
from feeds.first_seen import FirstSeenStore

DAY = 86400.0


def ctx(name):
    return QueryContext(qname=name, qtype="A", client_id="c",
                        timestamp=time.time())


def test_the_default_is_off_everywhere():
    s = Settings()
    assert s.psl_mode == "off"
    assert TyposquatModule.from_settings(Settings(typosquat_brands="x")).psl_mode == "off"
    assert NewDomainModule.from_settings(s).psl_mode == "off"
    assert RdapAgeModule.from_settings(s).psl_mode == "off"
    assert IndicatorCache().psl_mode == "off"


def test_an_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        IndicatorCache(psl_mode="sometimes")


# -- typosquat -------------------------------------------------------------

def typo(mode):
    return TyposquatModule(brands=["paypal"], official_domains=["paypal.com"],
                           psl_mode=mode)


@pytest.mark.parametrize("name", ["paypal.com", "paypa1.com", "paypal-login.com",
                                  "login.paypal.attacker.example",
                                  "paypal-login.co.uk", "paypal.pages.dev",
                                  "news.example.org"])
def test_typosquat_off_matches_the_legacy_module(name):
    legacy = TyposquatModule(brands=["paypal"], official_domains=["paypal.com"])
    assert typo("off").evaluate(ctx(name)) == legacy.evaluate(ctx(name))


def test_full_analyses_the_label_under_a_multi_label_suffix():
    off = typo("off").evaluate(ctx("paypal-secure.co.uk"))
    full = typo("full").evaluate(ctx("paypal-secure.co.uk"))
    # The old approximation analysed the label "co" and only caught the
    # brand by accident, as a "subdomain" of the suffix co.uk.
    assert off.features["registrable"] == "co.uk"
    assert off.features["signals"] == ["brand_in_subdomain"]
    assert full.features["registrable"] == "paypal-secure.co.uk"
    assert "brand_with_keyword" in full.features["signals"]
    assert full.score == pytest.approx(0.75)


def test_a_brand_site_on_a_shared_platform_is_still_detected():
    off = typo("off").evaluate(ctx("paypal.pages.dev"))
    full = typo("full").evaluate(ctx("paypal.pages.dev"))
    assert off.score == pytest.approx(0.6)
    assert full.score == pytest.approx(0.6), "no regression on this case"
    assert "brand_on_shared_platform" in full.features["signals"]


def test_a_site_name_containing_the_brand_on_a_platform_keeps_its_score():
    """Found on real data: these dropped to 0.4 before the rule covered them."""
    m = TyposquatModule(brands=["facebook"], official_domains=["facebook.com"],
                        psl_mode="full")
    result = m.evaluate(ctx("facebook-groups-new.blogspot.com"))
    assert result.score == pytest.approx(0.6)
    assert "brand_on_shared_platform" in result.features["signals"]


def test_the_brands_own_country_domain_is_no_longer_flagged():
    """google.com.ph scored 0.6 as 'brand in subdomain' of the suffix com.ph."""
    m = lambda mode: TyposquatModule(brands=["google"],
                                     official_domains=["google.com"],
                                     psl_mode=mode)
    assert m("off").evaluate(ctx("google.com.ph")).score == pytest.approx(0.6)
    assert m("full").evaluate(ctx("google.com.ph")).score == 0.0


def test_the_official_domain_stays_clean_in_every_mode():
    for mode in ("off", "icann", "full"):
        assert typo(mode).evaluate(ctx("www.paypal.com")).score == 0.0


# -- threat-intelligence parent matching ------------------------------------

def cache(mode, listed):
    c = IndicatorCache(psl_mode=mode)
    c.apply(FeedSnapshot(feed="f", domains=set(listed), source="t"))
    return c


def test_off_keeps_the_label_floor_behaviour():
    c = cache("off", ["pages.dev"])
    assert c.lookup("victim.pages.dev").match_type == "parent"


def test_full_never_spreads_a_listing_past_a_public_suffix():
    c = cache("full", ["pages.dev", "bad-site.pages.dev"])
    assert c.lookup("victim.pages.dev") is None
    assert c.lookup("pages.dev").match_type == "exact"
    assert c.lookup("x.bad-site.pages.dev").indicator == "bad-site.pages.dev"


def test_icann_mode_still_stops_at_co_uk():
    c = cache("icann", ["co.uk"])
    assert c.lookup("anything.co.uk") is None
    assert cache("off", ["co.uk"]).lookup("anything.co.uk") is not None


# -- nrd -------------------------------------------------------------------

def test_nrd_off_tracks_the_legacy_key():
    m = NewDomainModule(first_seen=FirstSeenStore())
    assert m._site("a.b.example.co.uk") == "co.uk"
    assert m._site("a.b.example.co.uk") == NewDomainModule._registrable(
        "a.b.example.co.uk")


def test_nrd_full_tracks_each_site_on_a_platform():
    m = NewDomainModule(first_seen=FirstSeenStore(), psl_mode="full")
    assert m._site("www.example.co.uk") == "example.co.uk"
    assert m._site("new-site.pages.dev") == "new-site.pages.dev"


# -- rdap ------------------------------------------------------------------

def rdap(mode, ages):
    calls = []

    def fetch(domain):
        calls.append(domain)
        return time.time() - ages[domain] * DAY

    return RdapAgeModule(fetch=fetch, psl_mode=mode), calls


def test_rdap_off_looks_up_the_legacy_key():
    module, calls = rdap("off", {"gov.uk": 9000})
    with pytest.raises(Exception):
        module.evaluate(ctx("www.local.gov.uk"))
    module.wait_idle()
    assert calls == ["gov.uk"]


def test_rdap_psl_looks_up_the_real_registration():
    module, calls = rdap("icann", {"local.gov.uk": 9000})
    with pytest.raises(Exception):
        module.evaluate(ctx("www.local.gov.uk"))
    module.wait_idle()
    assert calls == ["local.gov.uk"]
    assert module.evaluate(ctx("www.local.gov.uk")).score == 0.0


def test_rdap_full_refuses_to_score_a_platform_age():
    module, calls = rdap("full", {})
    with pytest.raises(RegistrationShared):
        module.evaluate(ctx("phish-site.pages.dev"))
    module.wait_idle()
    assert calls == [], "no lookup is sent for a shared-platform site"


def test_rdap_icann_mode_does_not_know_about_platforms():
    module, calls = rdap("icann", {"pages.dev": 3000})
    with pytest.raises(Exception):
        module.evaluate(ctx("phish-site.pages.dev"))
    module.wait_idle()
    assert calls == ["pages.dev"]
