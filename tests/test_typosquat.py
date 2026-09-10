"""Stage 12 tests: typosquat / brand impersonation.

The hard part of this signal is not finding near-miss spellings, it is not
firing on the brand itself and not firing on ordinary names. Most of what
follows is about those two failure modes, because a lexical detector that
flags `spotify.com` is worse than no detector at all.

Deterministic throughout: a fixed brand list, no external service, no
network.
"""

import time

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
from engine.modules.null import FixedScoreModule
from engine.modules.typosquat import (
    BrandsUnavailable,
    TyposquatModule,
    decode_punycode,
    levenshtein,
    max_distance_for,
    normalise_confusables,
    parse_list,
)
from proxy.dns_proxy import build_engine

BRANDS = ["spotify", "google", "microsoft", "amazon"]
OFFICIAL = ["spotify.com", "google.com", "microsoft.com", "amazon.com"]


def module(**kwargs) -> TyposquatModule:
    kwargs.setdefault("brands", BRANDS)
    kwargs.setdefault("official_domains", OFFICIAL)
    return TyposquatModule(**kwargs)


def ctx(qname: str) -> QueryContext:
    return QueryContext(qname=qname, qtype="A", client_id="cid",
                        timestamp=time.time())


def score_of(qname: str, **kwargs) -> float:
    return module(**kwargs).evaluate(ctx(qname)).score


def features_of(qname: str, **kwargs) -> dict:
    return module(**kwargs).evaluate(ctx(qname)).features


# -- edit distance ---------------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("spotify", "spotify", 0),
    ("spotify", "spotifz", 1),      # substitution
    ("spotify", "spotif", 1),       # deletion
    ("spotify", "spotiify", 1),     # insertion
    ("spotify", "spotfiy", 2),      # transposition costs two edits
    ("", "abc", 3),
    ("abc", "", 3),
])
def test_levenshtein_is_correct(a, b, expected):
    assert levenshtein(a, b) == expected


def test_levenshtein_cap_short_circuits():
    """The cap exists so a long unrelated label is abandoned early."""
    assert levenshtein("a" * 40, "b" * 40, cap=2) == 3


def test_max_distance_scales_with_brand_length():
    """One edit means more in a short brand than a long one."""
    assert max_distance_for("bank") == 1
    assert max_distance_for("spotify") == 2
    assert max_distance_for("microsoft") == 3


# -- confusables and punycode ---------------------------------------------

@pytest.mark.parametrize("label,expected", [
    ("sp0tify", "spotify"),
    ("g00gle", "google"),
    ("micros0ft", "microsoft"),
    ("rnicrosoft", "microsoft"),   # rn renders like m
    ("spotify", "spotify"),
])
def test_confusables_fold_to_the_brand(label, expected):
    assert normalise_confusables(label) == expected


def test_punycode_labels_are_compared_decoded():
    decoded, was_decoded = decode_punycode("xn--80ak6aa92e")
    assert was_decoded is True
    assert decoded != "xn--80ak6aa92e"


def test_malformed_punycode_is_left_alone_rather_than_dropped():
    decoded, was_decoded = decode_punycode("xn--")
    assert was_decoded is False
    assert decoded == "xn--"


def test_a_normal_label_is_not_treated_as_punycode():
    assert decode_punycode("spotify") == ("spotify", False)


# -- the brand itself must never be flagged -------------------------------

def test_the_official_brand_domain_scores_zero():
    """The single most important false positive to avoid."""
    result = module().evaluate(ctx("spotify.com"))
    assert result.score == 0.0
    assert result.features["matched_brand"] is None
    assert "official list" in result.features["reason"]


def test_a_subdomain_of_the_official_domain_scores_zero():
    assert score_of("open.spotify.com") == 0.0
    assert score_of("accounts.google.com") == 0.0


@pytest.mark.parametrize("qname", ["SPOTIFY.COM", "Spotify.Com", "spotify.com."])
def test_case_and_trailing_dot_are_normalised(qname):
    assert score_of(qname) == 0.0


def test_an_unrelated_domain_scores_zero():
    result = module().evaluate(ctx("example.org"))
    assert result.score == 0.0
    assert result.features["matched_brand"] is None
    assert "no configured brand resembles" in result.features["reason"]


@pytest.mark.parametrize("qname", [
    "wikipedia.org", "python.org", "some-company.co", "news.bbc.example",
])
def test_ordinary_names_produce_no_signal(qname):
    assert score_of(qname) == 0.0


# -- the detections --------------------------------------------------------

def test_brand_plus_suspicious_keyword_is_flagged():
    result = module().evaluate(ctx("spotifyapk.com"))
    assert result.score == pytest.approx(0.75)
    assert result.features["matched_brand"] == "spotify"
    assert result.features["suspicious_keyword"] == "apk"
    assert "brand_with_keyword" in result.features["signals"]


@pytest.mark.parametrize("qname,keyword", [
    ("amazon-support.com", "support"),
    ("microsoftlogin.com", "login"),
    ("googleverify.com", "verify"),
])
def test_other_brand_keyword_combinations(qname, keyword):
    features = features_of(qname)
    assert features["suspicious_keyword"] == keyword
    assert "brand_with_keyword" in features["signals"]


def test_transposition_is_detected():
    result = module().evaluate(ctx("spotfiy.com"))
    assert "transposition" in result.features["signals"]
    assert result.score >= 0.85


@pytest.mark.parametrize("qname,signal", [
    ("spotifz.com", "edit_distance"),    # substitution
    ("spotif.com", "edit_distance"),     # deletion
    ("spotiify.com", "edit_distance"),   # insertion
    ("gooogle.com", "edit_distance"),
])
def test_single_edit_variants_are_detected(qname, signal):
    features = features_of(qname)
    assert signal in features["signals"]
    assert features["edit_distance"] == 1


def test_confusable_substitution_is_detected():
    result = module().evaluate(ctx("sp0tify.com"))
    assert "confusable_characters" in result.features["signals"]
    assert result.score >= 0.85


def test_a_brand_in_a_subdomain_of_an_unrelated_domain_is_flagged():
    """The classic login.brand.attacker.example pattern."""
    result = module().evaluate(ctx("login.spotify.attacker.example"))
    assert result.features["matched_brand"] == "spotify"
    assert "brand_in_subdomain" in result.features["signals"]
    assert result.score >= 0.6


def test_multiple_labels_are_all_examined():
    features = features_of("a.b.spotify.evil.example")
    assert len(features["labels_examined"]) == 5
    assert features["registrable"] == "evil.example"


# -- scoring rules ---------------------------------------------------------

def test_two_independent_signals_score_higher_than_one():
    """The combination bonus, and the reason it exists."""
    one = module().evaluate(ctx("spotifz.com"))
    two = module().evaluate(ctx("sp0tify.com"))

    assert len(one.features["signals"]) == 1
    assert len(two.features["signals"]) >= 2
    assert two.features["combination_bonus_applied"] is True
    assert two.score > one.score


def test_the_bonus_is_not_applied_to_a_single_signal():
    assert features_of("spotifz.com")["combination_bonus_applied"] is False


@pytest.mark.parametrize("qname", [
    "spotify.com", "spotifyapk.com", "spotfiy.com", "sp0tify.com",
    "spotifz.com", "example.org", "a.b.c.d.e.f.spotify.example",
    "xn--80ak6aa92e.com", "microsoftaccountloginverifysecure.com",
])
def test_the_score_is_always_within_range(qname):
    result = module().evaluate(ctx(qname))
    assert 0.0 <= result.score <= 1.0
    assert result.is_valid()


def test_a_pile_of_signals_is_capped_at_one():
    assert score_of("sp0tfiy-login-verify.com") <= 1.0


# -- configuration ---------------------------------------------------------

def test_no_brands_configured_raises_rather_than_scoring_zero():
    """An unconfigured module cannot check, which is not the same as clean."""
    with pytest.raises(BrandsUnavailable):
        TyposquatModule(brands=[]).evaluate(ctx("anything.test"))


def test_the_engine_records_an_unconfigured_module_as_unavailable():
    """Stage 15: no brands configured is "cannot assess", not a failure."""
    result = DecisionEngine([TyposquatModule(brands=[])]).evaluate(
        ctx("anything.test"))[0]
    assert result.status == STATUS_UNAVAILABLE
    assert result.features["unavailable"] == "BrandsUnavailable"
    assert result.counts_toward_score is False


def test_the_brand_list_is_configurable():
    """A brand nobody configured must not be detected."""
    assert score_of("spotifyapk.com", brands=["google"],
                    official_domains=[]) == 0.0
    assert score_of("spotifyapk.com", brands=["spotify"],
                    official_domains=[]) > 0.0


def test_the_keyword_list_is_configurable():
    custom = module(keywords=["tickets"])
    assert custom.evaluate(ctx("spotifytickets.com")).features[
        "suspicious_keyword"] == "tickets"
    assert "brand_with_keyword" not in \
        custom.evaluate(ctx("spotifyapk.com")).features["signals"]


def test_without_an_official_list_the_brand_label_is_not_flagged():
    """`spotify.com` must still be safe when no official list is configured."""
    assert score_of("spotify.com", official_domains=[]) == 0.0


def test_parse_list_normalises_and_deduplicates():
    assert parse_list(" Spotify , google ,, spotify ") == ["spotify", "google"]
    assert parse_list("") == []


def test_settings_default_to_no_brands():
    """No defensible built-in list of 'the brands that matter' exists."""
    assert Settings().typosquat_brands == ""
    assert TyposquatModule.from_settings(Settings()).brands == []


def test_settings_are_read_through_from_settings():
    built = TyposquatModule.from_settings(Settings(
        typosquat_brands="spotify,google",
        typosquat_official_domains="spotify.com",
        typosquat_keywords="apk"))
    assert built.brands == ["spotify", "google"]
    assert built.official_domains == {"spotify.com"}
    assert built.keywords == {"apk"}


# -- invalid input ---------------------------------------------------------

@pytest.mark.parametrize("qname", ["", "   ", "."])
def test_an_empty_name_produces_no_signal_without_raising(qname):
    result = module().evaluate(ctx(qname))
    assert result.score == 0.0
    assert result.is_valid()


def test_a_single_label_name_is_handled():
    result = module().evaluate(ctx("localhost"))
    assert 0.0 <= result.score <= 1.0


def test_a_very_long_name_does_not_break_scoring():
    result = module().evaluate(ctx(".".join(["a" * 60] * 3)))
    assert result.is_valid()


# -- evidence --------------------------------------------------------------

def test_the_evidence_explains_the_score():
    features = features_of("spotifyapk.com")
    for key in ["qname", "registrable", "labels_examined", "matched_brand",
                "label_examined", "edit_distance", "similarity",
                "suspicious_keyword", "signals", "signal_scores", "reason"]:
        assert key in features, f"evidence is missing {key!r}"

    assert features["qname"] == "spotifyapk.com"
    assert features["registrable"] == "spotifyapk.com"
    assert features["signal_scores"]["brand_with_keyword"] == 0.75
    assert "apk" in features["reason"]


def test_the_evidence_is_json_serialisable():
    """It has to survive the storage layer and the API unchanged."""
    import json

    from storage.models import EvidenceRow

    result = module().evaluate(ctx("sp0tify.com"))
    row = EvidenceRow.from_payload({
        "module": "typosquat", "score": result.score,
        "features": result.features, "latency_ms": 0.1, "status": "ok"})
    restored = json.loads(row.features_json())
    assert restored["matched_brand"] == "spotify"
    assert "_unserialisable" not in restored


def test_the_evidence_never_claims_a_domain_is_malicious():
    """A signal is not a finding. The wording matters in a report."""
    text = " ".join(str(v) for v in features_of("spotifyapk.com").values()).lower()
    for word in ["malicious", "malware", "confirmed", "proven"]:
        assert word not in text


# -- registration and integration -----------------------------------------

def test_the_module_is_registered_under_its_name():
    assert REGISTRY["typosquat"] is TyposquatModule
    assert TyposquatModule.name == "typosquat"


def test_the_module_builds_through_the_startup_path():
    engine = build_engine(Settings(engine_modules="typosquat", db_enabled=False,
                                   typosquat_brands="spotify"))
    try:
        assert engine.name == "engine[typosquat]"
        assert engine.modules[0].brands == ["spotify"]
    finally:
        engine.close()


def test_typosquat_takes_the_default_weight():
    """It is deliberately absent from DEFAULT_WEIGHTS.

    Adding it would change the aggregator's defaults, which Stage 12 has no
    evidence to justify. 0.5 is the unlisted-module default and it is
    configurable through DNSF_AGGREGATOR_WEIGHTS.
    """
    from engine.aggregator import DEFAULT_WEIGHTS, RiskAggregator

    assert "typosquat" not in DEFAULT_WEIGHTS
    assert RiskAggregator().weight_for("typosquat") == 0.5


def test_ti_and_typosquat_aggregate_together_unchanged():
    """Adding a module must not disturb the existing aggregation."""
    engine = DecisionEngine([FixedScoreModule("ti", 1.0), module()])
    results = engine.evaluate(ctx("spotifyapk.com"))

    assert [r.module for r in results] == ["ti", "typosquat"]
    assert all(r.status == STATUS_OK for r in results)

    aggregated = engine.aggregator.aggregate(results)
    # (1.0 x 1.0 + 0.75 x 0.5) / (1.0 + 0.5)
    assert aggregated["score"] == pytest.approx(1.375 / 1.5, abs=1e-6)
    assert aggregated["explanation"]["counted_weight"] == 1.5


def test_disabling_typosquat_restores_the_previous_score():
    """Ablation: the ti-only result must be identical to before."""
    engine = DecisionEngine([FixedScoreModule("ti", 1.0), module()])
    engine.set_enabled("typosquat", False)

    aggregated = engine.aggregator.aggregate(engine.evaluate(ctx("spotifyapk.com")))
    assert aggregated["score"] == 1.0
    assert aggregated["explanation"]["excluded"] == ["typosquat"]
    assert aggregated["explanation"]["counted_weight"] == 1.0


def test_typosquat_does_not_alter_ti_or_nrd_behaviour():
    """The other modules must be untouched by this one running alongside."""
    from feeds.base import FeedSnapshot
    from feeds.cache import IndicatorCache
    from engine.modules.ti import ThreatIntelModule

    cache = IndicatorCache()
    cache.apply(FeedSnapshot(feed="f", domains={"spotifyapk.com"}))

    alone = ThreatIntelModule(cache).evaluate(ctx("spotifyapk.com"))
    together = DecisionEngine([ThreatIntelModule(cache), module()]).evaluate(
        ctx("spotifyapk.com"))[0]

    assert alone.score == together.score == 1.0
    assert together.features["match_type"] == "exact"
