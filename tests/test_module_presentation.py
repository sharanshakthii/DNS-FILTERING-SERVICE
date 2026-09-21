"""Tests for the dashboard's per-module presentation state.

`api.module_presentation.classify` reads only `status`, `score` and
`features` — the evidence the engine already produces — and must never
invent a state that evidence does not support. Every case here is built from
a real module's actual feature shape (see engine/modules/*.py), not a
hypothetical one.
"""

from api.module_presentation import (
    STATE_DETECTED,
    STATE_DISABLED,
    STATE_INSUFFICIENT_OBSERVATIONS,
    STATE_NOT_CONFIGURED,
    STATE_NO_MATCH,
    STATE_SKIPPED,
    STATE_UNAVAILABLE,
    attach_states,
    classify,
)


# -- detected ---------------------------------------------------------------

def test_a_ti_hit_is_detected():
    result = classify("ok", 1.0, {"listed": True, "indicator": "x.test",
                                  "feed": "f", "match_type": "exact"})
    assert result == {"state": STATE_DETECTED, "contributed": True}


def test_a_typosquat_match_is_detected():
    result = classify("ok", 0.9, {"matched_brand": "spotify",
                                  "signals": ["edit_distance"]})
    assert result == {"state": STATE_DETECTED, "contributed": True}


def test_a_dga_score_is_detected():
    result = classify("ok", 0.82, {"scored": True, "verdict_hint": "DGA-like"})
    assert result == {"state": STATE_DETECTED, "contributed": True}


# -- no match -----------------------------------------------------------

def test_a_ti_miss_is_no_match_not_a_blank_zero():
    result = classify("ok", 0.0, {"listed": False, "indicators": 4000})
    assert result == {"state": STATE_NO_MATCH, "contributed": True}


def test_a_typosquat_miss_is_no_match():
    result = classify("ok", 0.0, {"matched_brand": None,
                                  "reason": "no configured brand resembles "
                                            "this name"})
    assert result == {"state": STATE_NO_MATCH, "contributed": True}


def test_a_genuine_zero_with_no_explicit_flag_is_still_no_match():
    """A module without a dedicated flag still gets a correct, if less
    specific, no-match reading from the score alone."""
    result = classify("ok", 0.0, {"reason": "no rhythm to measure"})
    assert result == {"state": STATE_NO_MATCH, "contributed": True}


def test_a_near_zero_benign_dga_score_is_no_match_not_detected():
    """A DGA score is a continuous probability and is almost never exactly
    0.0. Without reading the module's own `verdict_hint`, a clearly-benign
    8e-05 would wrongly read as a "DETECTED" finding."""
    result = classify("ok", 0.00008, {"scored": True,
                                      "verdict_hint": "benign-like"})
    assert result == {"state": STATE_NO_MATCH, "contributed": True}


# -- not configured -------------------------------------------------------

def test_no_ti_feed_loaded_is_not_configured():
    result = classify("unavailable", 0.0, {
        "unavailable": "FeedUnavailable",
        "detail": "no threat-intelligence feed has loaded; cannot assess"})
    assert result == {"state": STATE_NOT_CONFIGURED, "contributed": False}


def test_no_brands_configured_is_not_configured():
    result = classify("unavailable", 0.0, {
        "unavailable": "BrandsUnavailable",
        "detail": "no brands configured; set DNSF_TYPOSQUAT_BRANDS to use "
                  "this module"})
    assert result == {"state": STATE_NOT_CONFIGURED, "contributed": False}


def test_no_dga_model_artifact_is_not_configured():
    result = classify("unavailable", 0.0, {
        "unavailable": "ModelUnavailable",
        "detail": "no model artifact at models/dga/dga_model.json"})
    assert result == {"state": STATE_NOT_CONFIGURED, "contributed": False}


def test_not_configured_is_not_a_normal_zero():
    """The state must never collapse to NO_MATCH just because the score is
    0.0 — that would make a missing feed look like a clean check."""
    result = classify("unavailable", 0.0, {"unavailable": "FeedUnavailable"})
    assert result["state"] != STATE_NO_MATCH


# -- insufficient observations --------------------------------------------

def test_too_few_beacon_observations_is_insufficient_observations():
    result = classify("unavailable", 0.0, {
        "unavailable": "InsufficientObservations",
        "detail": "2 observation(s) of x.test in the last 3600s; 4 are "
                  "needed before periodicity can be judged"})
    assert result == {"state": STATE_INSUFFICIENT_OBSERVATIONS,
                      "contributed": False}


def test_a_cold_nrd_observation_window_is_insufficient_observations():
    """`warming_up` is an OK, zero-score result — the module ran, but the
    observation window has not covered the threshold yet. It must not read
    as "checked, this domain is fine"."""
    result = classify("ok", 0.0, {
        "age_source": "first_seen", "warming_up": True,
        "warmup_remaining_s": 12.0})
    assert result == {"state": STATE_INSUFFICIENT_OBSERVATIONS,
                      "contributed": True}


def test_insufficient_observations_is_not_a_normal_zero():
    result = classify("unavailable", 0.0,
                      {"unavailable": "InsufficientObservations"})
    assert result["state"] != STATE_NO_MATCH


# -- unavailable / failed --------------------------------------------------

def test_a_module_error_is_unavailable_not_a_zero():
    result = classify("error", 0.0, {"error": "ValueError", "detail": "boom"})
    assert result == {"state": STATE_UNAVAILABLE, "contributed": False}


def test_an_invalid_score_is_unavailable():
    result = classify("invalid", 0.0, {"error": "score out of range"})
    assert result == {"state": STATE_UNAVAILABLE, "contributed": False}


def test_an_unrecognised_unavailable_reason_defaults_to_unavailable():
    """A future ModuleUnavailable subclass this function has never heard of
    must still read as "could not assess", not silently as a clean zero."""
    result = classify("unavailable", 0.0, {"unavailable": "SomeNewReason"})
    assert result == {"state": STATE_UNAVAILABLE, "contributed": False}


# -- disabled / skipped -----------------------------------------------------

def test_a_disabled_module_is_disabled():
    assert classify("disabled", 0.0, {}) == \
        {"state": STATE_DISABLED, "contributed": False}


def test_a_skipped_module_is_skipped():
    assert classify("skipped", 0.0, {"reason": "latency budget exhausted"}) == \
        {"state": STATE_SKIPPED, "contributed": False}


# -- attach_states ----------------------------------------------------------

def test_attach_states_adds_state_without_touching_other_fields():
    modules = [{"module": "ti", "score": 0.0, "status": "ok",
               "features": {"listed": False}, "latency_ms": 0.5}]
    enriched = attach_states(modules)

    assert enriched[0]["module"] == "ti"
    assert enriched[0]["score"] == 0.0
    assert enriched[0]["status"] == "ok"
    assert enriched[0]["latency_ms"] == 0.5
    assert enriched[0]["features"] == {"listed": False}
    assert enriched[0]["state"] == STATE_NO_MATCH
    assert enriched[0]["contributed"] is True


def test_attach_states_does_not_mutate_the_input():
    modules = [{"module": "ti", "score": 0.0, "status": "ok",
               "features": {"listed": False}, "latency_ms": 0.5}]
    attach_states(modules)
    assert "state" not in modules[0]
