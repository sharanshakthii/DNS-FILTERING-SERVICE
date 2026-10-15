"""
Presentation states for module evidence.

The dashboard's problem was never missing data — every module already
records a `status` and a `features` dict that says exactly what happened.
The problem was that the dashboard flattened all of it down to a number, so
"checked, found nothing" (a real 0.00), "could not check" (no feed loaded)
and "have not seen enough yet" (too few observations) all rendered as the
same blank zero.

This module names which of those happened, from the evidence the engine
already produced. It computes nothing new: no score, no weight, no verdict.
It only reads `ModuleResult.status` (`engine/modules/base.py`) and the
`features` dict each module already attaches to its own evidence, and picks
one label. If this and the evidence ever disagree, this is wrong, not the
evidence.
"""

from __future__ import annotations

#: A clean run that found something worth reporting: a nonzero score with
#: evidence behind it.
STATE_DETECTED = "detected"

#: A clean run that checked and found nothing. Zero here is a real answer,
#: not a placeholder for "unknown".
STATE_NO_MATCH = "no_match"

#: The module ran but has nothing to check against — no feed loaded, no
#: brand list, no trained model. Distinct from a finding of "no match":
#: nothing was actually evaluated.
STATE_NOT_CONFIGURED = "not_configured"

#: The module ran but has not observed enough history to judge yet. Distinct
#: from "not configured": the module has everything it needs except time.
STATE_INSUFFICIENT_OBSERVATIONS = "insufficient_observations"

#: The module errored, returned something unusable, or was skipped past the
#: latency budget. Excluded from aggregation the same way NOT_CONFIGURED and
#: INSUFFICIENT_OBSERVATIONS are, but for a reason that is a fault rather
#: than an operating condition.
STATE_UNAVAILABLE = "unavailable"

#: Switched off for this run (ablation). Not evaluated at all.
STATE_DISABLED = "disabled"

#: Not run because the per-query latency budget was already spent.
STATE_SKIPPED = "skipped"

#: `ModuleUnavailable` subclasses (see engine/modules/*.py) that mean "there
#: is nothing here to check against" rather than "not enough history yet".
#: Keyed by the exception class name the engine already records in
#: `features["unavailable"]` (engine/decision.py `_run_one`), so this reads
#: an identifier the evidence already carries instead of guessing from text.
_NOT_CONFIGURED_EXCEPTIONS = frozenset({
    "FeedUnavailable",      # engine/modules/ti.py: no TI feed loaded
    "BrandsUnavailable",    # engine/modules/typosquat.py: no brands configured
    "ModelUnavailable",     # engine/modules/dga.py: no trained model artifact
})

#: `ModuleUnavailable` subclasses that mean "ran fine, but too little history
#: to judge yet".
_INSUFFICIENT_OBSERVATION_EXCEPTIONS = frozenset({
    "InsufficientObservations",   # engine/modules/beaconing.py
    "RegistrationPending",        # engine/modules/rdap.py: lookup in flight
})

#: Feature keys that a module sets to signal "this OK, zero-score result is
#: a positive check that found nothing" rather than a fallback. One entry
#: per module that reports this explicitly; a module without one still gets
#: a correct (if less specific) NO_MATCH from the score==0.0 fallback below.
_NO_MATCH_FEATURE = {
    "listed": False,           # engine/modules/ti.py
    "matched_brand": None,     # engine/modules/typosquat.py
    "verdict_hint": "benign-like",  # engine/modules/dga.py — see the note
    # in dga.py: the threshold "only decides the wording of `verdict_hint`",
    # which exists for exactly this presentation purpose. Reading it here is
    # not a second threshold decision, it is reading the one the module
    # already made. A DGA score is a continuous probability and is almost
    # never exactly 0.0, so without this a near-zero, clearly-benign score
    # would otherwise fall through to DETECTED on the score==0.0 check below.
}


def classify(status: str, score: float, features: dict | None) -> dict:
    """One presentation state for a module's evidence row.

    Returns `{"state": ..., "contributed": ...}`. `contributed` mirrors
    `ModuleResult.counts_toward_score` (status == "ok"), restated here so a
    caller does not need to import engine internals just to render a dot.
    """
    features = features or {}

    if status == "ok":
        if features.get("warming_up") is True:
            # engine/modules/nrd.py: the observation window has not yet
            # covered the "new" threshold, so nothing can be judged yet even
            # though the module ran cleanly and returned 0.0.
            return {"state": STATE_INSUFFICIENT_OBSERVATIONS, "contributed": True}
        for key, no_match_value in _NO_MATCH_FEATURE.items():
            if features.get(key, "__absent__") == no_match_value:
                return {"state": STATE_NO_MATCH, "contributed": True}
        if score == 0.0:
            return {"state": STATE_NO_MATCH, "contributed": True}
        return {"state": STATE_DETECTED, "contributed": True}

    if status == "unavailable":
        reason = features.get("unavailable")
        if reason in _INSUFFICIENT_OBSERVATION_EXCEPTIONS:
            return {"state": STATE_INSUFFICIENT_OBSERVATIONS, "contributed": False}
        if reason in _NOT_CONFIGURED_EXCEPTIONS:
            return {"state": STATE_NOT_CONFIGURED, "contributed": False}
        return {"state": STATE_UNAVAILABLE, "contributed": False}

    if status == "disabled":
        return {"state": STATE_DISABLED, "contributed": False}
    if status == "skipped":
        return {"state": STATE_SKIPPED, "contributed": False}

    # "error", "invalid", or anything unrecognised: the module ran and
    # produced garbage, or raised something that was not `ModuleUnavailable`.
    # Not a configuration gap and not a clean zero.
    return {"state": STATE_UNAVAILABLE, "contributed": False}


def attach_states(modules: list[dict]) -> list[dict]:
    """Return `modules` with a `state` (and `contributed`) key added to each.

    Every other key is passed through unchanged. This never touches `score`,
    `features`, or `status` — it only names what they already say.
    """
    enriched = []
    for module in modules:
        result = classify(module.get("status"), module.get("score"),
                          module.get("features"))
        enriched.append({**module, **result})
    return enriched
