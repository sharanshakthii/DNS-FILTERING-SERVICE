"""
Human-readable decision summaries.

The aggregator already records *what* happened: every module's score, its
weight, its weighted contribution, whether it counted, and the thresholds the
total was judged against. That is complete, and it is the thing the project
claims. It is also a wall of numbers.

This turns that record into one sentence naming the signals that actually
drove the verdict. It is a rendering, not a second source of truth: every
clause comes from a `ModuleResult` or from the aggregation the engine already
produced. Nothing here can say a module fired if it did not, because nothing
here has any input except those results.

**No new judgement is made.** The verdict, the score and the thresholds are
decided elsewhere and are only quoted. If a summary and the contribution
table ever disagree, the table is right and this is broken.
"""

from __future__ import annotations

from .modules.base import (
    STATUS_DISABLED,
    STATUS_OK,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    ModuleResult,
)

#: Plain names for the sentence. A module not listed here is named by its
#: identifier, which is ugly but never wrong.
FRIENDLY_NAMES = {
    "ti": "threat intelligence",
    "nrd": "domain age",
    "typosquat": "brand impersonation",
    "dga": "the DGA model",
    "beaconing": "query periodicity",
    "null": "the reference module",
}

#: A signal is described as "elevated" above this. It is a presentation
#: threshold for choosing words, and it never affects a score or a verdict.
ELEVATED_AT = 0.5


def friendly(module: str) -> str:
    return FRIENDLY_NAMES.get(module, module)


def _phrase_for(result: ModuleResult) -> str:
    """One clause describing what a module found, from its own evidence."""
    features = result.features or {}
    name = friendly(result.module)

    if result.module == "ti" and features.get("listed"):
        indicator = features.get("indicator")
        feed = features.get("feed")
        match = features.get("match_type")
        detail = f"matched {indicator}" if indicator else "matched an indicator"
        if match == "parent":
            detail = f"inherits a listing on {indicator}"
        if feed:
            detail += f" on the {feed} feed"
        return f"{name} {detail}"

    if result.module == "nrd":
        age = features.get("observed_age_s")
        if features.get("age_source") == "nrd_list":
            return f"{name} shows a recent registration"
        if age is not None and features.get("first_observation"):
            return f"{name} has never seen this domain before"
        if age is not None:
            return f"{name} first saw it {int(age)}s ago"
        return f"{name} scored {result.score:.2f}"

    if result.module == "typosquat" and features.get("matched_brand"):
        signals = features.get("signals") or []
        return (f"{name} resembles {features['matched_brand']}"
                f"{' (' + ', '.join(signals) + ')' if signals else ''}")

    if result.module == "dga":
        return f"{name} scored the label {result.score:.2f} DGA-like"

    if result.module == "beaconing":
        observations = features.get("observations")
        cv = features.get("coefficient_of_variation")
        median = features.get("median_interval_s")
        if observations and median is not None:
            return (f"{name} saw {observations} queries about {median:.0f}s "
                    f"apart (variation {cv:.2f})")
        return f"{name} scored {result.score:.2f}"

    return f"{name} scored {result.score:.2f}"


def _join(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def summarise(results: list[ModuleResult], aggregation: dict) -> str:
    """One sentence explaining the verdict, built from `results`.

    `aggregation` is the dict the RiskAggregator produced; only its verdict,
    score and thresholds are read.
    """
    verdict = aggregation.get("policy_verdict") or aggregation.get("verdict")
    score = aggregation.get("aggregate_score", 0.0)
    thresholds = aggregation.get("thresholds") or {}

    counted = [r for r in results if r.status == STATUS_OK]
    elevated = sorted((r for r in counted if r.score >= ELEVATED_AT),
                      key=lambda r: r.score, reverse=True)
    unavailable = [friendly(r.module) for r in results
                   if r.status == STATUS_UNAVAILABLE]
    failed = [friendly(r.module) for r in results
              if r.status not in (STATUS_OK, STATUS_UNAVAILABLE,
                                  STATUS_DISABLED, STATUS_SKIPPED)]

    if not results:
        return "No detection modules are configured, so nothing was assessed."

    if not counted:
        why = _join(unavailable + failed) or "every module"
        return (f"No verdict could be reached: {why} could not assess this "
                f"query, so no signal contributed.")

    if elevated:
        clauses = _join([_phrase_for(r) for r in elevated[:3]])
        # "Allowed because <an elevated signal>" is a contradiction: the
        # signal fired and the query was allowed anyway, because its weighted
        # share did not reach the threshold. "Despite" is what happened.
        lead = {"BLOCK": "Blocked because", "FLAG": "Flagged because"}.get(
            verdict, "Allowed despite")
        gate = ("block" if verdict == "BLOCK"
                else "flag" if verdict == "FLAG" else None)
        gate_text = ""
        if gate and thresholds.get(f"{gate}_at") is not None:
            gate_text = (f", at or above the {gate} threshold "
                         f"{thresholds[f'{gate}_at']}")
        sentence = (f"{lead} {clauses}. "
                    f"{len(elevated)} of {len(counted)} usable signal"
                    f"{'s' if len(counted) != 1 else ''} were elevated, "
                    f"giving a combined risk of {score:.2f}{gate_text}"
                    f"{'' if gate else ', below the flag threshold '
                       + str(thresholds.get('flag_at', ''))}.")
    else:
        sentence = (f"Allowed because no usable signal was elevated: "
                    f"{len(counted)} module"
                    f"{'s' if len(counted) != 1 else ''} ran and the combined "
                    f"risk was {score:.2f}.")

    if unavailable:
        sentence += (f" {_join(unavailable).capitalize()} could not assess "
                     f"this query and did not contribute.")
    if failed:
        sentence += f" {_join(failed).capitalize()} failed."

    return sentence
