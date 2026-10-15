"""
Risk aggregation.

Turns a list of module scores into one verdict, and — more importantly for
this project — into a record of *how* that verdict was reached. The evidence
trace is the contribution; the arithmetic below is not.

**The aggregation method is a weighted mean, and it is not novel.** Combining
weighted detector scores against a threshold is standard practice in every
commercial DNS reputation system and in the literature going back to
Antonakakis et al. (Notos, USENIX Security 2010). It is used here because it
is transparent: every term in the sum is separately reportable, which a
learned combiner would not be. The weights are configured defaults, **not
learned and not optimised**. Stage 16 is where they get tuned against
measured false positives. Any report that describes them as tuned before then
is describing something that has not happened.

Three properties the arithmetic has to preserve, carried forward from
Stage 4:

**A failed module is not a zero.** Modules that errored, returned nonsense,
were skipped past the budget, or were disabled are excluded from both the
numerator and the denominator. Averaging them in as 0.0 would drag the score
down on exactly the queries where something went wrong.

**No contributors is not "allow".** If modules are registered but none
produced a usable score, the verdict is UNKNOWN, not ALLOW. Those are
different claims and the database must be able to tell them apart.

**Deciding is not enforcing.** The policy verdict is always computed and
always recorded. Whether a BLOCK is acted upon is a separate, explicit
configuration choice (requirement SR3), so a system can be evaluated in
production traffic before it is trusted to interrupt it.
"""

from __future__ import annotations

import logging

from .modules.base import ModuleResult

log = logging.getLogger("engine.aggregator")

VERDICT_ALLOW = "ALLOW"
VERDICT_FLAG = "FLAG"
VERDICT_BLOCK = "BLOCK"
VERDICT_UNKNOWN = "UNKNOWN"

#: Starting weights. Rationale, not optimisation:
#: `ti` is a third party's explicit assertion that a domain is malicious, so
#: it carries the most weight. `nrd` is a correlate — most malicious domains
#: are young (Bilge et al., NDSS 2011), but most young domains are not
#: malicious — so on its own it must not reach the block threshold. `null`
#: detects nothing and is weighted accordingly.
DEFAULT_WEIGHTS: dict[str, float] = {
    "ti": 1.0,
    "nrd": 0.4,
    "null": 0.0,
}

DEFAULT_WEIGHT = 0.5      # for a module with no configured weight
DEFAULT_FLAG_AT = 0.5
DEFAULT_BLOCK_AT = 0.8


def parse_weights(spec: str) -> dict[str, float]:
    """Parse `ti=1.0,nrd=0.4` into a weight map.

    Raises on malformed input rather than skipping the bad entry: a silently
    dropped weight would change an ablation's results while the run still
    looked successful.
    """
    weights = dict(DEFAULT_WEIGHTS)
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError(
                f"malformed weight {item!r}; expected name=value, "
                f"e.g. 'ti=1.0,nrd=0.4'")
        name, _, raw = item.partition("=")
        try:
            value = float(raw)
        except ValueError as exc:
            raise ValueError(f"weight for {name.strip()!r} is not a number: "
                             f"{raw!r}") from exc
        if value < 0:
            raise ValueError(f"weight for {name.strip()!r} is negative")
        weights[name.strip()] = value
    return weights


class RiskAggregator:
    """Combines module results into a verdict plus a full derivation."""

    def __init__(self, weights: dict[str, float] | None = None,
                 flag_at: float = DEFAULT_FLAG_AT,
                 block_at: float = DEFAULT_BLOCK_AT,
                 default_weight: float = DEFAULT_WEIGHT,
                 enforce: bool = False,
                 fail_mode: str = "open",
                 decisive: frozenset[str] | set[str] = frozenset()) -> None:
        if not 0.0 <= flag_at <= 1.0:
            raise ValueError(f"flag_at must be within [0,1], got {flag_at}")
        if not 0.0 <= block_at <= 1.0:
            raise ValueError(f"block_at must be within [0,1], got {block_at}")
        if block_at < flag_at:
            raise ValueError(
                f"block_at ({block_at}) is below flag_at ({flag_at}); the FLAG "
                f"band would be empty and nothing could ever be flagged "
                f"without also being blocked")
        if fail_mode not in {"open", "closed"}:
            raise ValueError(f"fail_mode must be 'open' or 'closed', "
                             f"got {fail_mode!r}")

        self.weights = dict(weights) if weights is not None else dict(DEFAULT_WEIGHTS)
        self.flag_at = flag_at
        self.block_at = block_at
        self.default_weight = default_weight
        self.enforce = enforce
        self.fail_mode = fail_mode
        #: Modules whose confirmed hit sets a floor under the score. A third
        #: party's explicit listing is an assertion, not a hint, and averaging
        #: it with quiet heuristic modules would let it be diluted below the
        #: flag threshold (the Stage 16 finding).
        self.decisive = frozenset(decisive)

    def weight_for(self, module: str) -> float:
        return self.weights.get(module, self.default_weight)

    # -- aggregation -------------------------------------------------------

    def aggregate(self, results: list[ModuleResult]) -> dict:
        """Return {"verdict", "score", "explanation"} for one query.

        `explanation` is the per-decision evidence trace: every module, its
        raw score, its weight, its weighted contribution, and whether it
        counted. It is what lets a reviewer see why a domain was blocked
        rather than being told that it was.
        """
        contributions = []
        weighted_sum = 0.0
        counted_weight = 0.0

        for result in results:
            weight = self.weight_for(result.module)
            counted = result.counts_toward_score
            weighted = result.score * weight if counted else 0.0

            if counted:
                weighted_sum += weighted
                counted_weight += weight

            contributions.append({
                "module": result.module,
                "score": round(result.score, 6),
                "weight": weight,
                "weighted": round(weighted, 6),
                "status": result.status,
                "counted": counted,
            })

        excluded = [c["module"] for c in contributions if not c["counted"]]

        # No modules registered at all is a deliberate configuration, not a
        # failure: the operator asked for no detection and got none.
        if not results:
            return self._result(VERDICT_ALLOW, 0.0, {
                "method": "weighted_mean",
                "reason": "no modules registered",
                "contributions": [],
                "excluded": [],
            })

        # Modules registered but nothing usable came back. This is "we do not
        # know", which is not the same claim as "this is fine".
        counted = [c for c in contributions if c["counted"]]
        if not counted:
            log.warning("no module produced a usable score; excluded: %s",
                        ", ".join(excluded) or "none")
            return self._result(VERDICT_UNKNOWN, 0.0, {
                "method": "weighted_mean",
                "reason": "no module produced a usable score",
                "contributions": contributions,
                "excluded": excluded,
                "counted_weight": 0.0,
            })

        # Modules ran cleanly but every one of them is weighted zero. That is
        # an operator decision, not an outage, and must not be reported as
        # UNKNOWN — "we were told not to care" is a different claim from "we
        # could not find out".
        if counted_weight <= 0.0:
            return self._result(VERDICT_ALLOW, 0.0, {
                "method": "weighted_mean",
                "reason": "all contributing modules are weighted zero",
                "contributions": contributions,
                "excluded": excluded,
                "counted_weight": 0.0,
            })

        score = weighted_sum / counted_weight
        decisive_hits = [c["module"] for c in contributions
                         if c["counted"] and c["module"] in self.decisive
                         and c["score"] >= 1.0]
        if decisive_hits:
            score = 1.0
        # Guard against float drift pushing a value a hair outside [0,1].
        score = round(min(1.0, max(0.0, score)), 6)

        return self._result(self._verdict_for(score), score, {
            "method": "weighted_mean",
            "contributions": contributions,
            "excluded": excluded,
            "counted_weight": round(counted_weight, 6),
            "weighted_sum": round(weighted_sum, 6),
            **({"decisive_hit": decisive_hits,
                "decisive_note": "a confirmed threat-intelligence listing sets "
                                 "the score to 1.0 regardless of the mean"}
               if decisive_hits else {}),
        })

    def _verdict_for(self, score: float) -> str:
        if score >= self.block_at:
            return VERDICT_BLOCK
        if score >= self.flag_at:
            return VERDICT_FLAG
        return VERDICT_ALLOW

    def _result(self, policy_verdict: str, score: float,
                explanation: dict) -> dict:
        """Attach the enforcement decision without altering the policy verdict.

        Stage 7 downgraded a non-enforced BLOCK to FLAG in the returned
        verdict. Stage 8 stops doing that: the verdict is what the policy
        decided, always, and a separate `enforcement` block says what will
        actually happen to the query. Conflating the two made an observation
        run indistinguishable in the database from a genuine FLAG, which would
        have corrupted the Stage 16 counts — an observed BLOCK is a detection,
        not a borderline score.
        """
        would_block = policy_verdict == VERDICT_BLOCK
        reason = "policy verdict is BLOCK"

        if policy_verdict == VERDICT_UNKNOWN and self.fail_mode == "closed":
            # Fail-closed: refuse what we could not assess (requirement SR3).
            would_block = True
            reason = "fail_mode=closed and the query could not be assessed"

        applied = would_block and self.enforce

        enforcement = {
            "enabled": self.enforce,
            "would_block": would_block,
            "applied": applied,
            "action": "block" if applied else "forward",
            "fail_mode": self.fail_mode,
        }
        if would_block:
            enforcement["reason"] = reason
        if would_block and not self.enforce:
            enforcement["not_applied_reason"] = (
                "DNSF_AGGREGATOR_ENFORCE is false: the decision is recorded "
                "but the query is forwarded normally")

        explanation = {
            **explanation,
            "aggregate_score": score,
            "thresholds": {"flag_at": self.flag_at, "block_at": self.block_at},
            "policy_verdict": policy_verdict,
            "verdict": policy_verdict,
            "enforced": applied,
            "enforcement": enforcement,
            "fail_mode": self.fail_mode,
            "weights_are_tuned": False,
        }

        return {"verdict": policy_verdict, "score": score,
                "explanation": explanation, "enforcement": enforcement}

    @classmethod
    def from_settings(cls, settings) -> "RiskAggregator":
        return cls(
            weights=parse_weights(settings.aggregator_weights),
            flag_at=settings.aggregator_flag_at,
            block_at=settings.aggregator_block_at,
            default_weight=settings.aggregator_default_weight,
            enforce=settings.aggregator_enforce,
            fail_mode=settings.aggregator_fail_mode,
            decisive={"ti"} if getattr(settings, "aggregator_ti_decisive",
                                       False) else set(),
        )
