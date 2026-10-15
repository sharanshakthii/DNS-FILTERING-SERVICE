"""
The decision engine.

Runs the registered modules over one query and assembles the evidence. It
does not aggregate risk and it does not block: verdict logic arrives in
Stage 7 and blocking in Stage 8. Until then every verdict is ALLOW, and the
engine says so in its name rather than implying detection it does not do.

Three properties matter more than anything else here.

**Fault isolation (NFR2).** A module that raises, hangs past the budget, or
returns nonsense is recorded as such and excluded. Resolution continues on
the remaining signals. A DNS resolver that stops resolving because one
heuristic threw an exception is worse than useless — it is an outage.

**Honest exclusion.** A failed module is never recorded as scoring 0.0. Zero
means "ran, found nothing"; a failure means "we do not know". Collapsing the
two would understate risk on precisely the queries where something went
wrong, and would silently bias every experiment that counts them.

**Identical code path across configurations.** Ablation switches modules off
through `enabled`, not by taking a different branch. TI-only and hybrid runs
execute the same dispatch, timing, and assembly code, so a latency difference
between them is a property of the configuration and not of two
implementations.
"""

from __future__ import annotations

import logging
import time

from .aggregator import RiskAggregator
from .explain import summarise
from .modules.base import (
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_INVALID,
    STATUS_OK,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    DetectionModule,
    ModuleUnavailable,
    ModuleResult,
    QueryContext,
)

log = logging.getLogger("engine")


class DecisionEngine:
    """Dispatches a query to every registered module and collects evidence."""

    def __init__(self, modules: list[DetectionModule] | None = None,
                 budget_ms: float = 50.0,
                 aggregator: RiskAggregator | None = None,
                 allowlist=None) -> None:
        """`budget_ms` caps the total time modules may spend on one query.

        This is a cumulative guard checked between modules, not a hard
        per-module timeout. Interrupting synchronous Python mid-call would
        need a thread per module per query, whose overhead would exceed the
        detection work and corrupt the very latency figures RQ2 reports. So
        the engine cannot stop a single slow module, and that limitation is
        stated rather than hidden: what it does guarantee is that a slow
        module cannot be compounded by the ones queued behind it.
        """
        self.modules: list[DetectionModule] = list(modules or [])
        self.budget_ms = budget_ms
        # Aggregation is a separate object so the scoring policy can be
        # swapped or re-weighted in Stage 16 without touching dispatch.
        self.aggregator = aggregator or RiskAggregator()
        #: Optional `engine.allowlist.Allowlist`; None keeps every earlier
        #: stage's behaviour exactly.
        self.allowlist = allowlist
        self._seen_names: set[str] = set()
        for module in self.modules:
            self._check_name(module)

    # -- registry ----------------------------------------------------------

    def _check_name(self, module: DetectionModule) -> None:
        if not module.name or module.name == "unnamed":
            raise ValueError(f"{type(module).__name__} must define a name")
        if module.name in self._seen_names:
            raise ValueError(
                f"duplicate module name {module.name!r}; evidence rows would "
                f"be ambiguous and the ablation could not attribute a score"
            )
        self._seen_names.add(module.name)

    def register(self, module: DetectionModule) -> "DecisionEngine":
        self._check_name(module)
        self.modules.append(module)
        return self

    @property
    def name(self) -> str:
        """Identifies the configuration in every log line and evidence row.

        Includes the active module list because Stage 16 has to be able to
        tell which configuration produced a stored decision, months later,
        from the database alone.
        """
        active = [m.name for m in self.modules if m.enabled]
        return f"engine[{','.join(active)}]" if active else "engine[none]"

    def set_enabled(self, name: str, enabled: bool) -> bool:
        """Switch a module on or off. The ablation control surface."""
        for module in self.modules:
            if module.name == name:
                module.enabled = enabled
                return True
        return False

    # -- evaluation --------------------------------------------------------

    def evaluate(self, ctx: QueryContext) -> list[ModuleResult]:
        """Run every module over `ctx` and return one result per module.

        Always returns a result for every registered module, including
        disabled and skipped ones. A missing row and a zero score must never
        be confusable when the experiments are counted.
        """
        results: list[ModuleResult] = []
        spent_ms = 0.0

        for module in self.modules:
            if not module.enabled:
                results.append(ModuleResult(module.name, 0.0, {}, 0.0,
                                            STATUS_DISABLED))
                continue

            if spent_ms >= self.budget_ms:
                results.append(ModuleResult(
                    module.name, 0.0,
                    {"reason": "latency budget exhausted",
                     "spent_ms": round(spent_ms, 3),
                     "budget_ms": self.budget_ms},
                    0.0, STATUS_SKIPPED))
                log.warning("skipped %s for %s: %.1fms of %.1fms budget spent",
                            module.name, ctx.qname, spent_ms, self.budget_ms)
                continue

            results.append(self._run_one(module, ctx))
            spent_ms += results[-1].latency_ms

        return results

    def _run_one(self, module: DetectionModule, ctx: QueryContext) -> ModuleResult:
        start = time.perf_counter()
        try:
            score = module.evaluate(ctx)
        except ModuleUnavailable as exc:
            # The module ran correctly and told us it has nothing to go on.
            # Excluded from aggregation exactly as an error is, but recorded
            # differently so the evidence can say which happened.
            elapsed = (time.perf_counter() - start) * 1000.0
            log.info("module %s unavailable for %s: %s",
                     module.name, ctx.qname, exc)
            return ModuleResult(
                module.name, 0.0,
                {"unavailable": type(exc).__name__, "detail": str(exc)[:200]},
                elapsed, STATUS_UNAVAILABLE)
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000.0
            log.exception("module %s failed on %s", module.name, ctx.qname)
            return ModuleResult(
                module.name, 0.0,
                {"error": type(exc).__name__, "detail": str(exc)[:200]},
                elapsed, STATUS_ERROR)

        elapsed = (time.perf_counter() - start) * 1000.0

        if score is None or not hasattr(score, "is_valid"):
            log.error("module %s returned %r, not a ModuleScore",
                      module.name, type(score).__name__)
            return ModuleResult(module.name, 0.0,
                                {"error": "not a ModuleScore",
                                 "returned": type(score).__name__},
                                elapsed, STATUS_INVALID)

        if not score.is_valid():
            # Not clamped on purpose. Clamping would hide the bug and produce
            # a plausible-looking score that no module actually computed.
            log.error("module %s returned an out-of-range score %r",
                      module.name, score.score)
            return ModuleResult(module.name, 0.0,
                                {"error": "score out of range",
                                 "returned": repr(score.score)},
                                elapsed, STATUS_INVALID)

        features = score.features if isinstance(score.features, dict) else {}
        return ModuleResult(module.name, float(score.score), features,
                            elapsed, STATUS_OK)

    # -- the interface the proxy calls ------------------------------------

    def decide(self, query, stopwatch, client_id: str = "unknown") -> dict:
        """Same signature and return shape as `AllowAllEngine.decide`.

        Returns {"verdict", "score", "evidence", "explanation", "enforcement"}.

        `verdict` is the policy decision. `enforcement` says what the resolver
        will actually do about it. Both are additive keys: the proxy reads the
        dict by key, so AllowAllEngine's three-key result still works and is
        treated as "forward".
        """
        ctx = QueryContext(
            qname=query.question.qname,
            qtype=query.question.qtype_name,
            client_id=client_id,
            timestamp=time.time(),
        )

        with stopwatch.measure("modules"):
            results = self.evaluate(ctx)

        with stopwatch.measure("aggregate"):
            decision = self.aggregator.aggregate(results)

        # Stage 15: a rendering of the aggregation, added here rather than
        # inside RiskAggregator so the scoring code keeps one job and every
        # existing aggregator test stands unchanged.
        explanation = {
            **decision["explanation"],
            "summary": summarise(results, decision["explanation"]),
        }

        verdict = decision["verdict"]
        enforcement = decision["enforcement"]
        entry = self.allowlist.match(ctx.qname) if self.allowlist else None
        if entry is not None:
            # The detectors' verdict is kept beside the override, never
            # replaced silently: the evidence stays reviewable.
            enforcement = {**enforcement, "would_block": False,
                           "applied": False, "action": "forward",
                           "allowlisted": True}
            explanation = {
                **explanation,
                "allowlisted": {"entry": entry,
                                "detector_verdict": verdict,
                                "detector_score": decision["score"]},
                "verdict": "ALLOW",
                "enforced": False,
                "enforcement": enforcement,
                "summary": (f"Allowed because {entry} is on the operator "
                            f"allowlist. Without it the detectors' verdict "
                            f"would have been {verdict} "
                            f"(score {decision['score']:.2f})."),
            }
            verdict = "ALLOW"

        return {
            "verdict": verdict,
            "score": decision["score"],
            "evidence": [r.to_evidence() for r in results],
            "explanation": explanation,
            "enforcement": enforcement,
        }

    def close(self) -> None:
        for module in self.modules:
            try:
                module.close()
            except Exception:
                log.exception("module %s failed to close", module.name)
