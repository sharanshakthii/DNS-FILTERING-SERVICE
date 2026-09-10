"""
Threshold and weight sweeps.

**Reporting only.** Nothing here writes a configuration back into the
project. `DEFAULT_WEIGHTS`, `flag_at` and `block_at` in `engine/aggregator.py`
are untouched by this module and by Stage 16 as a whole. The output says what
*would* happen under a different setting; deciding whether to adopt one is a
separate act, and one that should not be taken on synthetic data.

That last point is the reason this file does not contain a `best()` function.
Picking the configuration with the highest F1 on a generated dataset would
produce a number that looks like tuning and is really overfitting to the
generator. The sweep reports the grid; a human reads it.
"""

from __future__ import annotations

from engine.aggregator import DEFAULT_WEIGHTS, RiskAggregator

from .harness import ALL_MODULES, Harness
from .metrics import confusion

#: Flag/block pairs to report. Includes the project's current setting so the
#: table always contains the baseline it is being compared against.
THRESHOLD_GRID = [
    (0.20, 0.40), (0.30, 0.50), (0.40, 0.60),
    (0.50, 0.80),                                  # current project default
    (0.60, 0.85), (0.70, 0.90),
]

#: Weights to try for one module at a time, holding the others at default.
WEIGHT_GRID = [0.25, 0.5, 1.0, 1.5, 2.0]


def sweep_thresholds(harness: Harness,
                     modules: tuple[str, ...] = ALL_MODULES) -> list[dict]:
    """Vary the flag and block thresholds; weights stay at their defaults."""
    rows = []
    for flag_at, block_at in THRESHOLD_GRID:
        aggregator = RiskAggregator(flag_at=flag_at, block_at=block_at)
        results = harness.run(modules, aggregator=aggregator)
        metrics = confusion([r.label for r in results],
                            [r.predicted for r in results])

        verdicts: dict[str, int] = {}
        for row in results:
            verdicts[row.verdict] = verdicts.get(row.verdict, 0) + 1

        rows.append({
            "sweep": "threshold",
            "modules": ",".join(modules),
            "flag_at": flag_at,
            "block_at": block_at,
            "is_project_default": flag_at == 0.5 and block_at == 0.8,
            **metrics.as_dict(),
            "verdict_allow": verdicts.get("ALLOW", 0),
            "verdict_flag": verdicts.get("FLAG", 0),
            "verdict_block": verdicts.get("BLOCK", 0),
            "verdict_unknown": verdicts.get("UNKNOWN", 0),
        })
    return rows


def sweep_weights(harness: Harness,
                  modules: tuple[str, ...] = ALL_MODULES) -> list[dict]:
    """Vary one module's weight at a time, holding the rest at default.

    One at a time rather than a full grid: five modules across five weights
    is 3,125 configurations, and a joint search on synthetic data would be
    overfitting dressed up as tuning.
    """
    rows = []
    for module in modules:
        default_weight = RiskAggregator().weight_for(module)
        for weight in WEIGHT_GRID:
            weights = dict(DEFAULT_WEIGHTS)
            for name in ALL_MODULES:
                weights.setdefault(name, RiskAggregator().weight_for(name))
            weights[module] = weight

            results = harness.run(modules, aggregator=RiskAggregator(
                weights=weights))
            metrics = confusion([r.label for r in results],
                                [r.predicted for r in results])
            rows.append({
                "sweep": "weight",
                "modules": ",".join(modules),
                "varied_module": module,
                "weight": weight,
                "project_default_weight": default_weight,
                "is_project_default": weight == default_weight,
                **metrics.as_dict(),
            })
    return rows
