"""
Ablation experiments.

Runs the same dataset through a series of module configurations and reports
what each one detects. Three families:

  **Individually** — each module alone, which is the only way to see what a
  signal contributes on its own. Note that threat intelligence is scored
  against a feed the dataset itself declares, so its precision is 1.0 by
  construction and measures nothing. It is reported rather than hidden,
  because omitting it would look like an oversight.

  **Leave-one-out** — all five minus one. The delta against the baseline is
  the defensible output of this whole stage: absolute figures inherit the
  generator's bias, but that bias is shared across arms, so a difference
  between two arms is more meaningful than either number alone.

  **Research arms** — TI-only against ML-only against the hybrid, which is
  the comparison the project's research question actually names.

Nothing here changes production. Each configuration builds its own engine
and its own aggregator with the project's existing default weights and
thresholds.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.aggregator import RiskAggregator

from .harness import ALL_MODULES, Harness, RowResult, status_counts
from .metrics import Metrics, confusion


@dataclass
class Arm:
    """One configuration and what it detected."""

    name: str
    family: str
    modules: tuple[str, ...]
    metrics: Metrics
    per_category: dict
    module_status: dict
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "arm": self.name,
            "family": self.family,
            "modules": ",".join(self.modules),
            "module_count": len(self.modules),
            **self.metrics.as_dict(),
            "note": self.note,
        }


def per_category_recall(results: list[RowResult]) -> dict:
    """Detection rate per generated category.

    The aggregate hides which kind of row a configuration misses. A
    configuration can look adequate overall while catching no beacons at all.
    """
    tally: dict[str, dict[str, int]] = {}
    for row in results:
        entry = tally.setdefault(row.category, {"rows": 0, "predicted": 0,
                                                "label": row.label})
        entry["rows"] += 1
        entry["predicted"] += row.predicted

    for entry in tally.values():
        entry["detected_fraction"] = round(entry["predicted"] / entry["rows"], 4)
    return tally


def configurations() -> list[tuple[str, str, tuple[str, ...], str]]:
    """(name, family, modules, note) for every arm, in report order."""
    arms: list[tuple[str, str, tuple[str, ...], str]] = [
        ("baseline_all", "baseline", ALL_MODULES,
         "all five modules, project default weights and thresholds"),
    ]

    for module in ALL_MODULES:
        note = ""
        if module == "ti":
            note = ("scored against a feed the dataset declares, so precision "
                    "is 1.0 by construction and measures nothing")
        arms.append((f"only_{module}", "individual", (module,), note))

    for module in ALL_MODULES:
        arms.append((f"without_{module}", "leave_one_out",
                     tuple(m for m in ALL_MODULES if m != module),
                     "delta against baseline_all is the meaningful figure"))

    arms.extend([
        ("ti_only", "research_arm", ("ti",),
         "threat-intelligence-only arm of the research question"),
        ("ml_only", "research_arm", ("dga",),
         "ML-only arm; the DGA classifier is the project's only ML module"),
        ("hybrid", "research_arm", ALL_MODULES,
         "hybrid arm; identical configuration to baseline_all"),
    ])
    return arms


def run_ablation(harness: Harness,
                 aggregator_factory=RiskAggregator) -> list[Arm]:
    """Run every configuration and collect its metrics."""
    arms: list[Arm] = []

    for name, family, modules, note in configurations():
        results = harness.run(modules, aggregator=aggregator_factory())
        metrics = confusion([r.label for r in results],
                            [r.predicted for r in results])
        arms.append(Arm(name=name, family=family, modules=modules,
                        metrics=metrics,
                        per_category=per_category_recall(results),
                        module_status=status_counts(results),
                        note=note))
    return arms


def deltas_against_baseline(arms: list[Arm]) -> list[dict]:
    """Leave-one-out arms expressed as a change from the full configuration."""
    baseline = next((a for a in arms if a.name == "baseline_all"), None)
    if baseline is None:
        return []

    rows = []
    for arm in arms:
        if arm.family != "leave_one_out":
            continue
        removed = next(m for m in ALL_MODULES if m not in arm.modules)
        rows.append({
            "removed_module": removed,
            "baseline_f1": round(baseline.metrics.f1, 4),
            "arm_f1": round(arm.metrics.f1, 4),
            "delta_f1": round(arm.metrics.f1 - baseline.metrics.f1, 4),
            "delta_recall": round(
                arm.metrics.recall - baseline.metrics.recall, 4),
            "delta_precision": round(
                arm.metrics.precision - baseline.metrics.precision, 4),
            "delta_false_positive_rate": round(
                arm.metrics.false_positive_rate
                - baseline.metrics.false_positive_rate, 4),
        })
    return rows
