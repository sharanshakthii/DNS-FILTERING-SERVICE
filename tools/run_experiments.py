"""
Run the Stage 16 experiments and write the report artifacts.

Reproducible: the dataset is generated from a fixed seed, the harness pins
"now" so temporal features do not drift between runs, and the metadata
records the dataset's SHA-256 so a set of results can always be tied to the
input that produced it.

**Every figure produced here comes from synthetic data whose labels come from
the generator, not from observed ground truth.** The caveat is written into
`metadata.json` so it travels with the numbers rather than living only in a
README nobody opens next to a spreadsheet.

Usage:
    python tools/run_experiments.py
    python tools/run_experiments.py --ablation-only
    python tools/run_experiments.py --sweep-only --out experiments/results
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from experiments.ablation import deltas_against_baseline, run_ablation  # noqa: E402
from experiments.harness import (  # noqa: E402
    ALL_MODULES,
    Harness,
    dataset_checksum,
    load_rows,
)
from experiments.sweep import sweep_thresholds, sweep_weights  # noqa: E402

#: Pinned so temporal features are identical between runs. An arbitrary fixed
#: instant; only differences from it matter.
FIXED_NOW = 2_000_000_000.0

CAVEAT = (
    "SYNTHETIC evaluation. The labels in datasets/eval_dev.csv come from the "
    "generator in tools/make_eval_dataset.py, not from observed ground truth, "
    "and the classes are far more separable than real DNS traffic. These "
    "figures show that the evaluation pipeline works and permit RELATIVE "
    "comparison between configurations. They are NOT detection accuracy and "
    "must not be reported as such. Threat intelligence in particular is "
    "scored against a feed the dataset itself declares, so its precision is "
    "1.0 by construction and measures nothing."
)


def display(path: Path) -> str:
    """Path relative to the repository when it is inside it, absolute if not.

    `--out` may legitimately point anywhere, so relative_to() cannot be
    assumed to succeed.

    The absolute form uses `as_posix()` rather than `str()`. On Windows a
    path given as `/tmp/elsewhere` is a `WindowsPath`, and `str()` renders it
    `\\tmp\\elsewhere` — a shape that appears in no artifact and matches
    nothing the operator typed. `as_posix()` echoes back what was supplied.
    """
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return path.as_posix()


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})


def write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage 16 experiments")
    parser.add_argument("--dataset",
                        default=str(REPO_ROOT / "datasets" / "eval_dev.csv"))
    parser.add_argument("--out",
                        default=str(REPO_ROOT / "experiments" / "results"))
    parser.add_argument("--model",
                        default=str(REPO_ROOT / "models" / "dga"
                                    / "dga_model.json"))
    parser.add_argument("--ablation-only", action="store_true")
    parser.add_argument("--sweep-only", action="store_true")
    args = parser.parse_args()

    # A module reporting it cannot assess a query is normal here and would
    # otherwise emit one warning per row. Quieted for the batch run only.
    logging.getLogger("engine.aggregator").setLevel(logging.ERROR)
    logging.getLogger("engine").setLevel(logging.ERROR)

    dataset = Path(args.dataset)
    rows = load_rows(dataset)
    checksum = dataset_checksum(dataset)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    positives = sum(1 for r in rows if r.label == 1)
    print(f"dataset  : {dataset}")
    print(f"           {len(rows)} rows, {positives} label=1, "
          f"{len(rows) - positives} label=0")
    print(f"           sha256 {checksum[:16]}…")
    print(f"output   : {out_dir}")

    harness = Harness(rows, model_path=args.model, now=FIXED_NOW)
    artifacts: list[Path] = []
    run_ablation_step = not args.sweep_only
    run_sweep_step = not args.ablation_only

    ablation_rows: list[dict] = []
    delta_rows: list[dict] = []
    if run_ablation_step:
        print("\nablation")
        arms = run_ablation(harness)
        ablation_rows = [arm.as_dict() for arm in arms]
        delta_rows = deltas_against_baseline(arms)

        header = (f"  {'arm':<22}{'P':>7}{'R':>7}{'F1':>7}{'FPR':>7}"
                  f"{'TP':>6}{'FP':>6}{'FN':>6}")
        print(header)
        for arm in arms:
            m = arm.metrics
            print(f"  {arm.name:<22}{m.precision:>7.3f}{m.recall:>7.3f}"
                  f"{m.f1:>7.3f}{m.false_positive_rate:>7.3f}"
                  f"{m.true_positive:>6}{m.false_positive:>6}"
                  f"{m.false_negative:>6}")

        write_csv(out_dir / "ablation.csv", ablation_rows)
        write_json(out_dir / "ablation.json",
                   [{**arm.as_dict(), "per_category": arm.per_category,
                     "module_status": arm.module_status} for arm in arms])
        artifacts += [out_dir / "ablation.csv", out_dir / "ablation.json"]

        if delta_rows:
            write_csv(out_dir / "ablation_deltas.csv", delta_rows)
            artifacts.append(out_dir / "ablation_deltas.csv")
            print("\n  leave-one-out, change against the full configuration")
            for row in delta_rows:
                print(f"    removing {row['removed_module']:<10} "
                      f"delta F1 {row['delta_f1']:+.4f}  "
                      f"delta recall {row['delta_recall']:+.4f}  "
                      f"delta FPR {row['delta_false_positive_rate']:+.4f}")

    sweep_rows: list[dict] = []
    if run_sweep_step:
        print("\nsweep (reporting only; no project setting is changed)")
        sweep_rows = sweep_thresholds(harness, ALL_MODULES)
        sweep_rows += sweep_weights(harness, ALL_MODULES)
        write_csv(out_dir / "sweep.csv", sweep_rows)
        write_json(out_dir / "sweep.json", sweep_rows)
        artifacts += [out_dir / "sweep.csv", out_dir / "sweep.json"]

        print(f"  {'flag':>6}{'block':>7}{'P':>8}{'R':>8}{'F1':>8}"
              f"{'FPR':>8}   default")
        for row in sweep_rows:
            if row["sweep"] != "threshold":
                continue
            print(f"  {row['flag_at']:>6.2f}{row['block_at']:>7.2f}"
                  f"{row['precision']:>8.3f}{row['recall']:>8.3f}"
                  f"{row['f1']:>8.3f}{row['false_positive_rate']:>8.3f}"
                  f"   {'<-- current' if row['is_project_default'] else ''}")

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "path": display(dataset),
            "sha256": checksum,
            "rows": len(rows),
            "label_1": positives,
            "label_0": len(rows) - positives,
            "kind": "SYNTHETIC development fixture",
        },
        "fixed_now": FIXED_NOW,
        "model_artifact": display(Path(args.model)),
        "modules": list(ALL_MODULES),
        "project_defaults_unchanged": True,
        "ablation_arms": len(ablation_rows),
        "sweep_rows": len(sweep_rows),
        "caveat": CAVEAT,
    }
    write_json(out_dir / "metadata.json", metadata)
    artifacts.append(out_dir / "metadata.json")

    print("\nartifacts")
    for path in artifacts:
        print(f"  {display(path)} ({path.stat().st_size} bytes)")
    print("\n" + CAVEAT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
