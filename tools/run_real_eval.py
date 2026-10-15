"""
Run the real-world evaluation on a frozen dataset. No network access.

    python tools/run_real_eval.py                         # newest datasets/real_*.csv
    python tools/run_real_eval.py --dataset datasets/real_20261015.csv

Writes experiments/results/real_eval.json and real_eval_arms.csv, and prints
the tables. Brands default to the list start.ps1 configures, with each
brand's .com as its official domain; both are recorded in the output.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from experiments.real_eval import ARMS, evaluate, load   # noqa: E402

DEFAULT_BRANDS = ("google,paypal,microsoft,apple,amazon,facebook,instagram,"
                  "netflix,linkedin,github")

CAVEAT = (
    "Malicious labels are live feed listings and benign labels are Tranco "
    "ranks: real domains, but asserted labels rather than verified ground "
    "truth. All arms run with threat intelligence off, because the malicious "
    "rows were drawn from the feeds and TI would catch them by construction. "
    "nrd and beaconing are not evaluated: they need query history and "
    "timing, which a list of names does not contain. Registration ages are "
    "measured at collection time, after listing; at first sighting a domain "
    "was younger, so rdap figures are, if anything, conservative. The DGA "
    "artifact's largest coefficient is label_count, so it fires on almost "
    "any name with three or more labels; see dga_by_label_count before "
    "crediting it with any detection.")


def newest_dataset() -> Path:
    found = sorted((ROOT / "datasets").glob("real_*.csv"))
    if not found:
        raise SystemExit("no datasets/real_*.csv; run tools/make_real_dataset.py")
    return found[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description="real-world evaluation")
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--brands", default=DEFAULT_BRANDS)
    parser.add_argument("--model", default=str(ROOT / "models/dga/dga_model.json"))
    parser.add_argument("--out", type=Path, default=ROOT / "experiments/results")
    parser.add_argument("--psl-mode", default="off",
                        choices=["off", "icann", "full"],
                        help="off reproduces the published results file")
    parser.add_argument("--tag", default="",
                        help="suffix for the output files, e.g. dga_v2")
    args = parser.parse_args()

    # A row with no RDAP date is UNKNOWN in the rdap-only arm by design; the
    # aggregator's per-row warning about it is noise here, counted instead.
    logging.getLogger("engine.aggregator").setLevel(logging.ERROR)

    path = args.dataset or newest_dataset()
    rows, rdap, meta = load(path)

    # Refuse to report on a dataset that does not match its own metadata.
    for name, digest in meta["files"].items():
        actual = hashlib.sha256((path.parent / name).read_bytes()).hexdigest()
        if actual != digest:
            raise SystemExit(f"{name} does not match the checksum in its "
                             f"metadata; refusing to evaluate a modified set")

    if args.psl_mode != "off":
        # PSL registrations missing from the original collection live in a
        # separate top-up file, verified the same way.
        stem = path.name[:-len(".csv")]
        topup_meta = path.parent / f"{stem}.rdap_psl.meta.json"
        if not topup_meta.exists():
            raise SystemExit(f"--psl-mode {args.psl_mode} needs "
                             f"{stem}.rdap_psl.json; run tools/make_real_dataset.py "
                             f"--topup-rdap {path}")
        tmeta = json.loads(topup_meta.read_text(encoding="utf-8"))
        for name, digest in tmeta["files"].items():
            if hashlib.sha256((path.parent / name).read_bytes()).hexdigest() != digest:
                raise SystemExit(f"{name} does not match its checksum")
        topup = json.loads((path.parent / f"{stem}.rdap_psl.json")
                           .read_text(encoding="utf-8"))
        rdap = {**topup, **rdap}

    brands = [b.strip() for b in args.brands.split(",") if b.strip()]
    official = [f"{b}.com" for b in brands]
    result = evaluate(rows, rdap, meta, brands=brands, official=official,
                      dga_model_path=args.model, psl_mode=args.psl_mode)
    suffix = "" if args.psl_mode == "off" else f"_psl_{args.psl_mode}"
    if args.tag:
        suffix += f"_{args.tag}"

    report = {"dataset": path.name, "dga_model": Path(args.model).name, "collected_at": meta["collected_at"],
              "files": meta["files"], "tranco": meta["tranco"],
              "brands": brands, "official_domains": official,
              "aggregator": "RiskAggregator() shipped defaults: weighted mean, "
                            "flag 0.5, block 0.8, unlisted weight 0.5",
              "positive_verdicts": ["FLAG", "BLOCK"],
              "caveat": CAVEAT, **result}

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"real_eval{suffix}.json").write_text(json.dumps(report, indent=2),
                                             encoding="utf-8")
    with (args.out / f"real_eval{suffix}_arms.csv").open("w", newline="",
                                                 encoding="utf-8") as f:
        fields = ["arm", "modules", "precision", "recall", "f1",
                  "false_positive_rate", "true_positive", "false_positive",
                  "true_negative", "false_negative", "unknown"]
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for arm, _ in ARMS:
            writer.writerow({"arm": arm, **result["arms"][arm],
                             "modules": "+".join(result["arms"][arm]["modules"])})

    print(f"dataset {path.name}: {meta['malicious']} malicious, "
          f"{meta['benign']} benign, collected {meta['collected_at'][:10]}\n")
    print(f"{'arm (TI off)':24} {'prec':>6} {'recall':>7} {'F1':>6} {'FPR':>6} {'unk':>4}")
    for arm, _ in ARMS:
        a = result["arms"][arm]
        print(f"{arm:24} {a['precision']:6.3f} {a['recall']:7.3f} "
              f"{a['f1']:6.3f} {a['false_positive_rate']:6.3f} {a['unknown']:4}")
    print(f"\n{'module':10} {'fires on malicious':>20} {'fires on benign':>18}")
    for name, m in result["modules"].items():
        mal, ben = m["malicious"], m["benign"]
        print(f"{name:10} {mal['fired']:>5}/{mal['assessed']:<5} "
              f"({mal['fire_rate'] or 0:5.1%})   {ben['fired']:>4}/{ben['assessed']:<4} "
              f"({ben['fire_rate'] or 0:5.1%})")
    print("\ndga fire rate by name shape (label_count artefact):")
    for key, v in result["dga_by_label_count"].items():
        print(f"  {key:28} {v['fired']:>4}/{v['rows']:<4} ({v['fire_rate'] or 0:5.1%})")
    ti = result["ti_on_benign"]
    print(f"\nTI false positives on benign: {ti['listed']}/{ti['rows']} "
          f"({ti['false_positive_rate']:.1%}) {ti['listed_domains'][:10]}")
    print(f"rdap dates: {result['rdap_coverage']['with_date']}/"
          f"{result['rdap_coverage']['lookups']}")
    sp = result["shared_platform_malicious"]
    print(f"shared-platform malicious rows: {sp['rows']}, caught "
          f"{sp['caught_all_heuristics']}")
    print("\nall_heuristics recall by source:")
    for source, s in result["by_source_all_heuristics"].items():
        print(f"  {source:18} {s['positive']:>4}/{s['rows']:<4} ({s['rate']:.1%})")
    print(f"\nwrote {args.out / f'real_eval{suffix}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
