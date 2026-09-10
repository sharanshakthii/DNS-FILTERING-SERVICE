"""
Build the evaluation dataset for Stage 16.

**This is synthetic development data. It is not a corpus of real DNS traffic
and it carries no real ground truth.** No labelled DNS dataset is bundled
with this project; downloading one at build time would make the experiments
irreproducible and would put unvetted domains in the repository.

## The circularity problem, and what is done about it

An evaluation is only worth something if the labels come from somewhere other
than the detector. Here they cannot: a "typosquat" row is labelled malicious
*because* it was generated as a brand variant, which is the same rule the
typosquat module applies. Left alone, every module would score near-perfectly
and the numbers would measure nothing but the generator.

Two deliberate choices push back on that, and they are the reason this file
is worth reading before trusting any figure it produces:

  * **Benign rows that trip the heuristics.** `benign_new` domains are
    newly observed but harmless — a real resolver sees these constantly.
    `benign_periodic` domains poll on a schedule, exactly like a software
    updater. They exist so that domain age and beaconing produce false
    positives, because on real traffic they would.

  * **Malicious rows that no single module can catch.** A `dga` row is not
    on the threat feed. A `beacon` row has an ordinary-looking name. If a
    module could catch everything, the ablation would have nothing to show.

Even so: the classes here are far more separable than real traffic, and a
figure from this dataset must never be reported as detection accuracy.

## Columns

    domain              the queried name
    label               1 = should be detected, 0 = should not
    category            provenance of the row; never given to any module
    ti_listed           1 if the controlled feed contains it
    first_seen_age_s    seconds since this resolver first saw the domain
    observation_pattern none | periodic | jittered | irregular | sparse

The state columns exist so the harness gives each module the same inputs it
would have in production, rather than inventing them at run time.

Usage:
    python tools/make_eval_dataset.py
    python tools/make_eval_dataset.py --out datasets/eval_dev.csv --seed 20260906
"""

from __future__ import annotations

import argparse
import csv
import random
import string
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SEED = 20260906

WORDS = [
    "harbor", "meadow", "summit", "cedar", "orange", "silver", "castle",
    "forest", "island", "lantern", "maple", "orchid", "pebble", "quartz",
    "ripple", "shadow", "timber", "violet", "willow", "anchor", "breeze",
    "canyon", "delta", "ember", "falcon", "glacier", "hollow", "indigo",
    "jasmine", "kettle", "ladder", "mosaic", "nectar", "otter", "prairie",
    "raven", "saffron", "thistle", "velvet", "walnut", "zephyr", "clover",
]
SUFFIXES = ["group", "works", "labs", "studio", "shop", "media", "systems",
            "supply", "digital", "care", "cloud", "desk"]
TLDS = ["com", "net", "org", "io", "co", "info"]

#: Brands the typosquat module will be configured with. Ordinary company
#: names, chosen so no real brand is implicated by a synthetic fixture.
BRANDS = ["examplebrand", "acmeshop", "northwind", "contoso"]
BRAND_KEYWORDS = ["login", "verify", "secure", "account", "support"]

DGA_ALPHABETS = [string.ascii_lowercase,
                 string.ascii_lowercase + string.digits,
                 "0123456789abcdef"]

OLD = 400 * 24 * 3600      # long-established
RECENT = 3 * 3600          # first seen hours ago


def benign_label(rng: random.Random) -> str:
    shape = rng.randrange(3)
    if shape == 0:
        return rng.choice(WORDS) + rng.choice(SUFFIXES)
    if shape == 1:
        return f"{rng.choice(WORDS)}-{rng.choice(SUFFIXES)}"
    return rng.choice(WORDS) + rng.choice(WORDS)


def make_rows(per_category: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    rows: list[dict] = []
    seen: set[str] = set()

    def add(domain, label, category, ti_listed, age, pattern):
        if domain in seen:
            return False
        seen.add(domain)
        rows.append({
            "domain": domain, "label": label, "category": category,
            "ti_listed": ti_listed, "first_seen_age_s": age,
            "observation_pattern": pattern,
        })
        return True

    def fill(count, builder):
        made, attempts = 0, 0
        while made < count and attempts < count * 60:
            attempts += 1
            if builder():
                made += 1
        if made < count:
            raise RuntimeError(f"could only generate {made} of {count} rows")

    # -- benign ------------------------------------------------------------
    fill(per_category, lambda: add(
        f"{benign_label(rng)}.{rng.choice(TLDS)}", 0, "benign", 0,
        OLD + rng.randrange(10_000), rng.choice(["none", "irregular"])))

    # Benign but newly observed: the false positive domain age must produce.
    fill(per_category // 2, lambda: add(
        f"{benign_label(rng)}.{rng.choice(TLDS)}", 0, "benign_new", 0,
        rng.randrange(60, RECENT), "none"))

    # Benign but polling on a schedule: a software updater.
    fill(per_category // 2, lambda: add(
        f"{benign_label(rng)}.{rng.choice(TLDS)}", 0, "benign_periodic", 0,
        OLD, rng.choice(["periodic", "jittered"])))

    # -- should be detected ------------------------------------------------
    # On the feed, ordinary-looking name: only threat intelligence can see it.
    fill(per_category, lambda: add(
        f"{benign_label(rng)}.{rng.choice(TLDS)}", 1, "listed", 1,
        rng.randrange(60, OLD), "none"))

    # Algorithmically generated, not on the feed.
    def dga_row():
        alphabet = rng.choice(DGA_ALPHABETS)
        label = "".join(rng.choice(alphabet)
                        for _ in range(rng.randint(12, 22)))
        return add(f"{label}.{rng.choice(TLDS)}", 1, "dga", 0,
                   rng.randrange(60, RECENT), "none")
    fill(per_category, dga_row)

    # Brand impersonation, not on the feed.
    def squat_row():
        brand = rng.choice(BRANDS)
        shape = rng.randrange(3)
        if shape == 0:                                   # keyword
            label = brand + rng.choice(BRAND_KEYWORDS)
        elif shape == 1:                                 # substitution
            position = rng.randrange(len(brand))
            label = (brand[:position] + rng.choice("aeiou0123")
                     + brand[position + 1:])
        else:                                            # transposition
            position = rng.randrange(len(brand) - 1)
            label = (brand[:position] + brand[position + 1] + brand[position]
                     + brand[position + 2:])
        return add(f"{label}.{rng.choice(TLDS)}", 1, "typosquat", 0,
                   rng.randrange(60, RECENT), "none")
    fill(per_category, squat_row)

    # Regular check-ins, ordinary-looking name, not on the feed.
    fill(per_category, lambda: add(
        f"{benign_label(rng)}.{rng.choice(TLDS)}", 1, "beacon", 0,
        rng.randrange(60, OLD), rng.choice(["periodic", "jittered"])))

    return sorted(rows, key=lambda r: (r["category"], r["domain"]))


FIELDS = ["domain", "label", "category", "ti_listed", "first_seen_age_s",
          "observation_pattern"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--out",
                        default=str(REPO_ROOT / "datasets" / "eval_dev.csv"))
    parser.add_argument("--per-category", type=int, default=120)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    rows = make_rows(args.per_category, args.seed)
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    positives = sum(1 for r in rows if r["label"] == 1)
    print(f"wrote {len(rows)} rows to {path}")
    print(f"  label=1 (should be detected) : {positives}")
    print(f"  label=0 (should not)         : {len(rows) - positives}")
    categories: dict[str, int] = {}
    for row in rows:
        categories[row["category"]] = categories.get(row["category"], 0) + 1
    for name in sorted(categories):
        print(f"    {name:<18} {categories[name]}")
    print(f"  seed                         : {args.seed}")
    print("\nSYNTHETIC evaluation data. The labels come from the generator, "
          "not from observed ground truth. Figures derived from this file "
          "are NOT detection accuracy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
