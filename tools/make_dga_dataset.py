"""
Build the development dataset for the DGA module.

**This produces synthetic data. It is not a corpus of real malware domains,
and it must never be described as one.** No real DGA feed is bundled with
this project, and downloading one at build time would make the pipeline
non-reproducible and would put unvetted domains in the repository.

What the dataset is for: validating that the pipeline runs end to end —
features, deterministic split, training, evaluation, artifact, inference. It
is *not* a scientific evaluation set. The two classes here are far more
separable than real traffic, so metrics measured on it will be optimistic and
say nothing about how the module would perform against a real DGA family.
Stage 16 is where real data and honest evaluation belong.

Deterministic: a fixed seed and a fixed word list, so regenerating produces a
byte-identical file on any machine.

Usage:
    python tools/make_dga_dataset.py
    python tools/make_dga_dataset.py --out datasets/dga_dev.csv --seed 20260904
"""

from __future__ import annotations

import argparse
import csv
import random
import string
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SEED = 20260904

#: Ordinary English words used to build pronounceable, human-looking labels.
#: Not scraped from anywhere: a fixed list committed with the generator so
#: the output is reproducible without network access.
WORDS = [
    "blue", "river", "stone", "garden", "market", "coffee", "bright", "north",
    "harbor", "meadow", "summit", "cedar", "orange", "silver", "castle",
    "forest", "island", "lantern", "maple", "orchid", "pebble", "quartz",
    "ripple", "shadow", "timber", "violet", "willow", "yellow", "anchor",
    "breeze", "canyon", "delta", "ember", "falcon", "glacier", "hollow",
    "indigo", "jasmine", "kettle", "ladder", "mosaic", "nectar", "otter",
    "prairie", "quiver", "raven", "saffron", "thistle", "umber", "velvet",
    "walnut", "zephyr", "amber", "basil", "clover", "dune", "elm", "fern",
    "grove", "heather", "ivory", "juniper", "kelp", "lily", "moss", "nettle",
]

SUFFIXES = ["group", "works", "labs", "studio", "shop", "media", "hub",
            "systems", "supply", "co", "digital", "tech", "care", "hq"]

TLDS = ["com", "net", "org", "io", "co.uk", "de", "fr", "info"]

#: Character sets that mimic the shape of published DGA families: some emit
#: pure lowercase, some mix in digits, some use hexadecimal.
DGA_ALPHABETS = [
    string.ascii_lowercase,
    string.ascii_lowercase + string.digits,
    "0123456789abcdef",
]


def benign_domain(rng: random.Random) -> str:
    """A pronounceable, human-looking name."""
    shape = rng.randrange(4)
    if shape == 0:
        label = rng.choice(WORDS)
    elif shape == 1:
        label = rng.choice(WORDS) + rng.choice(WORDS)
    elif shape == 2:
        label = f"{rng.choice(WORDS)}-{rng.choice(SUFFIXES)}"
    else:
        label = rng.choice(WORDS) + rng.choice(SUFFIXES)
    return f"{label}.{rng.choice(TLDS)}"


def dga_domain(rng: random.Random) -> str:
    """A label drawn from a near-uniform character distribution."""
    alphabet = rng.choice(DGA_ALPHABETS)
    length = rng.randint(10, 24)
    label = "".join(rng.choice(alphabet) for _ in range(length))
    return f"{label}.{rng.choice(TLDS)}"


def build(count_per_class: int, seed: int) -> list[tuple[str, int]]:
    """Generate a balanced, deduplicated, deterministically ordered dataset."""
    rng = random.Random(seed)
    rows: list[tuple[str, int]] = []
    seen: set[str] = set()

    for generator, label in ((benign_domain, 0), (dga_domain, 1)):
        produced = 0
        attempts = 0
        while produced < count_per_class and attempts < count_per_class * 50:
            attempts += 1
            domain = generator(rng)
            if domain in seen:
                continue
            seen.add(domain)
            rows.append((domain, label))
            produced += 1
        if produced < count_per_class:
            raise RuntimeError(
                f"only produced {produced} unique domains for label {label}")

    # Sorted so the file is byte-identical regardless of generation order,
    # and so a reviewer can diff two regenerations meaningfully.
    return sorted(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--out", default=str(REPO_ROOT / "datasets" / "dga_dev.csv"))
    parser.add_argument("--per-class", type=int, default=600)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    rows = build(args.per_class, args.seed)
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["domain", "label"])
        writer.writerows(rows)

    benign = sum(1 for _, label in rows if label == 0)
    print(f"wrote {len(rows)} rows to {path}")
    print(f"  benign (label=0)   : {benign}")
    print(f"  DGA-like (label=1) : {len(rows) - benign}")
    print(f"  seed               : {args.seed}")
    print("\nSYNTHETIC development data. Not real malware domains. For "
          "pipeline validation only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
