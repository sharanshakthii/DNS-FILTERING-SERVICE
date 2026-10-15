"""
Real-world evaluation: would the system catch a malicious domain that no
feed had listed yet?

The malicious rows were *taken from* the threat-intelligence feeds, so the TI
module would detect every one of them by construction — exactly the
circularity the paper's Section X warns about. The question worth asking is
therefore the one TI cannot answer: with TI switched off, how many of these
real, currently-listed domains do the remaining signals catch, and at what
false-positive cost on real popular sites?

TI itself is evaluated only where it is not circular: its false-positive
rate on the benign (Tranco) rows.

Everything runs through the production module classes and the production
`RiskAggregator` with its shipped defaults. Nothing is fitted to this data,
and no weight or threshold is changed: the point is to measure the system as
it ships.

Two modules are not evaluated, and the report says so: `nrd` (observation
age needs a resolver's query history, which a list of names does not have)
and `beaconing` (needs query timing). Registration age from `rdap` is the
real-data counterpart of `nrd`.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from engine.aggregator import RiskAggregator
from engine.decision import DecisionEngine
from engine.modules.base import STATUS_OK, QueryContext
from engine.modules.dga import DGAModule
from engine.modules.rdap import RdapAgeModule
from engine.modules.typosquat import TyposquatModule

from .metrics import confusion

#: Configurations, all with TI off. Names are stable: they are the row keys
#: of the results files.
ARMS: list[tuple[str, tuple[str, ...]]] = [
    ("only_dga", ("dga",)),
    ("only_typosquat", ("typosquat",)),
    ("only_rdap", ("rdap",)),
    ("lexical_dga_typosquat", ("dga", "typosquat")),
    ("all_heuristics", ("dga", "typosquat", "rdap")),
]

POSITIVE = {"FLAG", "BLOCK"}

#: A module "fires" when its own score reaches this. Used only for the
#: per-module table; verdicts come from the aggregator.
FIRES_AT = 0.5


@dataclass(frozen=True)
class RealRow:
    domain: str
    label: int
    source: str
    rank: str
    shared_platform: bool
    ti_listed: bool


def load(csv_path: Path) -> tuple[list[RealRow], dict, dict]:
    """Rows, the RDAP answers, and the collection metadata."""
    stem = csv_path.name[:-len(".csv")]
    rdap = json.loads((csv_path.parent / f"{stem}.rdap.json")
                      .read_text(encoding="utf-8"))
    meta = json.loads((csv_path.parent / f"{stem}.meta.json")
                      .read_text(encoding="utf-8"))
    with csv_path.open(encoding="utf-8") as f:
        rows = [RealRow(domain=r["domain"], label=int(r["label"]),
                        source=r["source"], rank=r["rank"],
                        shared_platform=r["shared_platform"] == "1",
                        ti_listed=r["ti_listed"] == "1")
                for r in csv.DictReader(f)]
    return rows, rdap, meta


def build_modules(rdap: dict, collected_ts: float, brands: list[str],
                  official: list[str], dga_model_path: str) -> dict:
    """The real modules, with RDAP answered from the frozen lookups."""
    rdap_module = RdapAgeModule(fetch=lambda d: (_ for _ in ()).throw(
        RuntimeError(f"{d} missing from the frozen RDAP file")))
    for domain, answer in rdap.items():
        rdap_module.preload(domain, answer.get("registered"),
                            answer.get("error"), cached_at=collected_ts)
    return {
        "dga": DGAModule(model_path=dga_model_path),
        "typosquat": TyposquatModule(brands=brands, official_domains=official),
        "rdap": rdap_module,
    }


def evaluate(rows: list[RealRow], rdap: dict, meta: dict, *,
             brands: list[str], official: list[str],
             dga_model_path: str) -> dict:
    collected_ts = datetime.fromisoformat(meta["collected_at"]).timestamp()
    modules = build_modules(rdap, collected_ts, brands, official,
                            dga_model_path)
    ctxs = [QueryContext(qname=r.domain, qtype="A", client_id="eval",
                         timestamp=collected_ts) for r in rows]

    # Score every module once per row; arms then aggregate subsets of these
    # same results, so all arms see identical module outputs.
    per_module = {}
    for name, module in modules.items():
        engine = DecisionEngine([module])
        per_module[name] = [engine.evaluate(c)[0] for c in ctxs]

    labels = [r.label for r in rows]
    aggregator = RiskAggregator()      # shipped defaults, plain weighted mean
    arms = {}
    verdicts_by_arm = {}
    for arm, names in ARMS:
        verdicts = [aggregator.aggregate([per_module[n][i] for n in names])
                    ["verdict"] for i in range(len(rows))]
        verdicts_by_arm[arm] = verdicts
        predictions = [int(v in POSITIVE) for v in verdicts]
        arms[arm] = {
            "modules": list(names),
            **confusion(labels, predictions).as_dict(),
            "unknown": sum(v == "UNKNOWN" for v in verdicts),
        }

    module_table = {}
    for name, results in per_module.items():
        entry = {}
        for label, group in (("malicious", 1), ("benign", 0)):
            idx = [i for i, r in enumerate(rows) if r.label == group]
            ok = [i for i in idx if results[i].status == STATUS_OK]
            fired = [i for i in ok if results[i].score >= FIRES_AT]
            entry[label] = {
                "rows": len(idx),
                "assessed": len(ok),
                "fired": len(fired),
                "fire_rate": round(len(fired) / len(ok), 4) if ok else None,
                "mean_score": (round(sum(results[i].score for i in ok)
                                     / len(ok), 4) if ok else None),
            }
        module_table[name] = entry

    # The DGA artifact's largest coefficient is `label_count`, so any name
    # with three or more labels scores high regardless of its letters
    # (mail.google.com scores 0.83). Reporting the module only in aggregate
    # would credit it with detections that are really "has a subdomain".
    dga_split = {}
    for label, group in (("malicious", 1), ("benign", 0)):
        for shape, test in (("two_labels", lambda d: d.count(".") == 1),
                            ("three_plus_labels", lambda d: d.count(".") > 1)):
            idx = [i for i, r in enumerate(rows)
                   if r.label == group and test(r.domain)
                   and per_module["dga"][i].status == STATUS_OK]
            fired = sum(per_module["dga"][i].score >= FIRES_AT for i in idx)
            dga_split[f"{label}_{shape}"] = {
                "rows": len(idx), "fired": fired,
                "fire_rate": round(fired / len(idx), 4) if idx else None}

    best = "all_heuristics"
    by_source = {}
    for source in sorted({r.source for r in rows}):
        idx = [i for i, r in enumerate(rows) if r.source == source]
        hits = sum(verdicts_by_arm[best][i] in POSITIVE for i in idx)
        by_source[source] = {"rows": len(idx), "positive": hits,
                             "rate": round(hits / len(idx), 4) if idx else None}

    shared = [i for i, r in enumerate(rows) if r.label == 1 and r.shared_platform]
    benign = [r for r in rows if r.label == 0]
    ti_fp = [r for r in benign if r.ti_listed]
    return {
        "arms": arms,
        "modules": module_table,
        "dga_by_label_count": dga_split,
        "by_source_all_heuristics": by_source,
        "shared_platform_malicious": {
            "rows": len(shared),
            "caught_all_heuristics": sum(
                verdicts_by_arm[best][i] in POSITIVE for i in shared),
        },
        "ti_on_benign": {
            "rows": len(benign),
            "listed": len(ti_fp),
            "false_positive_rate": (round(len(ti_fp) / len(benign), 4)
                                    if benign else None),
            "listed_domains": sorted(r.domain for r in ti_fp),
        },
        "rdap_coverage": {
            "lookups": len(rdap),
            "with_date": sum(1 for v in rdap.values()
                             if v.get("registered") is not None),
        },
    }
