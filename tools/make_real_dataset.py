"""
Collect a real-world evaluation set and freeze it.

    python tools/make_real_dataset.py                 # 500 + 500, seed 20261015
    python tools/make_real_dataset.py --per-feed 60 --benign 300

Malicious rows are sampled from the live threat-intelligence feeds the
system already uses, stratified so each feed contributes. Benign rows are
sampled from the Tranco research top list (Le Pochat et al., NDSS 2019),
half from ranks 1-10,000 and half from 10,001-100,000, because the very top
of the list is unrealistically easy.

Everything the evaluation needs is written to `datasets/`, so
`tools/run_real_eval.py` never touches the network and can be re-run by
anyone with the same numbers:

    real_<date>.csv          the labelled rows
    real_<date>.rdap.json    the registration date found for every domain
    real_<date>.meta.json    sources, list ids, seed, counts, checksums

**Labels are a feed's or a ranking's assertion, not verified ground truth.**
A feed can list a compromised legitimate site; Tranco's top 100k contains
some abusive domains. Both are documented in the metadata and the report.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import random
import sys
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.modules.rdap import RdapAgeModule   # noqa: E402
from feeds.cache import IndicatorCache          # noqa: E402
from feeds.sources import (                     # noqa: E402
    DEFAULT_FEED_URL, EXTRA_DEFAULT_FEEDS, HttpFeedSource)

TRANCO_LATEST = "https://tranco-list.eu/api/lists/date/latest"
TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"
SEED = 20261015


def registrable(name: str) -> str:
    """Last two labels: the same approximation every module uses."""
    return ".".join(name.split(".")[-2:])


def usable(name: str) -> bool:
    labels = name.split(".")
    return (len(labels) >= 2 and not all(l.isdigit() for l in labels)
            and all(l and len(l) <= 63 for l in labels) and len(name) <= 253)


def fetch_feeds() -> tuple[dict[str, set[str]], list[dict]]:
    feeds = [("phishing-domains", DEFAULT_FEED_URL, "domains"),
             *EXTRA_DEFAULT_FEEDS]
    sets, info = {}, []
    for name, url, fmt in feeds:
        snap = HttpFeedSource(name=name, url=url, fmt=fmt).fetch()
        if not snap.ok:
            raise SystemExit(f"feed {name} failed: {snap.error}")
        sets[name] = {d for d in snap.domains if usable(d)}
        info.append({"feed": name, "url": url, "format": fmt,
                     "indicators": len(sets[name])})
        print(f"  {name:18} {len(sets[name]):>8} domains")
    return sets, info


def fetch_tranco() -> tuple[list[str], dict]:
    with urllib.request.urlopen(TRANCO_LATEST, timeout=30) as r:
        meta = json.load(r)
    with urllib.request.urlopen(TRANCO_ZIP, timeout=120) as r:
        raw = r.read()
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        text = z.read(z.namelist()[0]).decode("utf-8")
    ranked = [line.split(",", 1)[1].strip().lower()
              for line in text.splitlines() if "," in line]
    print(f"  tranco {meta.get('list_id')}: {len(ranked)} domains")
    return ranked, {"list_id": meta.get("list_id"),
                    "created_on": meta.get("created_on"),
                    "providers": (meta.get("configuration") or {}).get("providers"),
                    "url": TRANCO_ZIP}


def sample(args) -> tuple[list[dict], dict]:
    rng = random.Random(args.seed)
    print("fetching feeds")
    feed_sets, feed_info = fetch_feeds()
    print("fetching tranco")
    ranked, tranco_info = fetch_tranco()
    top100k = set(ranked[:100_000])

    # One index over every feed, with production parent matching, so a
    # benign row's TI status is exactly what the running proxy would say.
    index = IndicatorCache(match_parents=True)
    from feeds.base import FeedSnapshot
    for name, domains in feed_sets.items():
        index.apply(FeedSnapshot(feed=name, domains=frozenset(domains),
                                 fetched_at=time.time(), source="collection"))

    rows, taken = [], set()
    for name in sorted(feed_sets):
        pool = sorted(feed_sets[name] - taken)
        for domain in rng.sample(pool, min(args.per_feed, len(pool))):
            taken.add(domain)
            rows.append({
                "domain": domain, "label": 1, "source": name, "rank": "",
                "listed_in": ";".join(sorted(n for n, s in feed_sets.items()
                                             if domain in s)),
                "shared_platform": int(registrable(domain) in top100k
                                       and registrable(domain) != domain),
                "ti_listed": 1,
            })

    half = args.benign // 2
    strata = [("tranco_top10k", 0, 10_000, half),
              ("tranco_10k_100k", 10_000, 100_000, args.benign - half)]
    for name, lo, hi, n in strata:
        picks = rng.sample(range(lo, min(hi, len(ranked))), n)
        for i in sorted(picks):
            domain = ranked[i]
            if not usable(domain) or domain in taken:
                continue
            taken.add(domain)
            match = index.lookup(domain)
            rows.append({"domain": domain, "label": 0, "source": name,
                         "rank": i + 1, "listed_in": match.feed if match else "",
                         "shared_platform": 0, "ti_listed": int(bool(match))})

    meta = {"seed": args.seed, "feeds": feed_info, "tranco": tranco_info,
            "per_feed": args.per_feed, "benign_requested": args.benign}
    return rows, meta


def collect_rdap(domains: list[str], workers: int) -> dict:
    """Registration date per registrable domain, polite and retried."""
    module = RdapAgeModule(timeout_s=15.0)
    out: dict[str, dict] = {}

    def one(domain):
        for attempt in range(4):
            try:
                ts = module.fetch_registration(domain)
                return domain, {"registered": ts, "error": None}
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 503) and attempt < 3:
                    time.sleep(5 * (attempt + 1))
                    continue
                return domain, {"registered": None, "error": f"HTTP {exc.code}"}
            except Exception as exc:
                if attempt < 2:
                    time.sleep(2)
                    continue
                return domain, {"registered": None,
                                "error": f"{type(exc).__name__}: {str(exc)[:80]}"}
        return domain, {"registered": None, "error": "retries exhausted"}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for n, (domain, result) in enumerate(pool.map(one, domains), 1):
            out[domain] = result
            if n % 50 == 0:
                print(f"  rdap {n}/{len(domains)}")
    module.close()
    return out


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--per-feed", type=int, default=100)
    parser.add_argument("--benign", type=int, default=500)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--out", default=str(ROOT / "datasets"))
    args = parser.parse_args()

    collected_at = datetime.now(timezone.utc)
    stem = f"real_{collected_at:%Y%m%d}"
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    rows, meta = sample(args)
    regs = sorted({registrable(r["domain"]) for r in rows})
    print(f"rdap lookups for {len(regs)} registrable domains")
    rdap = collect_rdap(regs, args.workers)

    csv_path = out / f"{stem}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    rdap_path = out / f"{stem}.rdap.json"
    rdap_path.write_text(json.dumps(rdap, indent=1, sort_keys=True),
                         encoding="utf-8")

    found = sum(1 for v in rdap.values() if v["registered"] is not None)
    meta.update({
        "collected_at": collected_at.isoformat(),
        "rows": len(rows),
        "malicious": sum(r["label"] for r in rows),
        "benign": sum(1 - r["label"] for r in rows),
        "rdap": {"lookups": len(rdap), "with_registration_date": found,
                 "service": "https://rdap.org/domain/"},
        "files": {csv_path.name: sha256(csv_path),
                  rdap_path.name: sha256(rdap_path)},
        "caveat": ("Labels are feed listings (malicious) and Tranco rank "
                   "(benign), not verified ground truth. Feeds can list "
                   "compromised legitimate sites, and Tranco's top 100k "
                   "contains some abusive domains."),
    })
    meta_path = out / f"{stem}.meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"wrote {csv_path.name}: {meta['malicious']} malicious, "
          f"{meta['benign']} benign; rdap dates for {found}/{len(rdap)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
