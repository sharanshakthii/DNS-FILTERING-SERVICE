"""
Seed synthetic query history, for demonstrating the beaconing module.

Beaconing needs minutes or hours of history, which makes it the one signal
that cannot be demonstrated by typing a query and looking. This writes
observations through the project's own `storage` layer — the same
`QueryRecord` path the DNS proxy uses — so the rows the module reads are
structurally identical to real ones.

**The rows are synthetic and are labelled as such.** Every seeded record
carries `engine: "seeded-fixture"` and `qtype: "A"`, so a reviewer reading
the database or the dashboard can tell them apart from traffic the resolver
actually answered. Never seed a database you intend to take measurements
from.

Usage:
    python tools/seed_observations.py --pattern periodic  --domain beacon-demo.test
    python tools/seed_observations.py --pattern jittered  --domain jitter-demo.test
    python tools/seed_observations.py --pattern irregular --domain irregular-demo.test
    python tools/seed_observations.py --pattern sparse    --domain sparse-demo.test
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from storage.db import Database          # noqa: E402
from storage.models import QueryRecord   # noqa: E402

SEED = 20260905

#: Offsets in seconds before "now". Fixed, so a demonstration is repeatable.
PATTERNS = {
    # Twelve check-ins exactly five minutes apart.
    "periodic": [i * 300 for i in range(12)],
    # The same rhythm with a few seconds of jitter, as real beacons have.
    "jittered": [0, 297, 604, 901, 1198, 1503, 1797, 2104, 2399, 2702,
                 2998, 3301],
    # Human browsing: clustered and uneven.
    "irregular": [0, 41, 723, 911, 1204, 1207, 1966, 2011, 2890, 3402],
    # Too few observations to judge.
    "sparse": [0, 640],
    # Many queries in a few seconds: regular, but not a beacon.
    "burst": [round(i * 0.4, 1) for i in range(15)],
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--db", default="data/prj112.sqlite3")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--pattern", choices=sorted(PATTERNS), default="periodic")
    parser.add_argument("--client", default="seeded-client")
    parser.add_argument("--salt", default="prj112-dev-salt",
                        help="must match DNSF_CLIENT_SALT for per-client scope")
    args = parser.parse_args()

    offsets = PATTERNS[args.pattern]
    now = time.time()
    rng = random.Random(SEED)

    database = Database(args.db)
    try:
        for offset in sorted(offsets, reverse=True):
            when = now - offset
            record = QueryRecord.from_log_payload({
                "client": args.client,
                "qname": args.domain.strip().lower(),
                "qtype": "A",
                "verdict": "ALLOW",
                "rcode": "NOERROR",
                "score": 0.0,
                "engine": "seeded-fixture",
                "evidence": [],
                "explanation": None,
                "latency_ms": {"total": round(rng.uniform(1.0, 3.0), 3)},
                "added_latency_ms": 0.1,
            }, args.salt)
            # Override the timestamp: from_log_payload stamps "now", and the
            # whole point here is to place observations in the past.
            record.ts = datetime.fromtimestamp(when, tz=timezone.utc).isoformat()
            database.insert_record(record)

        total = database.count("queries")
    finally:
        database.close()

    print(f"seeded {len(offsets)} synthetic observations of "
          f"{args.domain} ({args.pattern}) into {args.db}")
    print(f"  offsets before now (s): {offsets}")
    print(f"  queries table now holds {total} rows")
    print("\nSYNTHETIC fixture rows, marked engine=\"seeded-fixture\". Not "
          "traffic this resolver answered. Do not take measurements from a "
          "seeded database.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
