"""
Read-only inspector for the Stage 3 database.

Verification helper, not part of the DNS service. It opens the database
read-only so it can safely be run while the proxy is still going, and it
never writes, migrates, or deletes anything.

Usage:
    python tools/inspect_db.py
    python tools/inspect_db.py --db data/prj112.sqlite3 --limit 20
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def open_readonly(path: Path) -> sqlite3.Connection:
    """Open with the read-only URI so a running proxy cannot be disturbed."""
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True,
                           timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect the PRJ_112 database")
    parser.add_argument("--db", default="data/prj112.sqlite3",
                        help="path to the SQLite file")
    parser.add_argument("--limit", type=int, default=10,
                        help="how many recent queries to show")
    args = parser.parse_args()

    path = Path(args.db)
    if not path.exists():
        print(f"NOT FOUND: {path.resolve()}")
        print("The proxy has not written a database at this path yet.")
        print("Check that you started it from the project folder, and that")
        print("DNSF_DB_ENABLED was not set to false.")
        return 1

    print(f"DATABASE : {path.resolve()}")
    print(f"SIZE     : {path.stat().st_size} bytes")

    conn = open_readonly(path)
    try:
        print(f"SCHEMA   : v{conn.execute('PRAGMA user_version').fetchone()[0]}")

        tables = sorted(r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"))
        print(f"TABLES   : {', '.join(tables)}")

        print("\nROW COUNTS")
        for table in ("queries", "decisions", "evidence", "feed_state"):
            if table in tables:
                count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                print(f"  {table:<12} {count}")

        rows = conn.execute(
            "SELECT q.id, q.ts, q.qname, q.qtype, q.client_hash, "
            "       q.latency_total_ms, q.latency_upstream_ms, "
            "       q.added_latency_ms, q.latency_json, q.error, "
            "       d.verdict, d.rcode, d.aggregate_score, d.engine, "
            "       d.explanation_json "
            "FROM queries q JOIN decisions d ON d.query_id = q.id "
            "ORDER BY q.id DESC LIMIT ?", (args.limit,)).fetchall()

        if not rows:
            print("\nNo queries stored yet.")
            return 0

        print(f"\nMOST RECENT {len(rows)} QUER{'Y' if len(rows) == 1 else 'IES'}"
              " (newest first)")
        for row in rows:
            print("-" * 66)
            print(f"  id            : {row['id']}")
            print(f"  timestamp     : {row['ts']}")
            print(f"  qname         : {row['qname']}")
            print(f"  qtype         : {row['qtype']}")
            print(f"  verdict       : {row['verdict']}   rcode: {row['rcode']}")
            print(f"  score         : {row['aggregate_score']}"
                  f"   engine: {row['engine']}")
            print(f"  client_hash   : {row['client_hash']}  (pseudonymised)")
            print(f"  total    (ms) : {row['latency_total_ms']}")
            print(f"  upstream (ms) : {row['latency_upstream_ms']}")
            print(f"  added    (ms) : {row['added_latency_ms']}"
                  "   <- cost of the filtering path")
            try:
                breakdown = json.loads(row["latency_json"])
                parts = "  ".join(f"{k}={v}" for k, v in sorted(breakdown.items()))
                print(f"  breakdown     : {parts}")
            except (TypeError, ValueError):
                print("  breakdown     : (unreadable)")
            if row["error"]:
                print(f"  error         : {row['error']}")

            explanation = row["explanation_json"] if "explanation_json" in \
                row.keys() else None
            if explanation:
                try:
                    trace = json.loads(explanation)
                except (TypeError, ValueError):
                    trace = None
                if trace:
                    print(f"  decision      : policy={trace.get('policy_verdict')}"
                          f"  enforced={trace.get('enforced')}"
                          f"  method={trace.get('method')}")
                    thresholds = trace.get("thresholds") or {}
                    print(f"  thresholds    : flag>={thresholds.get('flag_at')}"
                          f"  block>={thresholds.get('block_at')}")
                    enf = trace.get("enforcement") or {}
                    if enf:
                        print(f"  enforcement   : enabled={enf.get('enabled')}"
                              f"  would_block={enf.get('would_block')}"
                              f"  applied={enf.get('applied')}"
                              f"  action={enf.get('action')}")
                        if enf.get("not_applied_reason"):
                            print(f"                  {enf['not_applied_reason']}")
                    if trace.get("reason"):
                        print(f"  reason        : {trace['reason']}")
                    for item in trace.get("contributions") or []:
                        # "+" counted toward the score, "-" excluded.
                        mark = "+" if item.get("counted") else "-"
                        print(f"    [{mark}] {item['module']:<10}"
                              f" score={item['score']}"
                              f" x weight={item['weight']}"
                              f" = {item['weighted']}  ({item['status']})")

            evidence = conn.execute(
                "SELECT e.module, e.score, e.features_json, e.latency_ms, e.status "
                "FROM evidence e JOIN decisions d ON e.decision_id = d.id "
                "WHERE d.query_id = ? ORDER BY e.id", (row["id"],)).fetchall()
            if evidence:
                print("  evidence      :")
                for ev in evidence:
                    print(f"      {ev['module']:<12} score={ev['score']}"
                          f"  {ev['latency_ms']}ms  {ev['status']}"
                          f"  {ev['features_json']}")
            else:
                print("  evidence      : none (no modules until Stage 5)")

        print("-" * 66)
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
