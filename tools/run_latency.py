"""
Run the Stage 18 latency measurements and write the report artifacts.

Deliberately **not** part of the pytest suite: Mode B spawns real proxy
processes and sends thousands of queries, which belongs in an explicit
measurement run rather than in a suite people run on every change.
`tests/test_latency.py` covers the statistics and the structure; this
performs the measurement.

Two modes:

  **A — engine only.** Times module dispatch and aggregation over the Stage
  16 dataset, for every ablation configuration. No sockets, no upstream.
  Isolates what detection costs from what the network costs.

  **B — end to end.** Starts `python -m proxy.dns_proxy` against a loopback
  stub upstream, sends queries, and reads the per-phase breakdown back out
  of SQLite. Covers the real socket and packet path, and the two cases Mode A
  cannot reach: an enforced block, where no upstream call happens at all, and
  a module that declines to assess.

Usage:
    python tools/run_latency.py
    python tools/run_latency.py --mode a
    python tools/run_latency.py --queries 500 --repeats 3
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import platform
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.modules.base import QueryContext  # noqa: E402
from experiments.harness import (  # noqa: E402
    ALL_MODULES,
    Harness,
    dataset_checksum,
    load_rows,
)
from experiments.latency import (  # noqa: E402
    DEFAULT_REPEATS,
    DEFAULT_WARMUP,
    Distribution,
    added_latency,
    collect,
    discard_warmup,
    summarise_phases,
    time_engine,
)

FIXED_NOW = 2_000_000_000.0

#: Configurations timed in Mode A. Each module alone gives its own cost;
#: the full set gives the fusion; none gives the engine's own overhead with
#: no detection work at all, which is the baseline the rest are measured
#: against.
MODE_A_CONFIGS = [("none", ())] + [(m, (m,)) for m in ALL_MODULES] + [
    ("all", ALL_MODULES)]

CAVEAT = (
    "Measured on one machine. Unlike detection accuracy, a timing "
    "measurement does not depend on the dataset labels being correct, so "
    "these are real measurements of this implementation. They are still "
    "hardware-specific: absolute milliseconds will differ elsewhere. Mode B "
    "resolves against a loopback stub, not a real resolver, so upstream time "
    "is unnaturally small and stable — which is deliberate, so that added "
    "latency is not swamped by internet variance, but it means the total is "
    "not a realistic end-user figure. The portable results are the "
    "comparisons: the per-module ranking, and added latency relative to a "
    "resolution."
)


def build_query(name: str, txid: int = 0x4242) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii")
                     for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


# -- Mode A ----------------------------------------------------------------

def run_mode_a(harness: Harness, rows, repeats: int, warmup: int) -> list[dict]:
    print("\nMode A — engine only (no sockets, no upstream)")
    contexts = [QueryContext(qname=row.domain, qtype="A", client_id="latency",
                             timestamp=FIXED_NOW) for row in rows]
    out: list[dict] = []

    print(f"  {'configuration':<14}{'n':>7}{'p50':>9}{'p90':>9}{'p99':>9}"
          f"{'max':>9}   ms, modules+aggregate")
    for name, modules in MODE_A_CONFIGS:
        engine = harness.build_engine(modules)
        measured = time_engine(engine, contexts, repeats=repeats,
                               warmup=warmup)
        total = measured["phases"]["total"]

        out.append({
            "mode": "A", "configuration": name,
            "modules": ",".join(modules) or "(none)",
            "queries_timed": measured["queries_timed"],
            **{f"total_{k}": v for k, v in total.items() if k != "label"},
            **{f"modules_{k}": v
               for k, v in measured["phases"]["modules"].items()
               if k != "label"},
            **{f"aggregate_{k}": v
               for k, v in measured["phases"]["aggregate"].items()
               if k != "label"},
            "per_module": measured["per_module"],
            "per_run": measured["per_run"],
        })
        print(f"  {name:<14}{total['count']:>7}{total['p50']:>9.4f}"
              f"{total['p90']:>9.4f}{total['p99']:>9.4f}{total['max']:>9.4f}")

    print("\n  per-module cost of a single evaluate() call")
    print(f"  {'module':<14}{'n':>7}{'p50':>9}{'p90':>9}{'p99':>9}")
    for entry in out:
        if entry["configuration"] in {"none", "all"}:
            continue
        for name, stats in entry["per_module"].items():
            print(f"  {name:<14}{stats['count']:>7}{stats['p50']:>9.4f}"
                  f"{stats['p90']:>9.4f}{stats['p99']:>9.4f}")
    return out


# -- Mode B ----------------------------------------------------------------

class StubUpstream:
    """A loopback resolver that answers everything with 127.0.0.1.

    Keeps upstream time small and stable so that added latency is visible
    rather than buried under internet variance.
    """

    def __init__(self) -> None:
        import threading

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        from proxy.packet import parse_query

        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                query = parse_query(data)
            except Exception:
                continue
            header = struct.pack("!HHHHHH", query.txid, 0x8180, 1, 1, 0, 0)
            question = query.question.qname_wire + struct.pack(
                "!HH", query.question.qtype, query.question.qclass)
            answer = struct.pack("!HHHIH", 0xC00C, query.question.qtype,
                                 query.question.qclass, 60, 4) + b"\x7f\x00\x00\x01"
            self.sock.sendto(header + question + answer, addr)

    def start(self) -> "StubUpstream":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


def read_breakdowns(db_path: Path) -> list[dict]:
    """Per-query timing breakdowns, straight out of the decision database."""
    import sqlite3

    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True,
                           timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT q.latency_json, q.added_latency_ms, d.verdict, q.qname "
            "FROM queries q JOIN decisions d ON d.query_id = q.id "
            "ORDER BY q.id").fetchall()
    finally:
        conn.close()

    records = []
    for row in rows:
        try:
            breakdown = json.loads(row["latency_json"] or "{}")
        except (TypeError, ValueError):
            continue
        breakdown["verdict"] = row["verdict"]
        breakdown["qname"] = row["qname"]
        breakdown["added_recorded"] = row["added_latency_ms"]
        records.append(breakdown)
    return records


def run_proxy_case(label: str, env_extra: dict, names: list[str],
                   queries: int, warmup: int, workdir: Path) -> dict | None:
    """Start a real proxy, send queries, read the breakdowns back."""
    upstream = StubUpstream().start()
    db_path = workdir / f"{label}.sqlite3"
    port = 5450

    env = dict(os.environ,
               DNSF_LISTEN_PORT=str(port),
               DNSF_UPSTREAM_HOST="127.0.0.1",
               DNSF_UPSTREAM_PORT=str(upstream.port),
               DNSF_DB_PATH=str(db_path),
               DNSF_DB_FLUSH_INTERVAL="0.05",
               **env_extra)

    process = subprocess.Popen(
        [sys.executable, "-m", "proxy.dns_proxy"], env=env, cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    # A dedicated reader owns the pipe for the process's whole lifetime.
    # Reading only until "listening on" and then stopping fills the 64 KB
    # pipe buffer once the proxy has logged a few hundred queries, at which
    # point it blocks writing its own log and the measurement stalls — which
    # is exactly what a latency run must not do.
    import threading

    listening = threading.Event()

    def drain() -> None:
        for line in process.stdout:
            if "listening on" in line:
                listening.set()
        listening.set()          # pipe closed: release anyone waiting

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()

    if not listening.wait(timeout=40) or process.poll() is not None:
        process.terminate()
        upstream.stop()
        print(f"  {label:<22} proxy did not start; skipped")
        return None

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3.0)
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        try:
            client.ioctl(socket.SIO_UDP_CONNRESET, False)
        except OSError:
            pass

    try:
        for i in range(queries):
            name = names[i % len(names)]
            try:
                client.sendto(build_query(name, txid=(i % 65535) + 1),
                              ("127.0.0.1", port))
                client.recvfrom(4096)
            except (socket.timeout, ConnectionResetError):
                continue
    finally:
        client.close()
        time.sleep(1.0)          # let the async writer flush
        process.terminate()
        try:
            process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        upstream.stop()

    records = read_breakdowns(db_path)
    if not records:
        print(f"  {label:<22} no records stored; skipped")
        return None

    phases = summarise_phases(records, warmup)
    added = added_latency(records, warmup)
    verdicts: dict[str, int] = {}
    for record in records:
        verdicts[record["verdict"]] = verdicts.get(record["verdict"], 0) + 1

    upstream_seen = len(collect(records, "upstream"))
    print(f"  {label:<22}{len(records):>7}"
          f"{phases['total']['p50']:>9.4f}{phases['total']['p90']:>9.4f}"
          f"{phases['total']['p99']:>9.4f}{added['p50']:>10.4f}"
          f"   upstream on {upstream_seen}/{len(records)}")

    return {"mode": "B", "case": label, "queries_stored": len(records),
            "verdicts": verdicts, "phases": phases, "added": added,
            "queries_with_upstream": upstream_seen}


def run_mode_b(workdir: Path, queries: int, warmup: int) -> list[dict]:
    print("\nMode B — end to end through the real proxy (loopback stub upstream)")
    print(f"  {'case':<22}{'n':>7}{'p50':>9}{'p90':>9}{'p99':>9}{'added p50':>10}")

    feed = workdir / "feed.txt"
    feed.write_text("blocked-demo.test\n", encoding="utf-8")

    benign = [f"latency-{i}.test" for i in range(50)]
    cases = [
        # No detection at all: the floor this resolver cannot go below.
        ("baseline_no_modules", {}, benign),
        # Every module, forwarded normally.
        ("all_modules_allow", {
            "DNSF_ENGINE_MODULES": "ti,nrd,typosquat,dga,beaconing",
            "DNSF_FEED_FILE": str(feed),
            "DNSF_TYPOSQUAT_BRANDS": "examplebrand,acmeshop",
            "DNSF_NRD_NEW_WITHIN_S": "2",
        }, benign),
        # Enforced block: returns before the upstream call, so `upstream`
        # should be absent from every record.
        ("enforced_block", {
            "DNSF_ENGINE_MODULES": "ti",
            "DNSF_FEED_FILE": str(feed),
            "DNSF_AGGREGATOR_ENFORCE": "true",
        }, ["blocked-demo.test"]),
        # A module that declines to assess: not free, and it should show.
        ("module_unavailable", {
            "DNSF_ENGINE_MODULES": "typosquat",   # no brands configured
        }, benign),
    ]

    results = []
    for label, env_extra, names in cases:
        outcome = run_proxy_case(label, env_extra, names, queries, warmup,
                                 workdir)
        if outcome is not None:
            results.append(outcome)
    return results


# -- entry point -----------------------------------------------------------

def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n",
                                extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage 18 latency measurement")
    parser.add_argument("--dataset",
                        default=str(REPO_ROOT / "datasets" / "eval_dev.csv"))
    parser.add_argument("--out",
                        default=str(REPO_ROOT / "experiments" / "results"))
    parser.add_argument("--mode", choices=["a", "b", "both"], default="both")
    parser.add_argument("--queries", type=int, default=400,
                        help="queries per Mode B case")
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    args = parser.parse_args()

    logging.getLogger("engine").setLevel(logging.ERROR)
    logging.getLogger("engine.aggregator").setLevel(logging.ERROR)

    dataset = Path(args.dataset)
    rows = load_rows(dataset)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"dataset : {dataset.name} ({len(rows)} rows)")
    print(f"machine : {platform.platform()}")
    print(f"python  : {platform.python_version()}")
    print(f"warm-up : {args.warmup} discarded per configuration")
    print(f"repeats : {args.repeats}")

    mode_a: list[dict] = []
    mode_b: list[dict] = []

    if args.mode in ("a", "both"):
        harness = Harness(rows, now=FIXED_NOW)
        mode_a = run_mode_a(harness, rows, args.repeats, args.warmup)
        write_csv(out_dir / "latency_engine.csv", mode_a)

    if args.mode in ("b", "both"):
        workdir = out_dir / "_latency_run"
        workdir.mkdir(parents=True, exist_ok=True)
        mode_b = run_mode_b(workdir, args.queries, args.warmup)
        write_csv(out_dir / "latency_end_to_end.csv", [
            {"mode": r["mode"], "case": r["case"],
             "queries_stored": r["queries_stored"],
             "queries_with_upstream": r["queries_with_upstream"],
             **{f"total_{k}": v for k, v in r["phases"]["total"].items()
                if k != "label"},
             **{f"added_{k}": v for k, v in r["added"].items()
                if k != "label"}}
            for r in mode_b])

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "machine": platform.platform(),
        "processor": platform.processor() or "unknown",
        "python": platform.python_version(),
        "dataset": {"path": dataset.name, "rows": len(rows),
                    "sha256": dataset_checksum(dataset)},
        "warmup_discarded": args.warmup,
        "repeats": args.repeats,
        "queries_per_case": args.queries,
        "mode_a_engine_only": mode_a,
        "mode_b_end_to_end": mode_b,
        "caveat": CAVEAT,
    }
    (out_dir / "latency.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8")

    print("\nartifacts")
    for name in ("latency_engine.csv", "latency_end_to_end.csv",
                 "latency.json"):
        path = out_dir / name
        if path.exists():
            print(f"  {path.name} ({path.stat().st_size} bytes)")
    print("\n" + CAVEAT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
