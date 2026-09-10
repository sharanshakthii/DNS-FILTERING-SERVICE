"""
Stage 9 — end-to-end checkpoint.

Stages 1 to 8 are each verified on their own, and 314 unit and integration
tests pass. What this adds is one repeatable run that walks the whole chain
and reports on each link:

    packet -> detection module -> aggregation -> policy decision
           -> enforcement -> persistence -> evidence

**What this proves and what it does not.** It proves the components are wired
together correctly and that a decision survives from the wire to the database
with its evidence intact. It says *nothing* about detection accuracy: the
blocked domain is blocked because a controlled fixture lists it, not because
anything detected anything. Accuracy is measured in Stage 16 and is currently
NOT YET MEASURED.

**The demo domains are IANA-reserved and are not malicious.** RFC 2606 and
RFC 6761 reserve `example.com` and `example.net` for documentation. They are
used here precisely so that a demonstration never queries real malware
infrastructure and never depends on a live threat feed.

By default the run is fully offline and deterministic: a stub upstream on
loopback and a controlled local feed file. Pass --upstream to resolve against
a real resolver instead, which is more convincing but depends on the venue's
network.

Usage:
    python tools/checkpoint.py
    python tools/checkpoint.py --upstream 1.1.1.1:53
    python tools/checkpoint.py --port 5399 --keep
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

#: IANA-reserved for documentation (RFC 2606). NOT malicious. Listed in the
#: controlled fixture so the BLOCK outcome is deterministic and repeatable.
DEMO_BLOCKED_DOMAIN = "example.com"

#: Also IANA-reserved. Deliberately absent from the fixture.
DEMO_CLEAN_DOMAIN = "example.net"


class Report:
    """Collects checkpoint results and prints them as they happen."""

    def __init__(self) -> None:
        self.results: list[tuple[str, str, str]] = []
        self._n = 0

    def record(self, status: str, title: str, detail: str = "") -> None:
        self._n += 1
        self.results.append((status, title, detail))
        line = f"  [{status:4}] {self._n:02d}  {title}"
        if detail:
            line += f"\n              {detail}"
        print(line, flush=True)

    def check(self, condition: bool, title: str, detail: str = "") -> bool:
        self.record("PASS" if condition else "FAIL", title, detail)
        return bool(condition)

    def skip(self, title: str, reason: str) -> None:
        self.record("SKIP", title, reason)

    @property
    def failures(self) -> int:
        return sum(1 for status, _, _ in self.results if status == "FAIL")

    @property
    def passes(self) -> int:
        return sum(1 for status, _, _ in self.results if status == "PASS")

    @property
    def skips(self) -> int:
        return sum(1 for status, _, _ in self.results if status == "SKIP")


# -- DNS helpers (independent of the proxy, on purpose) -------------------

def build_query(name: str, txid: int = 0x4242, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii")
                     for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def _suppress_conn_reset(sock: socket.socket) -> None:
    """Stop Windows reporting ICMP port-unreachable as a socket reset.

    Winsock raises WSAECONNRESET (10054) on a UDP socket when an earlier
    datagram provoked an ICMP unreachable — for instance because nothing was
    listening on the destination port yet. Linux does not report this for an
    unconnected socket, which is why this harness passed there and failed on
    Windows. The proxy's own sockets already do this; the harness has its own
    socket and needs it too.
    """
    if not hasattr(socket, "SIO_UDP_CONNRESET"):
        return
    try:
        sock.ioctl(socket.SIO_UDP_CONNRESET, False)  # type: ignore[attr-defined]
    except OSError:
        pass


def ask(port: int, payload: bytes, timeout: float = 5.0) -> bytes | None:
    """Send one query and return the reply, or None if none arrived.

    A connection reset is treated as "no reply", not as success. Every
    checkpoint assertion tests `reply is not None`, so a reset still fails the
    check it belongs to rather than being silently swallowed.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        _suppress_conn_reset(sock)
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, ("127.0.0.1", port))
            return sock.recvfrom(4096)[0]
        except socket.timeout:
            return None
        except ConnectionResetError:
            # Nothing is listening on that port, or an earlier datagram
            # bounced. Either way there is no reply to return.
            return None


def rcode_of(reply: bytes) -> int:
    return struct.unpack("!H", reply[2:4])[0] & 0xF


def ancount_of(reply: bytes) -> int:
    return struct.unpack("!H", reply[6:8])[0]


# -- database inspection --------------------------------------------------

def latest_decision(db_path: str, qname: str) -> dict | None:
    """Read back the most recent stored decision for `qname`."""
    if not Path(db_path).exists():
        return None

    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True,
                           timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT q.id, q.qname, q.client_hash, q.latency_json, "
            "       q.latency_upstream_ms, q.added_latency_ms, "
            "       d.id AS decision_id, d.verdict, d.rcode, "
            "       d.aggregate_score, d.explanation_json "
            "FROM queries q JOIN decisions d ON d.query_id = q.id "
            "WHERE q.qname = ? ORDER BY q.id DESC LIMIT 1", (qname,)).fetchone()
        if row is None:
            return None

        out = dict(row)
        out["evidence"] = [dict(r) for r in conn.execute(
            "SELECT module, score, features_json, status FROM evidence "
            "WHERE decision_id = ? ORDER BY id", (row["decision_id"],))]
        return out
    finally:
        conn.close()


# -- the proxy under test -------------------------------------------------

class ProxyRun:
    """Starts `python -m proxy.dns_proxy` as a real process."""

    def __init__(self, port: int, upstream: tuple[str, int], feed_file: str,
                 db_path: str, enforce: bool) -> None:
        self.port = port
        self.env = dict(
            os.environ,
            DNSF_LISTEN_PORT=str(port),
            DNSF_UPSTREAM_HOST=upstream[0],
            DNSF_UPSTREAM_PORT=str(upstream[1]),
            DNSF_ENGINE_MODULES="ti",
            DNSF_FEED_FILE=feed_file,
            DNSF_FEED_NAME="checkpoint-fixture",
            DNSF_FEED_REFRESH_S="0",
            DNSF_DB_PATH=db_path,
            DNSF_AGGREGATOR_ENFORCE="true" if enforce else "false",
        )
        self.process: subprocess.Popen | None = None
        self.output = ""
        self.startup_error: str | None = None
        self._lines: list[str] = []
        self._reader: threading.Thread | None = None
        self._listening = threading.Event()
        #: True only if the readiness line was actually seen. The event is
        #: also set when the pipe closes, so it alone cannot distinguish
        #: "ready" from "died", and poll() may still read None in the instant
        #: after the pipe closes.
        self._saw_listening = False

    def _drain(self) -> None:
        """Read the proxy's output on a thread and watch for readiness.

        A single reader owns the pipe for the process's whole lifetime.
        Reading it here rather than calling communicate() later means a
        startup failure is visible immediately instead of only after the
        harness has already given up.
        """
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            self._lines.append(line)
            if "listening on" in line:
                self._saw_listening = True
                self._listening.set()
        # Pipe closed: the process has exited. Release anyone still waiting
        # so a dead proxy is reported rather than waited on until timeout.
        self._listening.set()

    def __enter__(self) -> "ProxyRun":
        self.process = subprocess.Popen(
            [sys.executable, "-m", "proxy.dns_proxy"], env=self.env,
            cwd=str(REPO_ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)

        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

        # Wait for the proxy to say it is listening, rather than probing it
        # with a datagram. Probing before the socket is bound produces an ICMP
        # port-unreachable, which Windows reports to the *sender* as
        # WSAECONNRESET — so the old readiness loop failed on Windows and
        # silently passed on Linux, where the same condition is not reported.
        if not self._listening.wait(timeout=30):
            self.startup_error = "proxy did not report 'listening on' within 30s"
            return self

        if not self._saw_listening:
            self.process.wait(timeout=5)
            self.startup_error = (
                f"proxy exited during startup with code {self.process.returncode}")

        return self

    @property
    def failure_detail(self) -> str:
        """The last few lines of proxy output, for reporting a startup failure."""
        tail = [ln.strip() for ln in self._lines[-6:] if ln.strip()]
        if not tail:
            return "the proxy produced no output at all"
        return " | ".join(tail)

    def __exit__(self, *_exc) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self._reader is not None:
            self._reader.join(timeout=5)
        self.output = "".join(self._lines)

    def log_lines(self, needle: str) -> list[str]:
        return [ln for ln in self.output.splitlines() if needle in ln]


# -- the checkpoint phases ------------------------------------------------

def check_observation_mode(report: Report, port: int, upstream: tuple[str, int],
                           feed_file: str, db_path: str, stub) -> None:
    print("\nPHASE A — enforcement DISABLED (observation mode)")
    print("  A BLOCK is decided and recorded; the query is still forwarded.\n")

    with ProxyRun(port, upstream, feed_file, db_path, enforce=False) as run:
        started = run.startup_error is None
        if not report.check(started, "proxy starts and binds",
                            f"UDP 127.0.0.1:{port}" if started
                            else f"{run.startup_error}: {run.failure_detail}"):
            return

        if stub is not None:
            stub.received.clear()

        clean = ask(port, build_query(DEMO_CLEAN_DOMAIN))
        report.check(clean is not None and rcode_of(clean) == 0,
                     f"clean domain resolves ({DEMO_CLEAN_DOMAIN})",
                     f"rcode=NOERROR answers={ancount_of(clean) if clean else 0}")

        blocked = ask(port, build_query(DEMO_BLOCKED_DOMAIN))
        report.check(blocked is not None and rcode_of(blocked) == 0,
                     f"listed domain still resolves ({DEMO_BLOCKED_DOMAIN})",
                     "enforcement is off, so the query is forwarded")

        if stub is not None:
            report.check(len(stub.received) >= 2,
                         "both queries reached upstream",
                         f"upstream received {len(stub.received)}")
        else:
            report.skip("both queries reached upstream",
                        "cannot count a real upstream resolver")

        time.sleep(1.2)   # let the async writer flush

    stored = latest_decision(db_path, DEMO_BLOCKED_DOMAIN)
    if not report.check(stored is not None, "decision persisted to SQLite",
                        db_path):
        return

    report.check(stored["verdict"] == "BLOCK",
                 "policy verdict recorded as BLOCK",
                 f"verdict={stored['verdict']} score={stored['aggregate_score']}")
    report.check(stored["rcode"] == "NOERROR",
                 "stored rcode shows the query was answered normally",
                 f"rcode={stored['rcode']}")

    trace = json.loads(stored["explanation_json"] or "{}")
    enforcement = trace.get("enforcement") or {}
    report.check(enforcement.get("would_block") is True
                 and enforcement.get("applied") is False,
                 "enforcement recorded as decided-but-not-applied",
                 f"would_block={enforcement.get('would_block')} "
                 f"applied={enforcement.get('applied')} "
                 f"action={enforcement.get('action')}")


def check_enforcement_mode(report: Report, port: int, upstream: tuple[str, int],
                           feed_file: str, db_path: str, stub) -> None:
    print("\nPHASE B — enforcement ENABLED")
    print("  The same decision now stops the query before it is forwarded.\n")

    with ProxyRun(port, upstream, feed_file, db_path, enforce=True) as run:
        started = run.startup_error is None
        if not report.check(started, "proxy restarts with enforcement on",
                            "" if started
                            else f"{run.startup_error}: {run.failure_detail}"):
            return

        if stub is not None:
            stub.received.clear()

        clean = ask(port, build_query(DEMO_CLEAN_DOMAIN, txid=0x1111))
        report.check(clean is not None and rcode_of(clean) == 0
                     and ancount_of(clean) >= 1,
                     f"clean domain still resolves ({DEMO_CLEAN_DOMAIN})",
                     "enforcement does not interfere with allowed traffic")

        blocked = ask(port, build_query(DEMO_BLOCKED_DOMAIN, txid=0x2222))
        report.check(blocked is not None and rcode_of(blocked) == 3
                     and ancount_of(blocked) == 0,
                     f"listed domain is blocked ({DEMO_BLOCKED_DOMAIN})",
                     "rcode=NXDOMAIN answers=0")
        report.check(blocked is not None
                     and struct.unpack("!H", blocked[:2])[0] == 0x2222,
                     "block response carries the client transaction ID")

        if stub is not None:
            forwarded = [r for r in stub.received
                         if DEMO_BLOCKED_DOMAIN.encode() in r]
            report.check(not forwarded,
                         "blocked query never reached upstream",
                         f"upstream saw {len(stub.received)} query/queries, "
                         f"none for {DEMO_BLOCKED_DOMAIN}")
        else:
            report.skip("blocked query never reached upstream",
                        "cannot inspect a real upstream resolver")

        malformed = struct.pack("!HHHHHH", 0x0999, 0x0100, 1, 0, 0, 0) + b"\x07ex"
        reply = ask(port, malformed)
        report.check(reply is not None and rcode_of(reply) == 1,
                     "malformed packet still answered FORMERR",
                     "the Stage 2 packet layer is unaffected by enforcement")

        time.sleep(1.2)

    # Read the log only after the context manager has exited: the process
    # output is collected on shutdown, so checking inside the block finds an
    # empty string and reports a false failure.
    log_hit = run.log_lines("blocked " + DEMO_BLOCKED_DOMAIN)
    report.check(bool(log_hit), "structured log records the block",
                 (log_hit[0][:150] + "...") if log_hit else "no log line found")

    stored = latest_decision(db_path, DEMO_BLOCKED_DOMAIN)
    if not report.check(stored is not None,
                        "blocked decision persisted to SQLite"):
        return

    report.check(stored["verdict"] == "BLOCK" and stored["rcode"] == "NXDOMAIN",
                 "stored decision shows the enforced block",
                 f"verdict={stored['verdict']} rcode={stored['rcode']}")

    report.check(stored["latency_upstream_ms"] is None,
                 "no upstream latency stored for a query never forwarded")

    latency = json.loads(stored["latency_json"] or "{}")
    report.check("enforce" in latency,
                 "enforcement latency measured separately",
                 f"enforce={latency.get('enforce')} ms  "
                 f"total={latency.get('total')} ms")

    report.check(stored["client_hash"] not in ("127.0.0.1", "", None),
                 "client address stored pseudonymised",
                 f"client_hash={stored['client_hash']}")

    evidence = stored["evidence"]
    report.check(len(evidence) == 1 and evidence[0]["module"] == "ti"
                 and evidence[0]["status"] == "ok",
                 "module evidence stored",
                 f"module={evidence[0]['module'] if evidence else '-'} "
                 f"score={evidence[0]['score'] if evidence else '-'}")

    features = json.loads(evidence[0]["features_json"]) if evidence else {}
    report.check(features.get("listed") is True
                 and features.get("match_type") == "exact",
                 "evidence explains why the domain matched",
                 f"indicator={features.get('indicator')} "
                 f"feed={features.get('feed')} "
                 f"match_type={features.get('match_type')}")

    trace = json.loads(stored["explanation_json"] or "{}")
    contributions = trace.get("contributions") or []
    report.check(bool(contributions)
                 and contributions[0]["module"] == "ti"
                 and "weight" in contributions[0],
                 "decision trace shows the aggregation derivation",
                 f"method={trace.get('method')} "
                 f"score={contributions[0]['score'] if contributions else '-'} "
                 f"x weight={contributions[0]['weight'] if contributions else '-'}")

    report.check((trace.get("enforcement") or {}).get("applied") is True,
                 "decision trace records that enforcement was applied")


# -- entry point ----------------------------------------------------------

def run_checkpoint(port: int = 5399, upstream: str | None = None,
                   keep: bool = False, workdir: str | None = None) -> int:
    print("=" * 72)
    print("PRJ_112 — STAGE 9 END-TO-END CHECKPOINT")
    print("=" * 72)
    print("Verifies that Stages 1-8 work together as one system:")
    print("  packet -> module -> aggregation -> decision -> enforcement")
    print("         -> persistence -> evidence")
    print()
    print("This proves INTEGRATION, not detection accuracy. The demo domain is")
    print("blocked because a controlled fixture lists it, not because anything")
    print("was detected. Accuracy is Stage 16: NOT YET MEASURED.")
    print()
    print(f"Demo domains are IANA-reserved (RFC 2606) and are NOT malicious:")
    print(f"  listed in the fixture : {DEMO_BLOCKED_DOMAIN}")
    print(f"  absent from it        : {DEMO_CLEAN_DOMAIN}")

    temp = workdir or tempfile.mkdtemp(prefix="prj112-checkpoint-")
    feed_file = str(Path(temp) / "checkpoint-feed.txt")
    db_path = str(Path(temp) / "checkpoint.sqlite3")

    Path(feed_file).write_text(
        "# CONTROLLED FIXTURE for the Stage 9 checkpoint.\n"
        "# Not threat intelligence. example.com is IANA-reserved for\n"
        "# documentation (RFC 2606) and is listed here only so that the\n"
        "# BLOCK outcome is deterministic.\n"
        f"{DEMO_BLOCKED_DOMAIN}\n", encoding="utf-8")

    stub = None
    if upstream:
        host, _, raw_port = upstream.partition(":")
        upstream_addr = (host, int(raw_port or 53))
        print(f"\nUpstream : {upstream_addr[0]}:{upstream_addr[1]} (real resolver)")
        print("           Two checkpoints will SKIP: a real resolver cannot be")
        print("           inspected to prove a query did or did not reach it.")
    else:
        from tests.test_proxy_integration import StubUpstream
        stub = StubUpstream("answer").start()
        upstream_addr = ("127.0.0.1", stub.port)
        print(f"\nUpstream : loopback stub on port {stub.port} (offline, deterministic)")

    print(f"Database : {db_path}")
    print(f"Feed     : {feed_file}")

    report = Report()
    try:
        check_observation_mode(report, port, upstream_addr, feed_file, db_path,
                               stub)
        check_enforcement_mode(report, port, upstream_addr, feed_file, db_path,
                               stub)
    finally:
        if stub is not None:
            stub.stop()

    print()
    print("=" * 72)
    print(f"RESULT: {report.passes} passed, {report.failures} failed, "
          f"{report.skips} skipped")
    if report.failures:
        print("STAGE 9 CHECKPOINT: FAILED")
        for status, title, detail in report.results:
            if status == "FAIL":
                print(f"  - {title}" + (f" ({detail})" if detail else ""))
    else:
        print("STAGE 9 CHECKPOINT: PASSED")
        print("Stages 1-8 are integrated end to end. Detection accuracy is")
        print("still NOT YET MEASURED.")
    print("=" * 72)

    if keep:
        print(f"\nArtefacts kept in {temp}")
    elif workdir is None:
        shutil.rmtree(temp, ignore_errors=True)

    return 1 if report.failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stage 9 end-to-end checkpoint for PRJ_112")
    parser.add_argument("--port", type=int, default=5399,
                        help="port for the proxy under test (default 5399)")
    parser.add_argument("--upstream", default=None,
                        help="real resolver as host:port, e.g. 1.1.1.1:53. "
                             "Omit for the deterministic offline stub.")
    parser.add_argument("--keep", action="store_true",
                        help="keep the temporary database and feed fixture")
    args = parser.parse_args()
    return run_checkpoint(port=args.port, upstream=args.upstream,
                          keep=args.keep)


if __name__ == "__main__":
    raise SystemExit(main())
