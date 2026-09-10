"""Stage 9 tests: the end-to-end checkpoint harness.

A verification tool that reports PASS when the system is broken is worse than
no tool at all, so most of these check that the harness can actually fail —
its exit code, its failure counting, and the fact that it reads the database
rather than its own assumptions.

The full run is exercised once as a subprocess. That is slow (roughly ten
seconds) but it is the only way to test what the tool actually does.
"""

import json
import subprocess
import sqlite3
import sys
from pathlib import Path

import pytest

from tools.checkpoint import (
    DEMO_BLOCKED_DOMAIN,
    DEMO_CLEAN_DOMAIN,
    Report,
    ancount_of,
    build_query,
    latest_decision,
    rcode_of,
    run_checkpoint,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# -- the demo domains must be safe ----------------------------------------

def test_demo_domains_are_iana_reserved():
    """A demonstration must never query real malware infrastructure.

    RFC 2606 reserves example.com and example.net for documentation.
    """
    assert DEMO_BLOCKED_DOMAIN == "example.com"
    assert DEMO_CLEAN_DOMAIN == "example.net"


def test_the_two_demo_domains_are_different():
    assert DEMO_BLOCKED_DOMAIN != DEMO_CLEAN_DOMAIN


# -- the report ------------------------------------------------------------

def test_a_passing_check_is_counted_as_a_pass(capsys):
    report = Report()
    assert report.check(True, "something works") is True
    assert (report.passes, report.failures, report.skips) == (1, 0, 0)
    assert "[PASS]" in capsys.readouterr().out


def test_a_failing_check_is_counted_as_a_failure(capsys):
    """The property that makes the tool worth running."""
    report = Report()
    assert report.check(False, "something is broken") is False
    assert (report.passes, report.failures, report.skips) == (0, 1, 0)
    assert "[FAIL]" in capsys.readouterr().out


def test_a_skip_is_neither_a_pass_nor_a_failure():
    report = Report()
    report.skip("cannot inspect a real resolver", "no stub available")
    assert (report.passes, report.failures, report.skips) == (0, 0, 1)


def test_checks_are_numbered_in_order(capsys):
    report = Report()
    report.check(True, "first")
    report.check(True, "second")
    out = capsys.readouterr().out
    assert "01  first" in out and "02  second" in out


# -- DNS helpers -----------------------------------------------------------

def test_build_query_produces_a_parseable_dns_query():
    from proxy.packet import parse_query

    query = parse_query(build_query("example.com", txid=0x1234))
    assert query.txid == 0x1234
    assert query.question.qname == "example.com"
    assert query.question.qtype == 1


def test_rcode_and_ancount_read_the_header():
    import struct

    reply = struct.pack("!HHHHHH", 1, 0x8183, 1, 2, 0, 0)
    assert rcode_of(reply) == 3
    assert ancount_of(reply) == 2


# -- database reads --------------------------------------------------------

def test_latest_decision_returns_none_for_a_missing_database(tmp_path):
    assert latest_decision(str(tmp_path / "nope.sqlite3"), "x.test") is None


def test_latest_decision_returns_none_for_an_unseen_domain(tmp_path):
    from storage.db import Database

    path = str(tmp_path / "empty.sqlite3")
    Database(path).close()
    assert latest_decision(path, "never-queried.test") is None


def test_latest_decision_reads_the_most_recent_row(tmp_path):
    from storage.db import Database
    from storage.models import QueryRecord

    path = str(tmp_path / "d.sqlite3")
    db = Database(path)
    try:
        for score in (0.1, 0.9):
            db.insert_record(QueryRecord.from_log_payload({
                "client": "192.0.2.1", "qname": "repeat.test", "qtype": "A",
                "verdict": "BLOCK", "rcode": "NXDOMAIN", "score": score,
                "evidence": [{"module": "ti", "score": score, "features": {},
                              "latency_ms": 0.1, "status": "ok"}],
                "latency_ms": {"total": 1.0}, "added_latency_ms": 0.5,
                "engine": "engine[ti]",
                "explanation": {"method": "weighted_mean"}}, "salt"))
    finally:
        db.close()

    found = latest_decision(path, "repeat.test")
    assert found["aggregate_score"] == 0.9, "an older row was returned"
    assert found["evidence"][0]["module"] == "ti"
    assert json.loads(found["explanation_json"])["method"] == "weighted_mean"


def test_latest_decision_opens_the_database_read_only(tmp_path):
    """It may be run while the proxy is writing; it must not disturb it."""
    from storage.db import Database

    path = str(tmp_path / "ro.sqlite3")
    Database(path).close()
    latest_decision(path, "x.test")

    conn = sqlite3.connect(path)
    try:
        conn.execute("INSERT INTO queries (ts, client_hash, qname, qtype, "
                     "latency_total_ms, added_latency_ms, latency_json) "
                     "VALUES ('t','h','x.test','A',1.0,0.5,'{}')")
        conn.commit()
    finally:
        conn.close()


# -- the full run ----------------------------------------------------------

@pytest.mark.slow
def test_the_checkpoint_passes_end_to_end(tmp_path):
    """Runs the real harness against a real proxy process.

    Slow, and deliberately so: this is the only test that exercises what the
    tool actually claims to verify.
    """
    exit_code = run_checkpoint(port=5407, workdir=str(tmp_path))

    assert exit_code == 0, "the checkpoint reported a failure"

    db = tmp_path / "checkpoint.sqlite3"
    assert db.exists(), "the checkpoint produced no database"

    stored = latest_decision(str(db), DEMO_BLOCKED_DOMAIN)
    assert stored["verdict"] == "BLOCK"
    assert stored["rcode"] == "NXDOMAIN"
    assert stored["evidence"][0]["module"] == "ti"


@pytest.mark.slow
def test_the_checkpoint_writes_a_controlled_fixture_not_real_intelligence(tmp_path):
    run_checkpoint(port=5408, workdir=str(tmp_path))

    fixture = (tmp_path / "checkpoint-feed.txt").read_text(encoding="utf-8")
    assert "CONTROLLED FIXTURE" in fixture
    assert "Not threat intelligence" in fixture
    assert DEMO_BLOCKED_DOMAIN in fixture
    assert DEMO_CLEAN_DOMAIN not in fixture


@pytest.mark.slow
def test_the_checkpoint_exits_non_zero_when_the_system_is_broken(tmp_path):
    """A verification tool that cannot fail is worthless.

    Points the proxy at a port where nothing is listening, using the same
    --upstream override a reviewer would use for a real resolver. Resolution
    then fails, so the clean-domain checkpoints must fail and the exit code
    must be non-zero. This is a realistic breakage — an unreachable upstream
    is exactly what a blocked campus network looks like.
    """
    exit_code = run_checkpoint(port=5409, upstream="127.0.0.1:1",
                               workdir=str(tmp_path))

    assert exit_code == 1, \
        "the checkpoint passed while the upstream was unreachable"


@pytest.mark.slow
def test_the_checkpoint_is_runnable_as_a_command():
    """`python tools/checkpoint.py` is what a reviewer will actually type."""
    completed = subprocess.run(
        [sys.executable, "tools/checkpoint.py", "--port", "5410"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=180)

    assert completed.returncode == 0, completed.stdout[-2000:]
    assert "STAGE 9 CHECKPOINT: PASSED" in completed.stdout
    assert "NOT YET MEASURED" in completed.stdout, \
        "the accuracy disclaimer is missing from the output"
    assert "0 failed" in completed.stdout


# -- Windows connection-reset regression ----------------------------------

def test_ask_returns_none_when_nothing_is_listening():
    """Regression for WinError 10054.

    Sending to a port with no listener provokes an ICMP port-unreachable.
    Windows reports that to the *sender* as WSAECONNRESET on the next
    recvfrom; Linux does not report it for an unconnected socket, which is
    why the original harness passed here and failed on Windows. Either way
    the correct result is "no reply", never an exception and never a pass.
    """
    from tools.checkpoint import ask

    assert ask(1, build_query("nothing.test"), timeout=0.5) is None


def test_ask_never_reports_a_reset_as_a_reply():
    """A reset must not be convertible into a successful checkpoint."""
    from tools.checkpoint import ask

    for _ in range(3):
        assert ask(1, build_query("nothing.test"), timeout=0.3) is None


def test_readiness_does_not_probe_before_the_proxy_binds():
    """The fix: wait for the proxy's own log line instead of sending a packet.

    Probing an unbound port is what produced the reset in the first place, so
    the harness must not send anything until the proxy says it is listening.
    """
    source = (REPO_ROOT / "tools" / "checkpoint.py").read_text(encoding="utf-8")
    enter_body = source.split("def __enter__", 1)[1].split("@property", 1)[0]

    assert "listening on" in enter_body, "readiness is not based on the log line"
    assert "ask(" not in enter_body, "the readiness path still sends a probe"


@pytest.mark.slow
def test_the_harness_reports_why_a_proxy_failed_to_start(tmp_path):
    """Requirement: a dying proxy must surface its own output, not a timeout."""
    from tools.checkpoint import ProxyRun

    feed = tmp_path / "f.txt"
    feed.write_text("example.com\n", encoding="utf-8")

    run = ProxyRun(port=5411, upstream=("127.0.0.1", 5), feed_file=str(feed),
                   db_path=str(tmp_path / "x.sqlite3"), enforce=False)
    run.env["DNSF_ENGINE_MODULES"] = "does-not-exist"

    with run:
        pass

    assert run.startup_error is not None, "a failed startup was reported as fine"
    assert "unknown module" in run.failure_detail, \
        f"the real cause was not surfaced: {run.failure_detail}"
