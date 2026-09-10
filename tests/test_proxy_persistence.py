"""Stage 3 integration: the proxy writing through a real recorder.

The two things that matter here are that decisions actually land in the
database, and that nothing the database does can affect whether a client
gets a DNS answer.
"""

import struct
import threading
import time

import pytest

from config.settings import Settings
from proxy.dns_proxy import DNSProxy
from storage.db import Database
from storage.writer import AsyncRecorder, NullRecorder
from tests.test_packet import make_query
from tests.test_proxy_integration import StubUpstream, ask


def start_proxy_with(recorder, upstream_port, timeout=2.0):
    settings = Settings(
        listen_host="127.0.0.1",
        listen_port=0,
        upstream_host="127.0.0.1",
        upstream_port=upstream_port,
        upstream_timeout=timeout,
        workers=4,
    )
    proxy = DNSProxy(settings, recorder=recorder)
    thread = threading.Thread(target=proxy.start, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            _ = proxy.port
            return proxy, thread
        except RuntimeError:
            time.sleep(0.01)
    raise RuntimeError("proxy did not bind within 5s")


@pytest.fixture
def persistent_stack(tmp_path):
    db_path = str(tmp_path / "live.sqlite3")
    upstream = StubUpstream("answer").start()
    recorder = AsyncRecorder(db_path, salt="test-salt", flush_interval=0.05)
    proxy, thread = start_proxy_with(recorder, upstream.port)

    yield proxy, recorder, db_path

    proxy.stop()
    thread.join(timeout=3)
    recorder.close()
    upstream.stop()


def test_a_resolved_query_is_persisted(persistent_stack):
    proxy, recorder, db_path = persistent_stack

    ask(proxy.port, make_query("persisted.test"))
    assert recorder.flush(timeout=5)

    db = Database(db_path)
    try:
        rows = db.recent_queries()
        assert len(rows) == 1
        row = rows[0]
        assert row["qname"] == "persisted.test"
        assert row["qtype"] == "A"
        assert row["verdict"] == "ALLOW"
        assert row["rcode"] == "NOERROR"
        assert row["engine"] == "allow-all"
    finally:
        db.close()


def test_latency_instrumentation_survives_into_the_database(persistent_stack):
    """RQ2 depends on these columns being real, not zero-filled."""
    proxy, recorder, db_path = persistent_stack

    ask(proxy.port, make_query("timed.test"))
    assert recorder.flush(timeout=5)

    db = Database(db_path)
    try:
        row = db.recent_queries()[0]
        assert row["latency_total_ms"] > 0
        assert row["latency_upstream_ms"] is not None
        assert row["added_latency_ms"] >= 0
        assert row["latency_total_ms"] >= row["latency_upstream_ms"]
        assert '"parse"' in row["latency_json"]
    finally:
        db.close()


def test_every_query_produces_exactly_one_row(persistent_stack):
    proxy, recorder, db_path = persistent_stack

    for i in range(30):
        ask(proxy.port, make_query(f"many{i}.test"))
    assert recorder.flush(timeout=10)

    db = Database(db_path)
    try:
        assert db.count("queries") == 30
        assert db.count("decisions") == 30
    finally:
        db.close()


def test_malformed_queries_are_persisted_too(persistent_stack):
    """FORMERR is an outcome the experiments need to count."""
    proxy, recorder, db_path = persistent_stack

    bad = struct.pack("!HHHHHH", 0x0999, 0x0100, 1, 0, 0, 0) + b"\x07example"
    ask(proxy.port, bad)
    assert recorder.flush(timeout=5)

    db = Database(db_path)
    try:
        row = db.recent_queries()[0]
        assert row["verdict"] == "FORMERR"
        assert row["qname"] is None
        assert row["error"]
    finally:
        db.close()


def test_client_ip_is_pseudonymised_in_storage(persistent_stack):
    proxy, recorder, db_path = persistent_stack

    ask(proxy.port, make_query("private.test"))
    assert recorder.flush(timeout=5)

    db = Database(db_path)
    try:
        assert db.recent_queries()[0]["client_hash"] != "127.0.0.1"
    finally:
        db.close()


# -- storage must never affect DNS service --------------------------------

class ExplodingRecorder:
    """Worst case: a recorder that raises on every call.

    Counting is locked because proxy workers call record() concurrently, and
    the count is polled rather than read once: the reply is sent to the
    client *before* _record runs, so a client that has its answer cannot
    assume the recorder has been reached yet.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.calls = 0

    def record(self, payload):
        with self._lock:
            self.calls += 1
        raise RuntimeError("storage is on fire")

    def wait_for(self, n, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self.calls >= n:
                    return True
            time.sleep(0.01)
        return False


def test_dns_still_works_when_the_recorder_raises():
    upstream = StubUpstream("answer").start()
    recorder = ExplodingRecorder()
    proxy, thread = start_proxy_with(recorder, upstream.port)
    try:
        reply = ask(proxy.port, make_query("resilient.test", txid=0x0A0A))
        txid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", reply[:12])
        assert txid == 0x0A0A
        assert flags & 0xF == 0, "expected NOERROR despite storage failure"
        assert an == 1

        # And the proxy is still serving afterwards.
        second = ask(proxy.port, make_query("still-alive.test", txid=0x0B0B))
        assert struct.unpack("!H", second[:2])[0] == 0x0B0B

        assert recorder.wait_for(2), (
            f"recorder was reached {recorder.calls} times, expected 2")
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_dns_still_works_with_no_recorder_at_all():
    """Persistence is optional; the Stage 2 behaviour must be unchanged."""
    upstream = StubUpstream("answer").start()
    proxy, thread = start_proxy_with(None, upstream.port)
    try:
        reply = ask(proxy.port, make_query("norecorder.test", txid=0x0C0C))
        assert struct.unpack("!H", reply[:2])[0] == 0x0C0C
        assert struct.unpack("!H", reply[6:8])[0] == 1
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_null_recorder_is_accepted_by_the_proxy():
    upstream = StubUpstream("answer").start()
    proxy, thread = start_proxy_with(NullRecorder(), upstream.port)
    try:
        reply = ask(proxy.port, make_query("null.test", txid=0x0D0D))
        assert struct.unpack("!H", reply[:2])[0] == 0x0D0D
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_persistence_does_not_dominate_the_measured_path(persistent_stack):
    """Storage is enqueue-only, so added latency must stay small.

    Not a performance claim and not a result — a guard that would catch
    someone later making the write synchronous, which would silently
    corrupt every latency figure the project reports.
    """
    proxy, recorder, db_path = persistent_stack

    for i in range(20):
        ask(proxy.port, make_query(f"lat{i}.test"))
    assert recorder.flush(timeout=10)

    db = Database(db_path)
    try:
        added = [r["added_latency_ms"] for r in db.recent_queries(limit=20)]
        worst = max(added)
        assert worst < 50.0, (
            f"added latency reached {worst:.2f} ms; storage may have ended up "
            f"on the query path"
        )
    finally:
        db.close()
