"""Stage 8 tests: enforcement.

The claim Stage 8 makes is that a blocked query is actually stopped. The
tests that matter most are therefore the ones that check the upstream was
never contacted, and the ones that check nothing is blocked when enforcement
is off. Everything else is detail.
"""

import struct
import threading
import time

import pytest

from config.settings import Settings
from engine.decision import DecisionEngine
from engine.modules.base import DetectionModule, ModuleScore
from engine.modules.null import FixedScoreModule
from proxy.dns_proxy import DNSProxy
from proxy.enforce import BlockResponder
from proxy.packet import HEADER_LEN, parse_query
from tests.test_packet import make_query
from tests.test_proxy_integration import StubUpstream, ask


class Capturing:
    def __init__(self):
        self._lock = threading.Lock()
        self.payloads = []

    def record(self, payload):
        with self._lock:
            self.payloads.append(payload)

    def wait_for(self, n, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if len(self.payloads) >= n:
                    return list(self.payloads)
            time.sleep(0.01)
        raise AssertionError(f"only {len(self.payloads)} payload(s) recorded")


def start(score, enforce, upstream_port, recorder=None, **overrides):
    """A proxy whose single module always returns `score`."""
    settings = Settings(
        listen_host="127.0.0.1", listen_port=0,
        upstream_host="127.0.0.1", upstream_port=upstream_port,
        upstream_timeout=overrides.pop("upstream_timeout", 2.0),
        workers=overrides.pop("workers", 4),
        aggregator_enforce=enforce, **overrides)
    engine = DecisionEngine(
        [FixedScoreModule("ti", score)],
        aggregator=__import__("engine.aggregator", fromlist=["RiskAggregator"])
        .RiskAggregator.from_settings(settings))
    proxy = DNSProxy(settings, engine=engine, recorder=recorder)
    thread = threading.Thread(target=proxy.start, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            _ = proxy.port
            return proxy, thread
        except RuntimeError:
            time.sleep(0.01)
    raise RuntimeError("proxy did not bind")


def rcode_of(reply):
    return struct.unpack("!H", reply[2:4])[0] & 0xF


def ancount_of(reply):
    return struct.unpack("!H", reply[6:8])[0]


# -- the responder in isolation -------------------------------------------

def test_nxdomain_is_the_default_representation():
    query = parse_query(make_query("blocked.test", txid=0x1234))
    payload, name = BlockResponder().build(query)

    assert name == "NXDOMAIN"
    txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", payload[:HEADER_LEN])
    assert txid == 0x1234
    assert (flags >> 15) & 1 == 1        # QR set
    assert flags & 0xF == 3
    assert qd == 1 and an == 0


def test_refused_states_only_that_we_decline():
    payload, name = BlockResponder(mode="refused").build(
        parse_query(make_query("blocked.test")))
    assert name == "REFUSED"
    assert struct.unpack("!H", payload[2:4])[0] & 0xF == 5


def test_sinkhole_answers_an_a_query_with_the_configured_address():
    payload, name = BlockResponder(mode="sinkhole",
                                   sinkhole_ipv4="192.0.2.1").build(
        parse_query(make_query("blocked.test", qtype=1)))

    assert name == "NOERROR"
    assert struct.unpack("!H", payload[6:8])[0] == 1
    assert payload.endswith(bytes([192, 0, 2, 1]))


def test_sinkhole_answers_an_aaaa_query_with_sixteen_bytes():
    payload, name = BlockResponder(mode="sinkhole", sinkhole_ipv6="::1").build(
        parse_query(make_query("blocked.test", qtype=28)))

    assert name == "NOERROR"
    assert payload.endswith(b"\x00" * 15 + b"\x01")


@pytest.mark.parametrize("qtype", [15, 16, 2, 6])
def test_sinkhole_falls_back_to_nxdomain_for_untreatable_types(qtype):
    """There is no meaningful synthetic MX or TXT answer."""
    payload, name = BlockResponder(mode="sinkhole").build(
        parse_query(make_query("blocked.test", qtype=qtype)))
    assert name == "NXDOMAIN", "a fallback was reported as a sinkhole"
    assert struct.unpack("!H", payload[2:4])[0] & 0xF == 3


def test_the_reported_rcode_matches_what_was_sent():
    """A fallback must never be logged as the configured mode."""
    responder = BlockResponder(mode="sinkhole")
    for qtype, expected in [(1, "NOERROR"), (16, "NXDOMAIN")]:
        payload, name = responder.build(
            parse_query(make_query("x.test", qtype=qtype)))
        actual = struct.unpack("!H", payload[2:4])[0] & 0xF
        assert (name == "NOERROR") == (actual == 0)
        assert name == expected


def test_the_block_ttl_is_configurable():
    payload, _ = BlockResponder(mode="sinkhole", ttl=300).build(
        parse_query(make_query("x.test", qtype=1)))
    assert struct.unpack("!I", payload[-10:-6])[0] == 300


# -- configuration validation ---------------------------------------------

def test_an_unknown_block_mode_is_rejected():
    with pytest.raises(ValueError, match="unknown block response"):
        BlockResponder(mode="teapot")


@pytest.mark.parametrize("kwargs", [
    {"sinkhole_ipv4": "not-an-ip"},
    {"sinkhole_ipv6": "192.0.2.1"},
    {"ttl": -1},
])
def test_malformed_enforcement_settings_fail_at_startup(kwargs):
    """Loudly at startup beats silently wrong on every query."""
    with pytest.raises(ValueError):
        BlockResponder(**kwargs)


def test_the_responder_is_built_from_settings():
    responder = BlockResponder.from_settings(
        Settings(block_response="sinkhole", block_sinkhole_ipv4="10.0.0.1"))
    assert responder.mode == "sinkhole"
    assert responder.describe()["sinkhole_ipv4"] == "10.0.0.1"


def test_enforcement_is_disabled_by_default():
    assert Settings().aggregator_enforce is False
    assert Settings().block_response == "nxdomain"


# -- end to end: enforcement enabled --------------------------------------

def test_a_blocked_query_returns_nxdomain():
    upstream = StubUpstream("answer").start()
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port)
    try:
        reply = ask(proxy.port, make_query("evil.test", txid=0x0B0B))
        assert struct.unpack("!H", reply[:2])[0] == 0x0B0B
        assert rcode_of(reply) == 3
        assert ancount_of(reply) == 0
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_a_blocked_query_never_reaches_upstream():
    """The point of blocking: the name must not leak to the upstream resolver."""
    upstream = StubUpstream("answer").start()
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port)
    try:
        ask(proxy.port, make_query("evil.test"))
        time.sleep(0.3)
        assert upstream.received == [], \
            "the blocked query was forwarded upstream anyway"
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_an_allowed_query_still_reaches_upstream():
    upstream = StubUpstream("answer").start()
    proxy, thread = start(0.0, enforce=True, upstream_port=upstream.port)
    try:
        reply = ask(proxy.port, make_query("clean.test", txid=0x0C0C))
        assert rcode_of(reply) == 0
        assert ancount_of(reply) == 1
        assert upstream.received, "an allowed query never reached upstream"
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_a_flagged_query_is_forwarded_even_when_enforcing():
    """FLAG must never be silently escalated into a block."""
    upstream = StubUpstream("answer").start()
    recorder = Capturing()
    proxy, thread = start(0.6, enforce=True, upstream_port=upstream.port,
                          recorder=recorder)
    try:
        reply = ask(proxy.port, make_query("borderline.test"))
        assert rcode_of(reply) == 0
        assert ancount_of(reply) == 1
        assert upstream.received, "a FLAG was treated as a block"

        payload = recorder.wait_for(1)[0]
        assert payload["verdict"] == "FLAG"
        assert payload["enforcement"]["action"] == "forward"
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_the_sinkhole_mode_works_end_to_end():
    upstream = StubUpstream("answer").start()
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port,
                          block_response="sinkhole",
                          block_sinkhole_ipv4="192.0.2.99")
    try:
        reply = ask(proxy.port, make_query("evil.test", qtype=1))
        assert rcode_of(reply) == 0
        assert ancount_of(reply) == 1
        assert reply.endswith(bytes([192, 0, 2, 99]))
        assert upstream.received == []
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


# -- end to end: enforcement disabled -------------------------------------

def test_a_block_decision_is_recorded_but_not_applied():
    """Requirement 11: calculate BLOCK, return the upstream answer, mark it."""
    upstream = StubUpstream("answer").start()
    recorder = Capturing()
    proxy, thread = start(1.0, enforce=False, upstream_port=upstream.port,
                          recorder=recorder)
    try:
        reply = ask(proxy.port, make_query("evil.test", txid=0x0D0D))
        assert rcode_of(reply) == 0, "the query was blocked with enforcement off"
        assert ancount_of(reply) == 1
        assert upstream.received, "the observed query never reached upstream"

        payload = recorder.wait_for(1)[0]
        assert payload["verdict"] == "BLOCK", \
            "the policy decision was not recorded as BLOCK"
        assert payload["rcode"] == "NOERROR"
        assert payload["enforcement"]["would_block"] is True
        assert payload["enforcement"]["applied"] is False
        assert payload["enforcement"]["action"] == "forward"
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


# -- fault isolation and other paths --------------------------------------

def test_a_module_failure_fails_open_by_default():
    """A broken heuristic must not take DNS service down."""
    class Exploding(DetectionModule):
        name = "exploding"

        def evaluate(self, c):
            raise RuntimeError("broken")

    upstream = StubUpstream("answer").start()
    settings = Settings(listen_host="127.0.0.1", listen_port=0,
                        upstream_host="127.0.0.1", upstream_port=upstream.port,
                        aggregator_enforce=True, workers=4)
    from engine.aggregator import RiskAggregator
    engine = DecisionEngine([Exploding()],
                            aggregator=RiskAggregator.from_settings(settings))
    proxy = DNSProxy(settings, engine=engine)
    thread = threading.Thread(target=proxy.start, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            _ = proxy.port
            break
        except RuntimeError:
            time.sleep(0.01)

    try:
        reply = ask(proxy.port, make_query("unknown.test"))
        assert rcode_of(reply) == 0, "a broken module blocked a query"
        assert ancount_of(reply) == 1
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_fail_closed_blocks_the_unassessable_when_enforcing():
    class Exploding(DetectionModule):
        name = "exploding"

        def evaluate(self, c):
            raise RuntimeError("broken")

    upstream = StubUpstream("answer").start()
    settings = Settings(listen_host="127.0.0.1", listen_port=0,
                        upstream_host="127.0.0.1", upstream_port=upstream.port,
                        aggregator_enforce=True, aggregator_fail_mode="closed",
                        workers=4)
    from engine.aggregator import RiskAggregator
    engine = DecisionEngine([Exploding()],
                            aggregator=RiskAggregator.from_settings(settings))
    proxy = DNSProxy(settings, engine=engine)
    thread = threading.Thread(target=proxy.start, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            _ = proxy.port
            break
        except RuntimeError:
            time.sleep(0.01)

    try:
        reply = ask(proxy.port, make_query("unassessable.test"))
        assert rcode_of(reply) == 3, "fail-closed did not block"
        assert upstream.received == []
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_malformed_queries_are_still_formerr_when_enforcing():
    """Enforcement must not change the packet-layer behaviour."""
    upstream = StubUpstream("answer").start()
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port)
    try:
        bad = struct.pack("!HHHHHH", 0x0999, 0x0100, 1, 0, 0, 0) + b"\x07example"
        reply = ask(proxy.port, bad)
        assert rcode_of(reply) == 1
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_an_upstream_timeout_on_an_allowed_query_is_still_servfail():
    upstream = StubUpstream("silent").start()
    proxy, thread = start(0.0, enforce=True, upstream_port=upstream.port,
                          upstream_timeout=0.4)
    try:
        reply = ask(proxy.port, make_query("slow.test"), timeout=5)
        assert rcode_of(reply) == 2
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_concurrent_blocked_queries_are_not_crossed():
    upstream = StubUpstream("answer").start()
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port,
                          workers=8)
    results = {}

    def worker(i):
        reply = ask(proxy.port, make_query(f"evil{i}.test", txid=i + 1))
        results[i] = (struct.unpack("!H", reply[:2])[0], rcode_of(reply))

    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(results) == 20
        assert all(results[i] == (i + 1, 3) for i in range(20))
        assert upstream.received == []
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


# -- measurement and persistence ------------------------------------------

def test_enforcement_latency_is_measured_separately():
    """RQ2 needs the cost of blocking separable from the cost of detecting."""
    upstream = StubUpstream("answer").start()
    recorder = Capturing()
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port,
                          recorder=recorder)
    try:
        ask(proxy.port, make_query("evil.test"))
        payload = recorder.wait_for(1)[0]

        latency = payload["latency_ms"]
        assert "enforce" in latency, "enforcement time was not measured"
        assert "upstream" not in latency, \
            "upstream time appeared on a query that was never forwarded"
        assert payload["added_latency_ms"] == pytest.approx(latency["total"],
                                                            abs=0.001)
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_the_decision_trace_survives_enforcement():
    upstream = StubUpstream("answer").start()
    recorder = Capturing()
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port,
                          recorder=recorder)
    try:
        ask(proxy.port, make_query("evil.test"))
        payload = recorder.wait_for(1)[0]

        assert payload["evidence"][0]["module"] == "ti"
        trace = payload["explanation"]
        assert trace["policy_verdict"] == "BLOCK"
        assert trace["contributions"][0]["weighted"] == 1.0
        assert trace["enforcement"]["applied"] is True
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_a_blocked_decision_is_persisted(tmp_path):
    import json

    from storage.db import Database
    from storage.writer import AsyncRecorder

    upstream = StubUpstream("answer").start()
    db_path = str(tmp_path / "block.sqlite3")
    recorder = AsyncRecorder(db_path, salt="s", flush_interval=0.05)
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port,
                          recorder=recorder)
    try:
        ask(proxy.port, make_query("evil.test"))
        assert recorder.flush(timeout=5)
    finally:
        proxy.stop()
        thread.join(timeout=3)
        recorder.close()
        upstream.stop()

    db = Database(db_path)
    try:
        row = db.recent_queries()[0]
        assert row["qname"] == "evil.test"
        assert row["verdict"] == "BLOCK"
        assert row["rcode"] == "NXDOMAIN"
        assert row["latency_upstream_ms"] is None, \
            "an upstream time was stored for a query that was never forwarded"
        trace = json.loads(row["explanation_json"])
        assert trace["enforcement"]["applied"] is True
    finally:
        db.close()


def test_client_addresses_are_still_pseudonymised_when_blocking(tmp_path):
    from storage.db import Database
    from storage.writer import AsyncRecorder

    upstream = StubUpstream("answer").start()
    db_path = str(tmp_path / "priv.sqlite3")
    recorder = AsyncRecorder(db_path, salt="s", flush_interval=0.05)
    proxy, thread = start(1.0, enforce=True, upstream_port=upstream.port,
                          recorder=recorder)
    try:
        ask(proxy.port, make_query("evil.test"))
        assert recorder.flush(timeout=5)
    finally:
        proxy.stop()
        thread.join(timeout=3)
        recorder.close()
        upstream.stop()

    db = Database(db_path)
    try:
        assert db.recent_queries()[0]["client_hash"] != "127.0.0.1"
    finally:
        db.close()
