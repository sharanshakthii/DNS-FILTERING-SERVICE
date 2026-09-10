"""Regression tests for the two SERVFAIL recording defects.

Both were found in live use on a threat-listed domain that had already been
taken down. They matter more than ordinary bugs because malicious domains are
disproportionately dead — Bilge et al. (NDSS 2011) found most detected
malicious domains live under two days — so both faults bias the experiments
in the same direction: they hide detections on real threats while leaving
measurements on live benign domains untouched.
"""

import struct
import threading
import time

import pytest

from config.settings import Settings
from engine.decision import DecisionEngine
from engine.modules.base import DetectionModule, ModuleScore
from proxy.dns_proxy import DNSProxy, JsonFormatter
from proxy.upstream import UpstreamError, UpstreamResolver, UpstreamTimeout
from proxy.packet import parse_query
from proxy.timing import Stopwatch
from tests.test_packet import make_query
from tests.test_proxy_integration import StubUpstream, ask


class AlwaysMatchModule(DetectionModule):
    """Scores 1.0 on everything, so evidence is guaranteed to exist."""

    name = "always"

    def evaluate(self, ctx):
        return ModuleScore(1.0, {"listed": True, "qname": ctx.qname})


def start_proxy(engine, upstream_port, recorder=None, timeout=0.4):
    settings = Settings(listen_host="127.0.0.1", listen_port=0,
                        upstream_host="127.0.0.1", upstream_port=upstream_port,
                        upstream_timeout=timeout, workers=4)
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


class CapturingRecorder:
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


# -- defect 1: evidence discarded on the SERVFAIL path --------------------

def test_evidence_survives_an_upstream_timeout():
    """Detection runs before forwarding, so its result must not be lost."""
    upstream = StubUpstream("silent").start()
    recorder = CapturingRecorder()
    engine = DecisionEngine([AlwaysMatchModule()])
    proxy, thread = start_proxy(engine, upstream.port, recorder)

    try:
        reply = ask(proxy.port, make_query("dead-but-listed.test"), timeout=5)
        assert struct.unpack("!H", reply[2:4])[0] & 0xF == 2, "expected SERVFAIL"

        payload = recorder.wait_for(1)[0]
        assert payload["verdict"] == "SERVFAIL"
        assert payload["error"] == "upstream_timeout"
        assert payload["evidence"], "the module's evidence was discarded"
        assert payload["evidence"][0]["module"] == "always"
        assert payload["evidence"][0]["score"] == 1.0

        # The aggregate is 0.0 here because risk aggregation is Stage 7 and
        # DecisionEngine reports 0.0 deliberately rather than inventing a
        # partial sum. What matters is that whatever the engine reported is
        # carried through this path rather than replaced with a default.
        expected = engine.decide(parse_query(make_query("dead-but-listed.test")),
                                 Stopwatch())["score"]
        assert payload["score"] == expected, "the decision's score was discarded"
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_evidence_survives_a_spoofed_upstream_reply():
    """The other SERVFAIL branch must behave identically."""
    upstream = StubUpstream("spoof").start()
    recorder = CapturingRecorder()
    engine = DecisionEngine([AlwaysMatchModule()])
    proxy, thread = start_proxy(engine, upstream.port, recorder)

    try:
        ask(proxy.port, make_query("spoofed-and-listed.test"), timeout=5)
        payload = recorder.wait_for(1)[0]
        assert payload["verdict"] == "SERVFAIL"
        assert payload["evidence"], "evidence lost on the UpstreamError path"
        assert payload["evidence"][0]["score"] == 1.0
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


# -- defect 2: timeout charged to the filtering path ----------------------

def test_upstream_timeout_is_not_charged_to_added_latency():
    """added_latency_ms is total minus upstream and must exclude the wait."""
    upstream = StubUpstream("silent").start()
    recorder = CapturingRecorder()
    proxy, thread = start_proxy(DecisionEngine([AlwaysMatchModule()]),
                                upstream.port, recorder, timeout=0.4)

    try:
        ask(proxy.port, make_query("slow.test"), timeout=5)
        payload = recorder.wait_for(1)[0]

        latency = payload["latency_ms"]
        assert latency["total"] >= 380, "the timeout did not actually elapse"
        assert latency.get("upstream", 0) >= 380, \
            "the timeout was not recorded as upstream time"
        assert payload["added_latency_ms"] < 100, (
            f"added latency was {payload['added_latency_ms']} ms; the upstream "
            f"wait is being charged to the filtering path")
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


def test_added_latency_is_never_negative_after_the_fix():
    upstream = StubUpstream("silent").start()
    recorder = CapturingRecorder()
    proxy, thread = start_proxy(DecisionEngine([]), upstream.port, recorder,
                                timeout=0.3)
    try:
        ask(proxy.port, make_query("neg.test"), timeout=5)
        assert recorder.wait_for(1)[0]["added_latency_ms"] >= 0
    finally:
        proxy.stop()
        thread.join(timeout=3)
        upstream.stop()


# -- the exception carries the elapsed time -------------------------------

def test_upstream_timeout_reports_how_long_it_waited():
    resolver = UpstreamResolver("127.0.0.1", 1, timeout=0.3)
    query = parse_query(make_query("nowhere.test"))

    with pytest.raises(UpstreamError) as caught:
        resolver.forward(query)

    assert caught.value.elapsed_ms >= 0, "elapsed_ms missing from the exception"


def test_upstream_error_defaults_to_zero_elapsed():
    """Callers use getattr with a default, so this must stay safe."""
    assert UpstreamError("boom").elapsed_ms == 0.0
    assert UpstreamTimeout("boom", 123.4).elapsed_ms == 123.4
