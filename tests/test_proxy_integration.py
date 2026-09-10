"""End-to-end tests for the proxy.

A stub upstream resolver runs on loopback so the whole path can be exercised
without touching the internet. That matters twice over: the tests are
deterministic, and they still pass on review day if the venue's network is
hostile.
"""

import json
import logging
import socket
import struct
import threading
import time

import pytest

from config.settings import Settings
from proxy.dns_proxy import DNSProxy, JsonFormatter
from proxy.packet import HEADER_LEN, parse_query
from tests.test_packet import encode_name, make_query


class StubUpstream:
    """Minimal authoritative-ish server for tests.

    mode:
      "answer"  — reply correctly with 127.0.0.1
      "silent"  — never reply, to exercise the timeout path
      "spoof"   — reply with a wrong transaction ID, to exercise validation
    """

    def __init__(self, mode="answer"):
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.received = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            self.received.append(data)

            if self.mode == "silent":
                continue

            try:
                q = parse_query(data)
            except Exception:
                continue

            txid = q.txid ^ 0xFFFF if self.mode == "spoof" else q.txid
            header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
            question = q.question.qname_wire + struct.pack(
                "!HH", q.question.qtype, q.question.qclass)
            answer = struct.pack("!HHHIH", 0xC00C, q.question.qtype,
                                 q.question.qclass, 60, 4) + b"\x7f\x00\x00\x01"
            self.sock.sendto(header + question + answer, addr)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


def start_proxy(upstream_port, timeout=2.0):
    settings = Settings(
        listen_host="127.0.0.1",
        listen_port=0,               # ephemeral
        upstream_host="127.0.0.1",
        upstream_port=upstream_port,
        upstream_timeout=timeout,
        workers=4,
    )
    proxy = DNSProxy(settings)
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


def ask(port, payload, timeout=3.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, ("127.0.0.1", port))
        return sock.recvfrom(4096)[0]


@pytest.fixture
def stack(request):
    mode = getattr(request, "param", "answer")
    upstream = StubUpstream(mode).start()
    proxy, thread = start_proxy(upstream.port,
                                timeout=0.4 if mode == "silent" else 2.0)
    yield proxy, upstream
    proxy.stop()
    thread.join(timeout=3)
    upstream.stop()


# -- the happy path -------------------------------------------------------

def test_resolves_a_query_end_to_end(stack):
    proxy, upstream = stack
    reply = ask(proxy.port, make_query("example.com", txid=0x1234))

    txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", reply[:HEADER_LEN])
    assert txid == 0x1234, "client's transaction ID must be restored"
    assert (flags >> 15) & 1 == 1
    assert flags & 0xF == 0
    assert qd == 1 and an == 1
    assert reply.endswith(b"\x7f\x00\x00\x01")


def test_upstream_sees_a_different_txid(stack):
    """The client's ID must not be forwarded verbatim.

    Passing a predictable client ID upstream would hand an off-path attacker
    half of what they need to spoof the reply.
    """
    proxy, upstream = stack
    ask(proxy.port, make_query("example.com", txid=0x1234))
    assert upstream.received, "upstream received nothing"
    forwarded_txid = struct.unpack("!H", upstream.received[0][:2])[0]
    assert forwarded_txid != 0x1234


def test_question_survives_the_round_trip(stack):
    proxy, _ = stack
    reply = ask(proxy.port, make_query("deep.sub.example.com"))
    assert encode_name("deep.sub.example.com") in reply


def test_handles_concurrent_queries(stack):
    proxy, _ = stack
    results = {}

    def worker(i):
        reply = ask(proxy.port, make_query(f"host{i}.test", txid=i + 1))
        results[i] = struct.unpack("!H", reply[:2])[0]

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(results) == 20
    assert all(results[i] == i + 1 for i in range(20)), \
        "replies were delivered to the wrong clients"


# -- failure paths --------------------------------------------------------

@pytest.mark.parametrize("stack", ["silent"], indirect=True)
def test_upstream_timeout_returns_servfail(stack):
    proxy, _ = stack
    reply = ask(proxy.port, make_query("slow.test", txid=0x0777))
    txid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", reply[:HEADER_LEN])
    assert txid == 0x0777
    assert flags & 0xF == 2, "expected SERVFAIL"
    assert an == 0


@pytest.mark.parametrize("stack", ["spoof"], indirect=True)
def test_mismatched_upstream_reply_is_not_passed_through(stack):
    """A reply with the wrong transaction ID must never reach the client."""
    proxy, _ = stack
    reply = ask(proxy.port, make_query("spoofed.test", txid=0x0555))
    txid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", reply[:HEADER_LEN])
    assert txid == 0x0555
    assert flags & 0xF == 2, "expected SERVFAIL, not the forged answer"
    assert an == 0


def test_malformed_query_gets_formerr_not_a_crash(stack):
    proxy, _ = stack
    bad = struct.pack("!HHHHHH", 0x0999, 0x0100, 1, 0, 0, 0) + b"\x07example"
    reply = ask(proxy.port, bad)
    txid, flags, _qd, _an, _ns, _ar = struct.unpack("!HHHHHH", reply[:HEADER_LEN])
    assert txid == 0x0999
    assert flags & 0xF == 1, "expected FORMERR"


def test_proxy_survives_a_flood_of_junk(stack):
    """Garbage must not take the resolver down; a good query still works after."""
    import random
    proxy, _ = stack
    rng = random.Random(7)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(200):
            length = rng.randint(0, 60)
            sock.sendto(bytes(rng.randrange(256) for _ in range(length)),
                        ("127.0.0.1", proxy.port))

    time.sleep(0.3)
    reply = ask(proxy.port, make_query("survivor.test", txid=0x0321))
    assert struct.unpack("!H", reply[:2])[0] == 0x0321


def test_two_byte_packet_gets_no_amplification(stack):
    """Too short to hold a question, so a FORMERR echo is all we may send.

    Never reply with more than we received to a packet we cannot validate.
    """
    proxy, _ = stack
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        sock.sendto(b"\x01\x02", ("127.0.0.1", proxy.port))
        try:
            reply = sock.recvfrom(4096)[0]
        except socket.timeout:
            return  # silence is also acceptable
    assert len(reply) <= HEADER_LEN


# -- logging --------------------------------------------------------------

def test_log_record_is_valid_json_with_latency_breakdown(stack, caplog):
    proxy, _ = stack
    formatter = JsonFormatter()

    with caplog.at_level(logging.INFO, logger="proxy"):
        ask(proxy.port, make_query("logged.test"))
        time.sleep(0.1)
        records = [r for r in caplog.records if getattr(r, "decision", None)]

    assert records, "no query record was logged"
    payload = json.loads(formatter.format(records[-1]))

    assert payload["event"] == "query"
    assert payload["qname"] == "logged.test"
    assert payload["qtype"] == "A"
    assert payload["verdict"] == "ALLOW"
    assert payload["rcode"] == "NOERROR"
    assert "upstream" in payload["latency_ms"]
    assert "parse" in payload["latency_ms"]
    assert payload["latency_ms"]["total"] > 0
    assert payload["added_latency_ms"] >= 0, \
        "added latency is total minus upstream and cannot be negative"
