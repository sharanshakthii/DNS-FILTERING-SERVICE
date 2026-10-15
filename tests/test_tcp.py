"""DNS over TCP: upstream fallback on truncation (RFC 7766).

The stub serves UDP and TCP on one port, as a real resolver does. Over UDP
it answers with TC set and no records; over TCP it returns the full answer.
"""

import socket
import struct
import threading
import time

import pytest

from proxy.packet import HEADER_LEN, parse_query
from proxy.upstream import (UpstreamError, UpstreamResolver, UpstreamTimeout,
                            is_truncated)
from tests.test_packet import make_query
from tests.test_proxy_integration import ask, start_proxy

RECORDS = 40       # well past what a 512-byte UDP reply can carry


def answer(q, records, txid=None, flags=0x8180):
    header = struct.pack("!HHHHHH", q.txid if txid is None else txid,
                         flags, 1, records, 0, 0)
    question = q.question.qname_wire + struct.pack(
        "!HH", q.question.qtype, q.question.qclass)
    body = b"".join(struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4)
                    + bytes([10, 0, i // 256, i % 256]) for i in range(records))
    return header + question + body


class DualStub:
    """UDP + TCP upstream on the same port.

    tcp_mode: "answer" | "wrong_txid" | "closed" (no TCP listener)
    udp_truncates: reply over UDP with TC set and no records
    """

    def __init__(self, tcp_mode="answer", udp_truncates=True):
        self.tcp_mode = tcp_mode
        self.udp_truncates = udp_truncates
        self.tcp_queries = 0
        self.udp_queries = 0
        self._stop = threading.Event()
        for _ in range(20):
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.bind(("127.0.0.1", 0))
            self.port = self.udp.getsockname()[1]
            self.tcp = None
            if tcp_mode == "closed":
                break
            try:
                self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.tcp.bind(("127.0.0.1", self.port))
                self.tcp.listen(8)
                break
            except OSError:
                self.tcp.close()
                self.udp.close()
        self.udp.settimeout(0.2)
        if self.tcp:
            self.tcp.settimeout(0.2)
        self._threads = [threading.Thread(target=self._udp_loop, daemon=True)]
        if self.tcp:
            self._threads.append(threading.Thread(target=self._tcp_loop,
                                                  daemon=True))

    def start(self):
        for t in self._threads:
            t.start()
        return self

    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(4096)
            except (socket.timeout, ConnectionResetError):
                continue
            except OSError:
                break
            self.udp_queries += 1
            q = parse_query(data)
            reply = (answer(q, 0, flags=0x8380) if self.udp_truncates
                     else answer(q, 1))
            self.udp.sendto(reply, addr)

    def _tcp_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2)
                try:
                    n = struct.unpack("!H", conn.recv(2))[0]
                    data = b""
                    while len(data) < n:
                        data += conn.recv(n - len(data))
                except (OSError, struct.error):
                    continue
                self.tcp_queries += 1
                q = parse_query(data)
                txid = q.txid ^ 0xFFFF if self.tcp_mode == "wrong_txid" else None
                reply = answer(q, RECORDS, txid=txid)
                conn.sendall(struct.pack("!H", len(reply)) + reply)

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self.udp.close()
        if self.tcp:
            self.tcp.close()


@pytest.fixture
def stub(request):
    s = DualStub(**getattr(request, "param", {})).start()
    yield s
    s.stop()


def q(name="big.example", txid=0x4242):
    return parse_query(make_query(name, txid=txid))


def ancount(message):
    return struct.unpack("!HHHHHH", message[:HEADER_LEN])[3]


# -- the resolver -----------------------------------------------------------

def test_a_truncated_udp_reply_is_completed_over_tcp(stub):
    resolver = UpstreamResolver("127.0.0.1", stub.port, timeout=2.0)
    reply, elapsed = resolver.forward(q())
    assert not is_truncated(reply)
    assert ancount(reply) == RECORDS
    assert len(reply) > 512
    assert struct.unpack("!H", reply[:2])[0] == 0x4242, "client ID restored"
    assert (stub.udp_queries, stub.tcp_queries) == (1, 1)
    assert resolver.tcp_retries == 1
    assert elapsed > 0


def test_with_fallback_off_the_truncated_reply_passes_through(stub):
    resolver = UpstreamResolver("127.0.0.1", stub.port, timeout=2.0,
                                tcp_fallback=False)
    reply, _ = resolver.forward(q())
    assert is_truncated(reply)
    assert stub.tcp_queries == 0


@pytest.mark.parametrize("stub", [{"udp_truncates": False}], indirect=True)
def test_an_ordinary_reply_never_touches_tcp(stub):
    resolver = UpstreamResolver("127.0.0.1", stub.port, timeout=2.0)
    reply, _ = resolver.forward(q())
    assert ancount(reply) == 1
    assert stub.tcp_queries == 0 and resolver.tcp_retries == 0


@pytest.mark.parametrize("stub", [{"tcp_mode": "wrong_txid"}], indirect=True)
def test_a_tcp_reply_for_another_question_is_rejected(stub):
    resolver = UpstreamResolver("127.0.0.1", stub.port, timeout=2.0)
    with pytest.raises(UpstreamError):
        resolver.forward(q())


@pytest.mark.parametrize("stub", [{"tcp_mode": "closed"}], indirect=True)
def test_an_unreachable_tcp_upstream_is_an_error_not_a_hang(stub):
    resolver = UpstreamResolver("127.0.0.1", stub.port, timeout=2.0)
    started = time.perf_counter()
    with pytest.raises(UpstreamError):
        resolver.forward(q())
    assert time.perf_counter() - started < 2.5


def test_forward_tcp_restores_the_client_transaction_id(stub):
    resolver = UpstreamResolver("127.0.0.1", stub.port, timeout=2.0)
    reply, _ = resolver.forward_tcp(q(txid=0x0001))
    assert struct.unpack("!H", reply[:2])[0] == 0x0001
    assert ancount(reply) == RECORDS


# -- through the proxy --------------------------------------------------------

def with_edns(message, size):
    """Append an EDNS OPT record advertising `size` bytes (RFC 6891)."""
    header = bytearray(message[:HEADER_LEN])
    struct.pack_into("!H", header, 10, 1)            # ARCOUNT = 1
    opt = b"\x00" + struct.pack("!HHIH", 41, size, 0, 0)
    return bytes(header) + message[HEADER_LEN:] + opt


def ask_tcp(port, *messages, timeout=4.0):
    """Send messages on one TCP connection; return the replies in order."""
    from proxy.upstream import _recv_exact
    replies = []
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        for m in messages:
            s.sendall(struct.pack("!H", len(m)) + m)
        for _ in messages:
            n = struct.unpack("!H", _recv_exact(s, 2))[0]
            replies.append(_recv_exact(s, n))
    return replies


@pytest.fixture
def proxied(stub):
    proxy, thread = start_proxy(stub.port)
    yield proxy, stub
    proxy.stop()
    thread.join(timeout=5)


def test_the_proxy_listens_on_tcp_at_the_udp_port(proxied):
    proxy, _ = proxied
    assert proxy.tcp_port == proxy.port


def test_a_classic_udp_client_is_told_to_use_tcp(proxied):
    """No EDNS means 512 bytes at most; a bigger answer must not be sent."""
    proxy, _ = proxied
    reply = ask(proxy.port, make_query("big.example", txid=0x7777))
    assert struct.unpack("!H", reply[:2])[0] == 0x7777
    assert is_truncated(reply) and ancount(reply) == 0
    assert len(reply) <= 512


def test_an_edns_udp_client_gets_the_full_answer(proxied):
    proxy, _ = proxied
    reply = ask(proxy.port, with_edns(make_query("big.example", txid=0x7878), 4096))
    assert not is_truncated(reply)
    assert ancount(reply) == RECORDS


def test_a_tcp_client_gets_the_full_answer(proxied):
    proxy, _ = proxied
    (reply,) = ask_tcp(proxy.port, make_query("big.example", txid=0x7979))
    assert struct.unpack("!H", reply[:2])[0] == 0x7979
    assert ancount(reply) == RECORDS and not is_truncated(reply)


def test_several_queries_share_one_connection(proxied):
    proxy, _ = proxied
    replies = ask_tcp(proxy.port, make_query("a.example", txid=1),
                      make_query("b.example", txid=2),
                      make_query("c.example", txid=3))
    assert [struct.unpack("!H", r[:2])[0] for r in replies] == [1, 2, 3]


def test_garbage_over_tcp_gets_formerr_and_the_proxy_survives(proxied):
    proxy, _ = proxied
    (reply,) = ask_tcp(proxy.port, b"\x12\x34" + b"\xff" * 5)
    assert struct.unpack("!H", reply[:2])[0] == 0x1234
    assert struct.unpack("!H", reply[2:4])[0] & 0x000F == 1      # FORMERR
    (ok,) = ask_tcp(proxy.port, make_query("big.example", txid=5))
    assert ancount(ok) == RECORDS


def test_an_idle_connection_is_closed(stub):
    from tests.test_proxy_integration import Settings, DNSProxy
    settings = Settings(listen_host="127.0.0.1", listen_port=0,
                        upstream_host="127.0.0.1", upstream_port=stub.port,
                        workers=2, tcp_idle_timeout=0.3, db_enabled=False)
    proxy = DNSProxy(settings)
    thread = threading.Thread(target=proxy.start, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 5
        while proxy.tcp_port is None and time.time() < deadline:
            time.sleep(0.01)
        with socket.create_connection(("127.0.0.1", proxy.tcp_port),
                                      timeout=3) as s:
            started = time.perf_counter()
            assert s.recv(1) == b"", "server closes an idle connection"
            assert time.perf_counter() - started < 2.5
    finally:
        proxy.stop()
        thread.join(timeout=5)


def test_tcp_can_be_switched_off(stub):
    from tests.test_proxy_integration import Settings, DNSProxy
    settings = Settings(listen_host="127.0.0.1", listen_port=0,
                        upstream_host="127.0.0.1", upstream_port=stub.port,
                        workers=2, tcp_enabled=False, db_enabled=False)
    proxy = DNSProxy(settings)
    thread = threading.Thread(target=proxy.start, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                proxy.port
                break
            except RuntimeError:
                time.sleep(0.01)
        assert proxy.tcp_port is None
    finally:
        proxy.stop()
        thread.join(timeout=5)


def start_custom(stub, **overrides):
    from tests.test_proxy_integration import Settings, DNSProxy
    engine = overrides.pop("engine", None)
    recorder = overrides.pop("recorder", None)
    settings = Settings(listen_host="127.0.0.1", listen_port=0,
                        upstream_host="127.0.0.1", upstream_port=stub.port,
                        workers=2, db_enabled=False, **overrides)
    proxy = DNSProxy(settings, engine=engine, recorder=recorder)
    thread = threading.Thread(target=proxy.start, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while proxy.tcp_port is None and time.time() < deadline:
        time.sleep(0.01)
    return proxy, thread


def test_an_enforced_block_over_tcp_never_reaches_upstream(stub):
    from engine.aggregator import RiskAggregator
    from engine.decision import DecisionEngine
    from engine.modules.null import FixedScoreModule

    records = []

    class Recorder:
        def record(self, payload):
            records.append(payload)

    engine = DecisionEngine([FixedScoreModule("ti", 1.0)],
                            aggregator=RiskAggregator(enforce=True))
    proxy, thread = start_custom(stub, engine=engine, recorder=Recorder())
    try:
        (reply,) = ask_tcp(proxy.tcp_port, make_query("blocked.example", txid=9))
    finally:
        proxy.stop()
        thread.join(timeout=5)
    assert struct.unpack("!H", reply[2:4])[0] & 0x000F == 3       # NXDOMAIN
    assert stub.udp_queries == 0 and stub.tcp_queries == 0
    assert records and records[-1]["transport"] == "tcp"
    assert records[-1]["verdict"] == "BLOCK"


def test_connections_past_the_limit_are_refused(stub):
    proxy, thread = start_custom(stub, tcp_max_connections=1)
    try:
        held = socket.create_connection(("127.0.0.1", proxy.tcp_port), timeout=3)
        time.sleep(0.2)                       # let the server register it
        with socket.create_connection(("127.0.0.1", proxy.tcp_port),
                                      timeout=3) as extra:
            try:
                assert extra.recv(1) == b""
            except ConnectionResetError:
                pass                          # also a refusal
        assert proxy.tcp_rejected == 1
        held.close()
    finally:
        proxy.stop()
        thread.join(timeout=5)
