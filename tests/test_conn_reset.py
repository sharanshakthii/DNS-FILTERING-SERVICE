"""Regression tests for Windows UDP connection resets.

On Windows, an ICMP port-unreachable provoked by a datagram we already sent
is reported as WSAECONNRESET (ConnectionResetError) on the *next* recvfrom.
It describes the fate of an earlier reply, not a fault on this socket, so
neither receive loop may treat it as fatal.

These tests inject the error directly rather than relying on the platform,
so they fail on Linux and macOS too if the handling regresses.
"""

import socket
import struct
import threading
import time
from unittest.mock import patch

import pytest

from config.settings import Settings
from proxy.dns_proxy import DNSProxy
from proxy.packet import parse_query
from proxy.upstream import UpstreamResolver, UpstreamTimeout
from tests.test_packet import make_query


class ResettingSocket:
    """Stands in for the listening socket, scripted to raise then recover."""

    def __init__(self, script):
        self._script = list(script)
        self.sent = []

    def recvfrom(self, _bufsize):
        if not self._script:
            raise socket.timeout()
        item = self._script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def sendto(self, payload, addr):
        self.sent.append((payload, addr))

    def getsockname(self):
        return ("127.0.0.1", 5353)

    def close(self):
        pass


def test_receive_loop_survives_connection_reset():
    """A reset must not end the loop; queries after it must still be served."""
    proxy = DNSProxy(Settings(listen_host="127.0.0.1", listen_port=0, workers=2))

    good = (make_query("after-reset.test"), ("127.0.0.1", 40000))
    proxy._sock = ResettingSocket([
        ConnectionResetError(10054, "forcibly closed by the remote host"),
        ConnectionResetError(10054, "forcibly closed by the remote host"),
        good,
    ])

    handled = []
    proxy._handle_safely = lambda data, addr: handled.append((data, addr))

    thread = threading.Thread(target=proxy._serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    proxy.stop()
    thread.join(timeout=3)

    assert not thread.is_alive(), "receive loop did not exit cleanly"
    assert proxy._conn_resets == 2, "resets were not counted"
    assert handled == [good], "the query after the resets was never served"


def test_receive_loop_still_propagates_real_socket_errors():
    """The fix must not swallow genuine failures.

    ConnectionResetError is survivable; a closed or broken socket is not, and
    silently looping on it would spin the CPU forever.
    """
    proxy = DNSProxy(Settings(listen_host="127.0.0.1", listen_port=0, workers=2))
    proxy._sock = ResettingSocket([OSError(9, "Bad file descriptor")])

    with pytest.raises(OSError):
        proxy._serve_forever()


class FakeUpstreamSocket:
    """Raises a reset once, then answers correctly."""

    def __init__(self, *_args, **_kwargs):
        self.sent = None
        self._raised = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def settimeout(self, _t):
        pass

    def ioctl(self, *_a):
        pass

    def sendto(self, payload, _addr):
        self.sent = payload

    def recvfrom(self, _bufsize):
        if not self._raised:
            self._raised = True
            raise ConnectionResetError(10054, "forcibly closed by the remote host")

        q = parse_query(self.sent)
        header = struct.pack("!HHHHHH", q.txid, 0x8180, 1, 1, 0, 0)
        question = q.question.qname_wire + struct.pack(
            "!HH", q.question.qtype, q.question.qclass)
        answer = struct.pack("!HHHIH", 0xC00C, q.question.qtype,
                             q.question.qclass, 60, 4) + b"\x7f\x00\x00\x01"
        return header + question + answer, ("127.0.0.1", 53)


def test_upstream_keeps_waiting_after_a_connection_reset():
    """A reset must not abort a lookup whose real answer is still in flight."""
    query = parse_query(make_query("resilient.test", txid=0x0BAD))
    resolver = UpstreamResolver("127.0.0.1", 53, timeout=1.0)

    with patch("proxy.upstream.socket.socket", FakeUpstreamSocket):
        response, elapsed_ms = resolver.forward(query)

    assert struct.unpack("!H", response[:2])[0] == 0x0BAD, \
        "client transaction ID was not restored"
    assert struct.unpack("!H", response[6:8])[0] == 1, "answer section lost"
    assert elapsed_ms >= 0


class AlwaysResettingSocket(FakeUpstreamSocket):
    def recvfrom(self, _bufsize):
        raise ConnectionResetError(10054, "forcibly closed by the remote host")


def test_unreachable_upstream_still_times_out():
    """Continuous resets must end in a timeout, not an infinite loop.

    This is what makes SERVFAIL still reachable when the upstream really is
    gone, which is the behaviour test_upstream_timeout_returns_servfail
    depends on.
    """
    query = parse_query(make_query("gone.test"))
    resolver = UpstreamResolver("127.0.0.1", 53, timeout=0.3)

    start = time.perf_counter()
    with patch("proxy.upstream.socket.socket", AlwaysResettingSocket):
        with pytest.raises(UpstreamTimeout):
            resolver.forward(query)
    elapsed = time.perf_counter() - start

    assert 0.25 <= elapsed < 3.0, f"timeout not honoured, took {elapsed:.2f}s"


def test_suppress_helper_is_a_noop_on_posix():
    """The ioctl is Windows-only and must not break other platforms."""
    from proxy.upstream import suppress_udp_conn_reset
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        suppress_udp_conn_reset(sock)   # must not raise on any platform
