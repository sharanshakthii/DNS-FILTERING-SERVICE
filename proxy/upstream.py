"""
Upstream forwarding.

One UDP socket per in-flight query. That is not how a production resolver
would do it, but it keeps the latency attribution honest: the measured
upstream time is exactly this query's round trip, with no queueing effects
from a shared socket muddying the numbers.
"""

from __future__ import annotations

import logging
import secrets
import socket
import struct
import time

from .packet import Query, response_matches, rebuild_with_txid

log = logging.getLogger("proxy.upstream")


def suppress_udp_conn_reset(sock: socket.socket) -> None:
    """Stop Windows reporting ICMP port-unreachable as a socket reset.

    SIO_UDP_CONNRESET is a Windows-only ioctl; setting it to False tells
    Winsock not to raise WSAECONNRESET on a UDP socket when an earlier
    datagram provokes an ICMP unreachable. The attribute does not exist on
    Linux or macOS, where the behaviour is already correct, so this is a
    no-op there.

    Best effort by design: both receive loops also handle ConnectionResetError
    directly, so the proxy survives even where this ioctl is unavailable.
    """
    if not hasattr(socket, "SIO_UDP_CONNRESET"):
        return
    try:
        sock.ioctl(socket.SIO_UDP_CONNRESET, False)  # type: ignore[attr-defined]
    except OSError as exc:
        log.debug("SIO_UDP_CONNRESET unavailable: %s", exc)


class UpstreamError(Exception):
    """Upstream did not give us a usable answer.

    Carries `elapsed_ms` so the caller can attribute the time to upstream
    rather than to the filtering path. Without it, a two-second timeout is
    silently charged to our own latency measurement.
    """

    def __init__(self, message: str, elapsed_ms: float = 0.0) -> None:
        super().__init__(message)
        self.elapsed_ms = elapsed_ms


class UpstreamTimeout(UpstreamError):
    pass


class UpstreamResolver:
    def __init__(self, host: str, port: int = 53, timeout: float = 2.0,
                 max_spoof_rejects: int = 3) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_spoof_rejects = max_spoof_rejects

    def forward(self, query: Query) -> tuple[bytes, float]:
        """Forward `query` upstream and return (response bytes, elapsed ms).

        The outbound query carries a freshly generated transaction ID, and
        the reply is restamped with the client's ID before it is returned.
        Replies that do not match the outstanding question are dropped and
        we keep waiting until the deadline, rather than treating the first
        packet that arrives as authoritative.
        """
        upstream_txid = secrets.randbits(16)
        outbound = struct.pack("!H", upstream_txid) + query.raw[2:]
        upstream_request = Query(
            txid=upstream_txid,
            flags=query.flags,
            question=query.question,
            raw=outbound,
        )

        start = time.perf_counter()
        rejects = 0

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            suppress_udp_conn_reset(sock)
            sock.settimeout(self.timeout)
            try:
                sock.sendto(outbound, (self.host, self.port))
            except OSError as exc:
                raise UpstreamError(f"send failed: {exc}",
                                    (time.perf_counter() - start) * 1000.0) from exc

            deadline = start + self.timeout

            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    raise UpstreamTimeout(
                        f"no valid reply from {self.host}:{self.port} "
                        f"within {self.timeout}s",
                        (time.perf_counter() - start) * 1000.0)
                sock.settimeout(remaining)

                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout as exc:
                    raise UpstreamTimeout(
                        f"no reply from {self.host}:{self.port} "
                        f"within {self.timeout}s",
                        (time.perf_counter() - start) * 1000.0) from exc
                except ConnectionResetError:
                    # Windows reports an ICMP unreachable for a datagram we
                    # already sent. It says nothing about whether a valid reply
                    # is still in flight, and aborting here would let anyone
                    # able to provoke an ICMP cut short a legitimate lookup.
                    # Keep waiting; a genuinely dead upstream still ends in
                    # UpstreamTimeout and therefore SERVFAIL.
                    log.debug("connection reset while awaiting %s; still waiting",
                              query.question.qname)
                    continue
                except OSError as exc:
                    raise UpstreamError(f"receive failed: {exc}",
                                        (time.perf_counter() - start) * 1000.0) from exc

                if addr[0] != self.host:
                    rejects += 1
                    log.warning("reply from unexpected source %s (expected %s)",
                                addr[0], self.host)
                elif response_matches(upstream_request, data):
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    return rebuild_with_txid(data, query.txid), elapsed_ms
                else:
                    rejects += 1
                    log.warning("dropped non-matching reply for %s",
                                query.question.qname)

                if rejects >= self.max_spoof_rejects:
                    raise UpstreamError(
                        f"{rejects} non-matching replies for "
                        f"{query.question.qname}; giving up",
                        (time.perf_counter() - start) * 1000.0)
