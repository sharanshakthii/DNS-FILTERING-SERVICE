"""
Block responses.

How a filtering resolver expresses "no" is a real design decision, not a
detail, and the options behave differently in ways a reviewer can ask about.

**NXDOMAIN (default).** The cleanest failure: the client gives up immediately
without needing to reach any other server. It is the action RPZ expresses as
`CNAME .`, and it is what most filtering resolvers use by default.

  The caveat, and it is a genuine one: RFC 8020 states that NXDOMAIN means the
  queried name *and every name beneath it* do not exist, and that a caching
  resolver SHOULD treat the whole subtree as unreachable. So blocking
  `bad.example.com` with NXDOMAIN can suppress `good.bad.example.com` in a
  downstream cache. For a filtering resolver that is usually the intent, but
  it is over-blocking by any strict reading and it is documented rather than
  ignored.

**Sinkhole.** Answers with a non-routable address — 0.0.0.0 or ::. Keeps the
name resolvable, which suits a walled-garden or block-page deployment. Its
known failure mode is that a client may try to connect to itself, so a local
service on the same host can be reached instead of nothing.

**REFUSED.** States that this resolver declines to answer, without asserting
anything about whether the name exists. Honest, but many stub resolvers treat
it as a server fault and fail over to another resolver, which defeats the
block entirely.

Only A and AAAA can be sinkholed, because there is no meaningful synthetic
answer for MX or TXT. Anything else falls back to NXDOMAIN, and the response
records which representation was actually used so the log never claims a
sinkhole that was not sent.

None of this makes the block hard to bypass. A client that speaks DoH to a
third party never reaches this resolver at all. See the README limitations.
"""

from __future__ import annotations

import ipaddress
import logging

from .packet import (
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_REFUSED,
    Query,
    build_response,
)

log = logging.getLogger("proxy.enforce")

BLOCK_NXDOMAIN = "nxdomain"
BLOCK_SINKHOLE = "sinkhole"
BLOCK_REFUSED = "refused"

VALID_RESPONSES = {BLOCK_NXDOMAIN, BLOCK_SINKHOLE, BLOCK_REFUSED}

QTYPE_A = 1
QTYPE_AAAA = 28


class BlockResponder:
    """Builds the DNS response used when a query is blocked."""

    def __init__(self, mode: str = BLOCK_NXDOMAIN, sinkhole_ipv4: str = "0.0.0.0",
                 sinkhole_ipv6: str = "::", ttl: int = 60) -> None:
        mode = (mode or BLOCK_NXDOMAIN).lower()
        if mode not in VALID_RESPONSES:
            raise ValueError(
                f"unknown block response {mode!r}; expected one of "
                f"{sorted(VALID_RESPONSES)}")
        if ttl < 0:
            raise ValueError(f"block_ttl must not be negative, got {ttl}")

        self.mode = mode
        self.ttl = ttl

        # Parsed once at startup so a malformed address fails loudly here
        # rather than silently producing a wrong answer per query.
        try:
            self._v4 = ipaddress.IPv4Address(sinkhole_ipv4).packed
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"invalid sinkhole IPv4 {sinkhole_ipv4!r}") from exc
        try:
            self._v6 = ipaddress.IPv6Address(sinkhole_ipv6).packed
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"invalid sinkhole IPv6 {sinkhole_ipv6!r}") from exc

        self.sinkhole_ipv4 = sinkhole_ipv4
        self.sinkhole_ipv6 = sinkhole_ipv6

    @classmethod
    def from_settings(cls, settings) -> "BlockResponder":
        return cls(mode=settings.block_response,
                   sinkhole_ipv4=settings.block_sinkhole_ipv4,
                   sinkhole_ipv6=settings.block_sinkhole_ipv6,
                   ttl=settings.block_ttl)

    def build(self, query: Query) -> tuple[bytes, str]:
        """Return (wire response, rcode name actually used).

        The second element is what gets logged and stored, so a fallback can
        never be recorded as the mode that was configured.
        """
        if self.mode == BLOCK_REFUSED:
            return build_response(query, RCODE_REFUSED), "REFUSED"

        if self.mode == BLOCK_SINKHOLE:
            qtype = query.question.qtype
            rdata = None
            if qtype == QTYPE_A:
                rdata = self._v4
            elif qtype == QTYPE_AAAA:
                rdata = self._v6

            if rdata is not None:
                return (build_response(query, RCODE_NOERROR,
                                       answer_rdata=rdata, ttl=self.ttl),
                        "NOERROR")

            # No sensible synthetic answer for this type.
            log.debug("sinkhole not applicable to %s for %s; using NXDOMAIN",
                      query.question.qtype_name, query.question.qname)
            return build_response(query, RCODE_NXDOMAIN), "NXDOMAIN"

        return build_response(query, RCODE_NXDOMAIN), "NXDOMAIN"

    def describe(self) -> dict:
        info = {"mode": self.mode, "ttl": self.ttl}
        if self.mode == BLOCK_SINKHOLE:
            info["sinkhole_ipv4"] = self.sinkhole_ipv4
            info["sinkhole_ipv6"] = self.sinkhole_ipv6
        return info

    def __repr__(self) -> str:
        return f"<BlockResponder mode={self.mode!r}>"
