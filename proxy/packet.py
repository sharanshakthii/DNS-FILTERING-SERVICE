"""
DNS wire-format parsing and response construction.

Deliberately written against RFC 1035 with the standard library only.
The project's contribution depends on measuring the true cost of the
filtering path, so the packet layer must be ours to instrument rather
than hidden inside a third-party resolver library.

Only the pieces the proxy actually needs are implemented:
  - parse the header and the single question of a query
  - rebuild responses (NXDOMAIN / SERVFAIL) without an upstream round trip
  - validate that an upstream reply belongs to our request
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

HEADER_LEN = 12
MAX_LABEL_LEN = 63
MAX_NAME_LEN = 255

# RCODEs we emit
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
               15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


class MalformedQuery(Exception):
    """Raised when a received packet is not a query we can act on.

    The proxy catches this and answers FORMERR rather than crashing;
    a filtering resolver that dies on a bad packet is a denial-of-service
    waiting to happen.
    """


@dataclass(frozen=True)
class Question:
    qname: str          # normalised, lowercase, no trailing dot
    qtype: int
    qclass: int
    qname_wire: bytes   # original wire encoding, reused when rebuilding replies

    @property
    def qtype_name(self) -> str:
        return QTYPE_NAMES.get(self.qtype, str(self.qtype))


@dataclass(frozen=True)
class Query:
    txid: int
    flags: int
    question: Question
    raw: bytes

    @property
    def is_query(self) -> bool:
        # QR bit (bit 15) clear means this is a query.
        return (self.flags >> 15) & 1 == 0

    @property
    def recursion_desired(self) -> bool:
        return (self.flags >> 8) & 1 == 1


def _parse_qname(data: bytes, offset: int) -> tuple[str, bytes, int]:
    """Read a QNAME starting at offset.

    Returns (dotted name, wire bytes including the terminating zero,
    offset just past the name).

    Compression pointers are rejected here on purpose. They are legal in
    answer sections but have no business in the question of a query, and
    accepting them in this position is a well-known way to build parsers
    that loop forever on hostile input.
    """
    labels: list[str] = []
    start = offset
    total = 0

    while True:
        if offset >= len(data):
            raise MalformedQuery("qname truncated: ran off the end of the packet")

        length = data[offset]

        if length & 0xC0:
            raise MalformedQuery("compression pointer in question section")

        offset += 1

        if length == 0:
            break

        if length > MAX_LABEL_LEN:
            raise MalformedQuery(f"label length {length} exceeds {MAX_LABEL_LEN}")

        end = offset + length
        if end > len(data):
            raise MalformedQuery("qname truncated: label runs past the packet")

        total += length + 1
        if total > MAX_NAME_LEN:
            raise MalformedQuery(f"qname exceeds {MAX_NAME_LEN} bytes")

        label = data[offset:end]
        try:
            labels.append(label.decode("ascii").lower())
        except UnicodeDecodeError:
            # Punycode arrives as ASCII, so anything else is either binary
            # junk or an attempt to smuggle bytes through the log.
            raise MalformedQuery("non-ASCII byte in label")

        offset = end

    wire = data[start:offset]
    return ".".join(labels), wire, offset


def parse_query(data: bytes) -> Query:
    """Parse an inbound DNS query. Raises MalformedQuery on anything unusable."""
    if len(data) < HEADER_LEN:
        raise MalformedQuery(f"packet is {len(data)} bytes, need at least {HEADER_LEN}")

    txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:HEADER_LEN]
    )

    if (flags >> 15) & 1:
        raise MalformedQuery("QR bit set: this is a response, not a query")

    if qdcount != 1:
        # Multiple questions are permitted by the grammar but not by any
        # deployed resolver, and we cannot render a single verdict for two
        # names. Refusing is the honest behaviour.
        raise MalformedQuery(f"QDCOUNT is {qdcount}, only 1 is supported")

    qname, qname_wire, offset = _parse_qname(data, HEADER_LEN)

    if offset + 4 > len(data):
        raise MalformedQuery("question truncated: missing QTYPE/QCLASS")

    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])

    if not qname:
        raise MalformedQuery("empty qname (root query)")

    return Query(
        txid=txid,
        flags=flags,
        question=Question(qname=qname, qtype=qtype, qclass=qclass,
                          qname_wire=qname_wire),
        raw=data,
    )


def build_response(query: Query, rcode: int, answer_rdata: bytes | None = None,
                   ttl: int = 60) -> bytes:
    """Build a reply to `query` with the given RCODE.

    If answer_rdata is supplied (4 bytes for an A record), a single answer
    record is included — this is the sinkhole path. Otherwise the answer
    section is empty, which is what NXDOMAIN and SERVFAIL want.
    """
    # QR=1, copy OPCODE and RD from the query, RA=1, then the rcode.
    opcode = (query.flags >> 11) & 0xF
    rd = (query.flags >> 8) & 1
    flags = (1 << 15) | (opcode << 11) | (rd << 8) | (1 << 7) | (rcode & 0xF)

    include_answer = answer_rdata is not None and rcode == RCODE_NOERROR
    ancount = 1 if include_answer else 0

    header = struct.pack("!HHHHHH", query.txid, flags, 1, ancount, 0, 0)
    question = query.question.qname_wire + struct.pack(
        "!HH", query.question.qtype, query.question.qclass
    )

    if not include_answer:
        return header + question

    # Name compression pointer back to the question's name at offset 12.
    answer = struct.pack(
        "!HHHIH",
        0xC00C,
        query.question.qtype,
        query.question.qclass,
        ttl,
        len(answer_rdata),
    ) + answer_rdata

    return header + question + answer


def build_formerr(txid: int) -> bytes:
    """Minimal FORMERR for a packet too broken to parse a question out of."""
    flags = (1 << 15) | RCODE_FORMERR
    return struct.pack("!HHHHHH", txid, flags, 0, 0, 0, 0)


def response_matches(request: Query, response: bytes) -> bool:
    """Check that an upstream response actually answers our request.

    Guards against off-path spoofing: an attacker who can inject a UDP
    packet but cannot see our query has to guess both the transaction ID
    and the exact question. This is not a complete defence — an on-path
    attacker still wins — and the report must say so.
    """
    if len(response) < HEADER_LEN:
        return False

    txid, flags, qdcount = struct.unpack("!HHH", response[:6])

    if txid != request.txid:
        return False
    if not (flags >> 15) & 1:      # must have QR set
        return False
    if qdcount != 1:
        return False

    try:
        qname, _wire, offset = _parse_qname(response, HEADER_LEN)
    except MalformedQuery:
        return False

    if qname != request.question.qname:
        return False

    if offset + 4 > len(response):
        return False

    qtype, qclass = struct.unpack("!HH", response[offset:offset + 4])
    return qtype == request.question.qtype and qclass == request.question.qclass


def rebuild_with_txid(response: bytes, txid: int) -> bytes:
    """Replace the transaction ID of a response.

    The proxy uses a fresh random TXID upstream so that a client's
    predictable IDs are not passed through; the reply must be stamped back
    with the client's original ID before it is returned.
    """
    if len(response) < 2:
        raise MalformedQuery("response too short to restamp")
    return struct.pack("!H", txid) + response[2:]


# -- UDP size limits (RFC 1035 4.2.1, RFC 6891 6.2.3) -------------------------

#: The largest UDP reply a client that sent no EDNS OPT record will accept.
CLASSIC_UDP_LIMIT = 512
TYPE_OPT = 41
FLAG_TC = 0x0200


def client_udp_limit(query: Query) -> int:
    """The UDP payload size the client advertised, or 512 if none.

    Read from the OPT pseudo-record in the query's additional section. Any
    parsing doubt falls back to 512, the one size every client accepts.
    """
    raw = query.raw
    try:
        _txid, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", raw[:HEADER_LEN])
    except struct.error:
        return CLASSIC_UDP_LIMIT
    if qd != 1 or an or ns or not ar:
        return CLASSIC_UDP_LIMIT
    offset = HEADER_LEN + len(query.question.qname_wire) + 4
    for _ in range(ar):
        # An OPT record's owner name is the root: a single zero byte.
        if offset + 11 > len(raw) or raw[offset] != 0:
            return CLASSIC_UDP_LIMIT
        rtype, rclass, _ttl, rdlen = struct.unpack(
            "!HHIH", raw[offset + 1:offset + 11])
        if rtype == TYPE_OPT:
            return max(CLASSIC_UDP_LIMIT, min(rclass, 65535))
        offset += 11 + rdlen
    return CLASSIC_UDP_LIMIT


def truncated_reply(query: Query, response: bytes) -> bytes:
    """Header and question only, TC set: "ask me again over TCP".

    Keeps the response's flags and rcode, drops every record, and restores
    the client's question. A client receiving this retries over TCP.
    """
    flags = struct.unpack("!H", response[2:4])[0] if len(response) >= 4 else 0x8180
    header = struct.pack("!HHHHHH", query.txid, flags | FLAG_TC, 1, 0, 0, 0)
    return header + query.question.qname_wire + struct.pack(
        "!HH", query.question.qtype, query.question.qclass)
