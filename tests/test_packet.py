"""Unit tests for the DNS packet layer.

Every malformed case here is one the proxy would otherwise crash on, and a
crash in the query path is a denial of service on whatever network the
resolver serves. These are acceptance criteria for Stage 2, not extras.
"""

import struct

import pytest

from proxy.packet import (
    HEADER_LEN,
    MalformedQuery,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    build_formerr,
    build_response,
    parse_query,
    rebuild_with_txid,
    response_matches,
)


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def make_query(name="example.com", txid=0x1234, qtype=1, qclass=1,
               qdcount=1, flags=0x0100) -> bytes:
    header = struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, qclass)


# -- parsing the good case ------------------------------------------------

def test_parses_a_normal_query():
    q = parse_query(make_query("example.com"))
    assert q.txid == 0x1234
    assert q.question.qname == "example.com"
    assert q.question.qtype == 1
    assert q.question.qtype_name == "A"
    assert q.is_query
    assert q.recursion_desired


def test_qname_is_lowercased():
    q = parse_query(make_query("ExAmPlE.CoM"))
    assert q.question.qname == "example.com"


def test_parses_aaaa_and_txt():
    assert parse_query(make_query("a.test", qtype=28)).question.qtype_name == "AAAA"
    assert parse_query(make_query("a.test", qtype=16)).question.qtype_name == "TXT"


def test_unknown_qtype_falls_back_to_number():
    assert parse_query(make_query("a.test", qtype=999)).question.qtype_name == "999"


def test_long_but_legal_name():
    name = ".".join(["a" * 60] * 3)
    assert parse_query(make_query(name)).question.qname == name


# -- malformed input ------------------------------------------------------

@pytest.mark.parametrize("data", [b"", b"\x00", b"\x12\x34", b"\x00" * 11])
def test_rejects_short_packets(data):
    with pytest.raises(MalformedQuery):
        parse_query(data)


def test_rejects_response_packets():
    with pytest.raises(MalformedQuery, match="QR bit"):
        parse_query(make_query(flags=0x8180))


@pytest.mark.parametrize("qdcount", [0, 2, 65535])
def test_rejects_wrong_question_count(qdcount):
    with pytest.raises(MalformedQuery, match="QDCOUNT"):
        parse_query(make_query(qdcount=qdcount))


def test_rejects_compression_pointer_in_question():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    packet = header + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    with pytest.raises(MalformedQuery, match="compression pointer"):
        parse_query(packet)


def test_rejects_unterminated_qname():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    with pytest.raises(MalformedQuery, match="truncated"):
        parse_query(header + b"\x07example")


def test_rejects_label_running_past_the_packet():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    with pytest.raises(MalformedQuery, match="truncated"):
        parse_query(header + b"\x3fabc")


def test_rejects_oversized_name():
    # 5 labels of 63 bytes = 320 bytes, over the 255 limit.
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    body = (b"\x3f" + b"a" * 63) * 5 + b"\x00" + struct.pack("!HH", 1, 1)
    with pytest.raises(MalformedQuery, match="exceeds"):
        parse_query(header + body)


def test_rejects_missing_qtype_qclass():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    with pytest.raises(MalformedQuery, match="QTYPE"):
        parse_query(header + encode_name("example.com"))


def test_rejects_root_query():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    packet = header + b"\x00" + struct.pack("!HH", 1, 1)
    with pytest.raises(MalformedQuery, match="empty qname"):
        parse_query(packet)


def test_rejects_non_ascii_label():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    packet = header + b"\x03\xff\xfe\xfd\x00" + struct.pack("!HH", 1, 1)
    with pytest.raises(MalformedQuery, match="non-ASCII"):
        parse_query(packet)


def test_random_junk_never_crashes():
    """Fuzz-ish sweep: the only acceptable outcomes are a parse or a
    MalformedQuery. Anything else means the proxy can be killed by a packet."""
    import random
    rng = random.Random(20260830)
    for _ in range(3000):
        length = rng.randint(0, 80)
        data = bytes(rng.randrange(256) for _ in range(length))
        try:
            parse_query(data)
        except MalformedQuery:
            pass


# -- response construction ------------------------------------------------

def test_nxdomain_response_shape():
    q = parse_query(make_query("blocked.test", txid=0xABCD))
    resp = build_response(q, RCODE_NXDOMAIN)
    txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", resp[:HEADER_LEN])
    assert txid == 0xABCD
    assert (flags >> 15) & 1 == 1          # QR set
    assert flags & 0xF == RCODE_NXDOMAIN
    assert qd == 1 and an == 0
    assert resp[HEADER_LEN:] == q.question.qname_wire + struct.pack("!HH", 1, 1)


def test_sinkhole_response_carries_an_answer():
    q = parse_query(make_query("sink.test"))
    resp = build_response(q, RCODE_NOERROR, answer_rdata=b"\x7f\x00\x00\x01")
    _txid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", resp[:HEADER_LEN])
    assert an == 1
    assert flags & 0xF == RCODE_NOERROR
    assert resp.endswith(b"\x7f\x00\x00\x01")


def test_answer_is_dropped_for_error_rcodes():
    q = parse_query(make_query("sink.test"))
    resp = build_response(q, RCODE_NXDOMAIN, answer_rdata=b"\x7f\x00\x00\x01")
    assert struct.unpack("!H", resp[6:8])[0] == 0


def test_formerr_is_well_formed():
    resp = build_formerr(0x4242)
    txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", resp[:HEADER_LEN])
    assert txid == 0x4242 and flags & 0xF == 1 and qd == 0 and an == 0


# -- upstream response validation -----------------------------------------

def _reply_to(query_bytes: bytes, txid=None, qname=None, qtype=1) -> bytes:
    q = parse_query(query_bytes)
    header = struct.pack("!HHHHHH", txid if txid is not None else q.txid,
                         0x8180, 1, 0, 0, 0)
    name = encode_name(qname) if qname else q.question.qname_wire
    return header + name + struct.pack("!HH", qtype, 1)


def test_matching_reply_is_accepted():
    raw = make_query("example.com", txid=0x1111)
    assert response_matches(parse_query(raw), _reply_to(raw))


def test_reply_with_wrong_txid_is_rejected():
    raw = make_query("example.com", txid=0x1111)
    assert not response_matches(parse_query(raw), _reply_to(raw, txid=0x2222))


def test_reply_for_a_different_name_is_rejected():
    raw = make_query("example.com", txid=0x1111)
    assert not response_matches(parse_query(raw), _reply_to(raw, qname="evil.test"))


def test_reply_for_a_different_qtype_is_rejected():
    raw = make_query("example.com", txid=0x1111)
    assert not response_matches(parse_query(raw), _reply_to(raw, qtype=28))


def test_truncated_or_junk_reply_is_rejected():
    raw = make_query("example.com")
    q = parse_query(raw)
    assert not response_matches(q, b"")
    assert not response_matches(q, b"\x11\x11")
    assert not response_matches(q, b"\xff" * 40)


def test_query_shaped_reply_is_rejected():
    """A reply without QR set is not an answer, whatever else it contains."""
    raw = make_query("example.com", txid=0x1111)
    q = parse_query(raw)
    header = struct.pack("!HHHHHH", 0x1111, 0x0100, 1, 0, 0, 0)
    fake = header + q.question.qname_wire + struct.pack("!HH", 1, 1)
    assert not response_matches(q, fake)


def test_rebuild_with_txid_replaces_only_the_id():
    raw = make_query("example.com", txid=0x1111)
    reply = _reply_to(raw)
    restamped = rebuild_with_txid(reply, 0x9999)
    assert struct.unpack("!H", restamped[:2])[0] == 0x9999
    assert restamped[2:] == reply[2:]
