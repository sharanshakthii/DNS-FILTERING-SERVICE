"""
UDP receive-path diagnostic.

Read-only with respect to the project: this imports nothing from `proxy`,
`storage`, or `config`, changes no production behaviour, and writes no
files. It exists to answer one question with evidence — does a UDP datagram
sent to 127.0.0.1 actually reach a Python socket on this machine?

Subcommands, in the order they should be run:

  selftest   One Python socket sends a datagram to another Python socket on
             loopback. If this fails, nothing else can work, and the fault
             is in the OS or a security product, not in this project.

  listen     A bare-bones UDP listener using only `socket`. None of the
             project's code is involved. If nslookup can reach this but not
             the proxy, the fault is in the proxy. If it can reach neither,
             the fault is outside the project.

  query      Sends a correctly formed DNS query from Python and prints the
             reply. Removes nslookup from the picture entirely.

Usage:
    python tools/diag_udp.py selftest
    python tools/diag_udp.py listen --port 5399
    python tools/diag_udp.py query --port 5399 --name example.com
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}


def build_query(name: str, txid: int = 0x4242) -> bytes:
    """A standard recursive A query. Byte-for-byte what any resolver sends."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii")
                     for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def describe(data: bytes) -> str:
    if len(data) < 12:
        return f"{len(data)} bytes (too short to be a DNS message)"
    txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    kind = "response" if (flags >> 15) & 1 else "query"
    rcode = RCODES.get(flags & 0xF, str(flags & 0xF))
    return (f"{len(data)} bytes | {kind} | txid=0x{txid:04X} | "
            f"rcode={rcode} | questions={qd} answers={an}")


def cmd_selftest(args) -> int:
    print("SELFTEST — can one Python socket reach another over loopback?\n")

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(3.0)
    port = receiver.getsockname()[1]
    print(f"  receiver bound to 127.0.0.1:{port}")

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe = b"PRJ112-DIAGNOSTIC-PROBE"

    try:
        sender.sendto(probe, ("127.0.0.1", port))
        print(f"  sent {len(probe)} bytes")
        data, addr = receiver.recvfrom(4096)
        print(f"  received {len(data)} bytes from {addr[0]}:{addr[1]}")
        if data == probe:
            print("\nRESULT: PASS — loopback UDP works for Python on this machine.")
            return 0
        print("\nRESULT: FAIL — data arrived but was altered.")
        return 1
    except socket.timeout:
        print("\nRESULT: FAIL — the datagram never arrived.")
        print("Loopback UDP is being blocked for Python on this machine.")
        print("A security product with network filtering is the usual cause.")
        return 1
    finally:
        sender.close()
        receiver.close()


def cmd_listen(args) -> int:
    print(f"LISTEN — bare socket on 127.0.0.1:{args.port}, no project code.\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Deliberately NOT setting SO_REUSEADDR: if the port is taken, this
    # should fail loudly rather than share the port ambiguously.
    try:
        sock.bind(("127.0.0.1", args.port))
    except OSError as exc:
        print(f"  BIND FAILED: {exc}")
        print("  Something else holds this port. Stop the proxy first, or")
        print("  choose a different port.")
        return 1

    sock.settimeout(1.0)
    print(f"  bound. waiting {args.seconds}s for any datagram...")
    print("  (send one now from the other terminal)\n")

    deadline = time.time() + args.seconds
    count = 0
    try:
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            count += 1
            print(f"  [{count}] from {addr[0]}:{addr[1]} -> {describe(data)}")
            print(f"       raw: {data[:48].hex()}")
    finally:
        sock.close()

    print()
    if count:
        print(f"RESULT: PASS — {count} datagram(s) reached a plain Python socket.")
        print("The network path is fine. Suspicion moves to the proxy.")
        return 0
    print("RESULT: FAIL — nothing arrived in", args.seconds, "seconds.")
    print("The sender's packets are not reaching Python at all.")
    return 1


def cmd_query(args) -> int:
    print(f"QUERY — sending a DNS query for {args.name} "
          f"to {args.host}:{args.port}\n")

    payload = build_query(args.name)
    print(f"  outbound: {describe(payload)}")
    print(f"  raw:      {payload.hex()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    try:
        start = time.perf_counter()
        sock.sendto(payload, (args.host, args.port))
        print(f"  sent {len(payload)} bytes from local port "
              f"{sock.getsockname()[1]}")
        data, addr = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - start) * 1000
        print(f"\n  reply from {addr[0]}:{addr[1]} after {elapsed:.1f} ms")
        print(f"  inbound:  {describe(data)}")
        print(f"  raw:      {data[:64].hex()}")
        print("\nRESULT: PASS — the proxy received and answered a real query.")
        print("nslookup is the odd one out, not the proxy.")
        return 0
    except socket.timeout:
        print(f"\nRESULT: NO REPLY within {args.timeout}s.")
        print("Check the proxy terminal:")
        print("  - a log line appeared  -> the request arrived, the reply did not")
        print("  - no log line at all   -> the request never arrived")
        return 1
    except OSError as exc:
        print(f"\nRESULT: SEND FAILED — {exc}")
        return 1
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("selftest").set_defaults(func=cmd_selftest)

    listen = sub.add_parser("listen")
    listen.add_argument("--port", type=int, default=5399)
    listen.add_argument("--seconds", type=int, default=30)
    listen.set_defaults(func=cmd_listen)

    query = sub.add_parser("query")
    query.add_argument("--host", default="127.0.0.1")
    query.add_argument("--port", type=int, default=5399)
    query.add_argument("--name", default="example.com")
    query.add_argument("--timeout", type=float, default=5.0)
    query.set_defaults(func=cmd_query)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
