"""
PRJ_112 filtering DNS proxy — Stage 2.

What this stage does: receives queries on UDP, parses them safely, forwards
them upstream with a fresh transaction ID, validates the reply, returns it,
and records a structured JSON line with per-phase latency for every query.

What this stage does NOT do: filter anything. The decision engine arrives in
Stage 4 and blocking in Stage 8. Until then the engine below allows every
query, and says so in its name. Nothing here pretends to be detection.

Run:
    python -m proxy.dns_proxy
Test:
    dig @127.0.0.1 -p 5353 example.com
"""

from __future__ import annotations

import hashlib
import json
import logging
import signal
import socket
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from config.settings import Settings

from .packet import (
    MalformedQuery,
    Query,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    build_formerr,
    build_response,
    parse_query,
)
from .enforce import BlockResponder
from .timing import Stopwatch
from .upstream import (
    UpstreamError,
    UpstreamResolver,
    UpstreamTimeout,
    suppress_udp_conn_reset as _suppress_udp_conn_reset,
)

log = logging.getLogger("proxy")


class JsonFormatter(logging.Formatter):
    """One JSON object per line.

    Query records carry a `decision` payload; everything else is a plain
    message. Keeping both in one stream means the experiment scripts read a
    single file.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
        }
        decision = getattr(record, "decision", None)
        if decision is not None:
            payload["event"] = "query"
            payload.update(decision)
        else:
            payload["event"] = "log"
            payload["message"] = record.getMessage()
            if record.exc_info:
                payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


class AllowAllEngine:
    """Stage 2 decision engine: allows everything.

    This is the real behaviour of the system at this stage, not a stub
    standing in for missing code. Stage 4 adds DecisionEngine alongside it
    and Stage 8 wires the BLOCK verdict to a response. This class remains
    the default so the verified Stage 1-3 behaviour is unchanged unless
    modules are configured deliberately.
    """

    name = "allow-all"

    def decide(self, query: Query, stopwatch: Stopwatch,
               client_id: str = "unknown") -> dict:
        return {"verdict": "ALLOW", "score": 0.0, "evidence": []}


class DNSProxy:
    def __init__(self, settings: Settings, engine: AllowAllEngine | None = None,
                 recorder=None) -> None:
        """`recorder` is any object with a non-blocking `record(payload)`.

        Typed loosely and defaulted to None on purpose: this module imports
        nothing from `storage`, so the proxy can be tested, run, and reasoned
        about with no database in the picture at all. main() does the wiring.
        """
        self.settings = settings
        self.engine = engine or AllowAllEngine()
        self.recorder = recorder
        self.blocker = BlockResponder.from_settings(settings)
        self.upstream = UpstreamResolver(
            host=settings.upstream_host,
            port=settings.upstream_port,
            timeout=settings.upstream_timeout,
        )
        self._sock: socket.socket | None = None
        self._conn_resets = 0
        self._stop = threading.Event()
        self._pool = ThreadPoolExecutor(max_workers=settings.workers,
                                        thread_name_prefix="dnsf")

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _suppress_udp_conn_reset(sock)
        sock.bind((self.settings.listen_host, self.settings.listen_port))
        sock.settimeout(0.5)  # so the accept loop can notice self._stop
        self._sock = sock

        log.info("listening on %s:%d, upstream %s:%d, engine=%s, "
                 "block_response=%s",
                 self.settings.listen_host, self.settings.listen_port,
                 self.settings.upstream_host, self.settings.upstream_port,
                 self.engine.name, self.blocker.mode)

        try:
            self._serve_forever()
        finally:
            self._pool.shutdown(wait=True)
            sock.close()
            self._sock = None
            log.info("stopped")

    def stop(self) -> None:
        self._stop.set()

    @property
    def port(self) -> int:
        """Actual bound port. Useful when the tests bind to port 0."""
        if self._sock is None:
            raise RuntimeError("proxy is not running")
        return self._sock.getsockname()[1]

    def _serve_forever(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                # Windows surfaces an ICMP port-unreachable from an *earlier*
                # reply as WSAECONNRESET (10054) on the *next* recvfrom, even
                # though UDP has no connection to reset. It reports the fate of
                # a datagram we already sent, not a failure of this socket, so
                # the only correct response is to carry on serving. Letting it
                # escape kills the resolver, which means any client that sends
                # a query and closes its socket can take the service down.
                self._conn_resets += 1
                log.debug("ignored UDP connection reset (total %d)",
                          self._conn_resets)
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            self._pool.submit(self._handle_safely, data, addr)

    # -- request handling --------------------------------------------------

    def _handle_safely(self, data: bytes, addr: tuple[str, int]) -> None:
        """Never let a worker thread die silently.

        A crash here would drop the query with no reply and no log line,
        which is the hardest kind of fault to diagnose during a live demo.
        """
        try:
            self._handle(data, addr)
        except Exception:
            log.exception("unhandled error while serving %s", addr[0])

    def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        stopwatch = Stopwatch()

        try:
            with stopwatch.measure("parse"):
                query = parse_query(data)
        except MalformedQuery as exc:
            # Answer FORMERR when there is enough of a packet to echo an ID
            # back, otherwise stay silent — replying to two bytes of noise
            # just makes us a reflector.
            txid = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else None
            log.warning("malformed query from %s: %s", addr[0], exc)
            if txid is not None:
                self._send(build_formerr(txid), addr)
            self._record(None, addr, "FORMERR", stopwatch,
                         error=str(exc), rcode="FORMERR")
            return

        with stopwatch.measure("decide"):
            # Modules receive a pseudonymised client identifier, never a real
            # address. Beaconing detection (Stage 13) is defined over
            # (client, domain) pairs, so the identifier has to be present in
            # the contract from the start; SR1 says it must not be an IP.
            decision = self.engine.decide(
                query, stopwatch, client_id=self._client_id(addr[0]))

        # Stage 8: act on the enforcement decision, not on the verdict string.
        # A BLOCK verdict with enforcement off is a recorded detection, and
        # the query is forwarded normally. Engines that predate Stage 8 return
        # no enforcement block at all and are treated as "forward".
        enforcement = decision.get("enforcement") or {}

        if enforcement.get("action") == "block":
            with stopwatch.measure("enforce"):
                payload, rcode_name = self.blocker.build(query)
            self._send(payload, addr)
            # Deliberately returns before upstream.forward: an enforced block
            # must not leak the queried name to the upstream resolver, which
            # would defeat the point of blocking it.
            log.info("blocked %s (%s, score=%.3f) with %s",
                     query.question.qname, decision["verdict"],
                     decision["score"], rcode_name)
            self._record(query, addr, decision["verdict"], stopwatch,
                         score=decision["score"],
                         evidence=decision["evidence"],
                         explanation=decision.get("explanation"),
                         rcode=rcode_name)
            return

        try:
            response, upstream_ms = self.upstream.forward(query)
            stopwatch.record("upstream", upstream_ms)
        except UpstreamTimeout as exc:
            # The timeout is upstream time, not ours. Without recording it,
            # added_latency_ms (total minus upstream) attributes the whole
            # wait to the filtering path and poisons the Stage 17 latency
            # distribution.
            stopwatch.record("upstream", exc.elapsed_ms)
            log.warning("upstream timeout for %s: %s", query.question.qname, exc)
            self._send(build_response(query, RCODE_SERVFAIL), addr)
            # Detection ran before forwarding, so its evidence exists and must
            # be kept. Malicious domains are disproportionately dead — Bilge
            # et al. (NDSS 2011) found most live under two days — so dropping
            # evidence here would systematically undercount detections on
            # exactly the domains that matter.
            self._record(query, addr, "SERVFAIL", stopwatch,
                         score=decision["score"], evidence=decision["evidence"],
                         explanation=decision.get("explanation"),
                         error="upstream_timeout", rcode="SERVFAIL")
            return
        except UpstreamError as exc:
            stopwatch.record("upstream", getattr(exc, "elapsed_ms", 0.0))
            log.warning("upstream error for %s: %s", query.question.qname, exc)
            self._send(build_response(query, RCODE_SERVFAIL), addr)
            self._record(query, addr, "SERVFAIL", stopwatch,
                         score=decision["score"], evidence=decision["evidence"],
                         explanation=decision.get("explanation"),
                         error=str(exc), rcode="SERVFAIL")
            return

        self._send(response, addr)
        self._record(query, addr, decision["verdict"], stopwatch,
                     score=decision["score"], evidence=decision["evidence"],
                     explanation=decision.get("explanation"),
                     rcode="NOERROR")

    def _client_id(self, ip: str) -> str:
        """Pseudonymise a client address for the engine.

        Uses the same salted digest as the storage layer so an evidence row
        and its query row agree, computed inline rather than imported from
        `storage` to keep the proxy independent of persistence.
        """
        digest = hashlib.sha256(
            f"{self.settings.client_salt}:{ip}".encode("utf-8")).hexdigest()
        return digest[:16]

    def _send(self, payload: bytes, addr: tuple[str, int]) -> None:
        if self._sock is None:
            return
        try:
            self._sock.sendto(payload, addr)
        except OSError as exc:
            log.warning("failed to reply to %s: %s", addr[0], exc)

    def _record(self, query: Query | None, addr: tuple[str, int], verdict: str,
                stopwatch: Stopwatch, *, score: float = 0.0,
                evidence: list | None = None, rcode: str = "",
                error: str | None = None,
                explanation: dict | None = None) -> None:
        """Emit the structured record for one query.

        `latency_ms` is deliberately broken out by phase. The added cost of
        filtering is total minus upstream, and reporting that number is the
        whole point of RQ2 — it cannot be reconstructed after the fact from
        a single aggregate figure.
        """
        latency = stopwatch.as_dict()
        added = round(latency["total"] - latency.get("upstream", 0.0), 3)

        payload = {
            "client": addr[0],
            "qname": query.question.qname if query else None,
            "qtype": query.question.qtype_name if query else None,
            "verdict": verdict,
            "rcode": rcode,
            "score": score,
            "evidence": evidence or [],
            "explanation": explanation,
            "enforcement": ((explanation or {}).get("enforcement")
                            if explanation else None),
            "latency_ms": latency,
            "added_latency_ms": added,
            "engine": self.engine.name,
        }
        if error:
            payload["error"] = error

        log.info("query", extra={"decision": payload})

        if self.recorder is not None:
            # Storage is downstream of the reply, which has already been sent
            # by this point, and record() is contractually non-blocking. The
            # try/except is belt and braces: no storage defect may ever be
            # able to affect DNS service.
            try:
                self.recorder.record(payload)
            except Exception:
                log.exception("recorder raised; continuing without persistence")


def configure_logging(settings: Settings) -> None:
    handler: logging.Handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.log_level, logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)

    if settings.log_file:
        file_handler = logging.FileHandler(settings.log_file)
        file_handler.setFormatter(JsonFormatter())
        root.addHandler(file_handler)


def build_engine(settings: Settings):
    """Construct the engine from configuration, or keep the Stage 2 default.

    An unknown module name is fatal at startup rather than silently ignored:
    running an ablation that quietly omits a signal would produce results
    that look valid and are not.
    """
    names = settings.module_names
    if not names:
        return AllowAllEngine()

    from engine import DecisionEngine, RiskAggregator
    from engine.allowlist import Allowlist
    from engine.modules import REGISTRY

    modules = []
    for name in names:
        if name not in REGISTRY:
            raise SystemExit(
                f"unknown module {name!r} in DNSF_ENGINE_MODULES. "
                f"Available: {', '.join(sorted(REGISTRY)) or '(none)'}")
        cls = REGISTRY[name]
        # Modules needing configuration expose from_settings; simple ones
        # construct bare. Keeps REGISTRY a plain name-to-class map.
        factory = getattr(cls, "from_settings", None)
        modules.append(factory(settings) if factory else cls())

    aggregator = RiskAggregator.from_settings(settings)
    allowlist = Allowlist.from_settings(settings)
    engine = DecisionEngine(modules, budget_ms=settings.engine_budget_ms,
                            aggregator=aggregator,
                            allowlist=allowlist if len(allowlist) else None)
    log.info("engine configured with modules: %s "
             "(flag>=%.2f block>=%.2f enforce=%s fail=%s)",
             ", ".join(names), aggregator.flag_at, aggregator.block_at,
             aggregator.enforce, aggregator.fail_mode)
    return engine


def build_recorder(settings: Settings):
    """Construct the recorder, or fall back to running without one.

    A database that cannot be opened is a reason to lose persistence, not a
    reason to refuse to serve DNS. The failure is logged loudly so it is not
    discovered later by finding an empty table.
    """
    if not settings.db_enabled:
        log.info("persistence disabled (DNSF_DB_ENABLED=false)")
        return None

    try:
        from storage import AsyncRecorder
        recorder = AsyncRecorder(
            db_path=settings.db_path,
            salt=settings.client_salt,
            queue_size=settings.db_queue_size,
            batch_size=settings.db_batch_size,
            flush_interval=settings.db_flush_interval,
        )
        log.info("persistence enabled at %s", settings.db_path)
        return recorder
    except Exception as exc:
        log.error("could not open the database at %s (%s); "
                  "continuing WITHOUT persistence", settings.db_path, exc)
        return None


def main() -> int:
    settings = Settings.from_env()
    configure_logging(settings)

    recorder = build_recorder(settings)
    engine = build_engine(settings)
    proxy = DNSProxy(settings, engine=engine, recorder=recorder)

    def shutdown(signum, _frame):
        log.info("signal %s received, shutting down", signum)
        proxy.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        proxy.start()
    except PermissionError:
        log.error("cannot bind %s:%d — ports below 1024 need root; "
                  "set DNSF_LISTEN_PORT to something above 1024",
                  settings.listen_host, settings.listen_port)
        return 1
    except OSError as exc:
        log.error("cannot bind %s:%d — %s",
                  settings.listen_host, settings.listen_port, exc)
        return 1
    finally:
        if recorder is not None:
            recorder.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
