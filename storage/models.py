"""
Persistence records.

These dataclasses are the boundary between the proxy's in-memory decision
payload and the database. The proxy knows nothing about them; the recorder
translates. That keeps the query path free of storage concerns and lets the
schema change without touching dns_proxy.py.

One decision per query, many evidence rows per decision. That shape is
dictated by Stage 7: risk aggregation must be able to show which module
contributed what, and a flat table cannot answer that without either
repeating the query columns or losing the per-module breakdown.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone


def hash_client(ip: str, salt: str) -> str:
    """Pseudonymise a client address.

    SR1 says we retain no more client identity than the experiment needs.
    Experiments need to group queries by origin, not to identify a person, so
    a salted digest is enough. Truncated to 16 hex characters: still ample to
    distinguish the handful of clients on a test network, short enough that
    the table stays readable during a demo.

    This is pseudonymisation, not anonymisation. The address space is small
    enough to brute-force if the salt leaks, and the report must say so
    rather than describing the logs as anonymous.
    """
    digest = hashlib.sha256(f"{salt}:{ip}".encode("utf-8")).hexdigest()
    return digest[:16]


@dataclass
class EvidenceRow:
    module: str
    score: float
    features: dict
    latency_ms: float
    status: str = "ok"

    @classmethod
    def from_payload(cls, item: dict) -> "EvidenceRow":
        return cls(
            module=str(item.get("module", "unknown")),
            score=float(item.get("score", 0.0)),
            features=item.get("features") or {},
            latency_ms=float(item.get("latency_ms", 0.0)),
            status=str(item.get("status", "ok")),
        )

    def features_json(self) -> str:
        try:
            return json.dumps(self.features, separators=(",", ":"),
                              default=str)
        except (TypeError, ValueError):
            # Never let an unserialisable feature value stop a row being
            # written; the row is worth more than the one bad field.
            return json.dumps({"_unserialisable": True})


@dataclass
class QueryRecord:
    """One resolved (or rejected) query, ready to persist."""

    ts: str
    client_hash: str
    qname: str | None
    qtype: str | None
    verdict: str
    rcode: str
    score: float
    engine: str
    latency: dict
    added_latency_ms: float
    error: str | None = None
    evidence: list[EvidenceRow] = field(default_factory=list)
    #: Stage 7 aggregation derivation. None for engines that do not aggregate.
    explanation: dict | None = None

    @property
    def latency_total_ms(self) -> float:
        return float(self.latency.get("total", 0.0))

    @property
    def latency_upstream_ms(self) -> float | None:
        value = self.latency.get("upstream")
        return float(value) if value is not None else None

    def explanation_json(self) -> str | None:
        """Serialise the aggregation derivation, or None when absent.

        None rather than "{}" so a row written by a non-aggregating engine is
        distinguishable from one where aggregation ran and explained nothing.
        """
        if not self.explanation:
            return None
        try:
            return json.dumps(self.explanation, separators=(",", ":"),
                              default=str)
        except (TypeError, ValueError):
            return json.dumps({"_unserialisable": True})

    def latency_json(self) -> str:
        try:
            return json.dumps(self.latency, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            return "{}"

    @classmethod
    def from_log_payload(cls, payload: dict, salt: str) -> "QueryRecord":
        """Build a record from the proxy's decision payload.

        The proxy emits exactly one dict shape for every outcome — ALLOW,
        BLOCK, SERVFAIL, FORMERR — so this is the only translation point in
        the system and there is no per-verdict special casing anywhere else.
        """
        client = payload.get("client")
        return cls(
            ts=datetime.now(timezone.utc).isoformat(),
            client_hash=hash_client(client, salt) if client else "unknown",
            qname=payload.get("qname"),
            qtype=payload.get("qtype"),
            verdict=str(payload.get("verdict", "UNKNOWN")),
            rcode=str(payload.get("rcode", "")),
            score=float(payload.get("score", 0.0)),
            engine=str(payload.get("engine", "unknown")),
            latency=payload.get("latency_ms") or {},
            added_latency_ms=float(payload.get("added_latency_ms", 0.0)),
            error=payload.get("error"),
            evidence=[EvidenceRow.from_payload(e)
                      for e in (payload.get("evidence") or [])],
            explanation=payload.get("explanation"),
        )
