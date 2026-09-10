"""
Read-only access to the decision database.

The API opens the SQLite file with the `mode=ro` URI, so it is incapable of
writing to the database the DNS query path depends on. That is deliberate:
`storage/` owns the write side, this owns the read side, and no bug in a
presentation layer can corrupt a decision record.

The queries live here rather than in `storage/db.py` because they exist only
to serve HTTP — pagination, filtering, aggregate counts — and pushing them
into the write-side module would make the DNS path carry code it never calls.

Every query is parameterised. No caller-supplied string is ever interpolated
into SQL; the sort and filter options are matched against fixed allow-lists.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

#: Verdicts the aggregator can produce. Used to validate a filter before it
#: reaches the database, so an unknown value is a 422 rather than an empty
#: result the caller might read as "no matching decisions".
VALID_VERDICTS = {"ALLOW", "FLAG", "BLOCK", "UNKNOWN", "SERVFAIL", "FORMERR"}

MAX_LIMIT = 500


class DatabaseUnavailable(RuntimeError):
    """The database file is missing or cannot be opened read-only.

    Distinct from "the database is empty": one means the API cannot answer,
    the other means the answer is zero. Conflating them would let a broken
    deployment look like an idle one.
    """


def _json_or_none(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


class DecisionRepository:
    """Read-only queries over the decisions written by the DNS proxy."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    # -- connection --------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        path = Path(self.db_path)
        if not path.exists():
            raise DatabaseUnavailable(
                f"no database at {path}. The DNS proxy creates it on first "
                f"run; start it at least once, or set DNSF_DB_PATH.")
        try:
            conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True,
                                   timeout=5.0)
        except sqlite3.Error as exc:
            raise DatabaseUnavailable(f"cannot open {path}: {exc}") from exc
        conn.row_factory = sqlite3.Row
        return conn

    def available(self) -> tuple[bool, str | None]:
        """(is the database readable, why not)."""
        try:
            with self._connect() as conn:
                conn.execute("SELECT 1 FROM queries LIMIT 1")
            return True, None
        except DatabaseUnavailable as exc:
            return False, str(exc)
        except sqlite3.Error as exc:
            return False, f"database unreadable: {exc}"

    def schema_version(self) -> int | None:
        try:
            with self._connect() as conn:
                return conn.execute("PRAGMA user_version").fetchone()[0]
        except (DatabaseUnavailable, sqlite3.Error):
            return None

    # -- decisions ---------------------------------------------------------

    def _row_to_decision(self, row: sqlite3.Row) -> dict:
        """Shape a stored row for the API.

        `client_hash` is carried through under a name that says what it is.
        The raw address was never stored, so there is nothing here to redact —
        the pseudonymisation happened at write time in `storage/models.py`.
        """
        explanation = _json_or_none(row["explanation_json"])
        return {
            "id": row["id"],
            "timestamp": row["ts"],
            "qname": row["qname"],
            "qtype": row["qtype"],
            "verdict": row["verdict"],
            "rcode": row["rcode"],
            "score": row["aggregate_score"],
            "engine": row["engine"],
            "client_hash": row["client_hash"],
            "latency_ms": {
                "total": row["latency_total_ms"],
                "upstream": row["latency_upstream_ms"],
                "added": row["added_latency_ms"],
                "breakdown": _json_or_none(row["latency_json"]) or {},
            },
            "error": row["error"],
            "enforcement": (explanation or {}).get("enforcement"),
        }

    def list_decisions(self, limit: int = 50, offset: int = 0,
                       verdict: str | None = None,
                       qname: str | None = None) -> tuple[list[dict], int]:
        """Return (page of decisions, total matching rows)."""
        limit = max(1, min(int(limit), MAX_LIMIT))
        offset = max(0, int(offset))

        clauses, params = [], []
        if verdict:
            clauses.append("d.verdict = ?")
            params.append(verdict)
        if qname:
            # Anchored prefix match, not a caller-supplied LIKE pattern.
            clauses.append("q.qname LIKE ? ESCAPE '\\'")
            escaped = (qname.strip().lower()
                       .replace("\\", "\\\\").replace("%", "\\%")
                       .replace("_", "\\_"))
            params.append(f"{escaped}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM queries q "
                f"JOIN decisions d ON d.query_id = q.id {where}",
                params).fetchone()[0]

            rows = conn.execute(
                f"SELECT q.id, q.ts, q.qname, q.qtype, q.client_hash, "
                f"       q.latency_total_ms, q.latency_upstream_ms, "
                f"       q.added_latency_ms, q.latency_json, q.error, "
                f"       d.verdict, d.rcode, d.aggregate_score, d.engine, "
                f"       d.explanation_json "
                f"FROM queries q JOIN decisions d ON d.query_id = q.id "
                f"{where} ORDER BY q.id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset]).fetchall()

        return [self._row_to_decision(r) for r in rows], total

    def get_decision(self, decision_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT q.id, q.ts, q.qname, q.qtype, q.client_hash, "
                "       q.latency_total_ms, q.latency_upstream_ms, "
                "       q.added_latency_ms, q.latency_json, q.error, "
                "       d.verdict, d.rcode, d.aggregate_score, d.engine, "
                "       d.explanation_json "
                "FROM queries q JOIN decisions d ON d.query_id = q.id "
                "WHERE q.id = ?", (decision_id,)).fetchone()
        return self._row_to_decision(row) if row else None

    def get_evidence(self, decision_id: int) -> dict | None:
        """Per-module evidence plus the aggregation derivation, or None."""
        with self._connect() as conn:
            head = conn.execute(
                "SELECT q.id, q.qname, d.id AS decision_id, d.verdict, "
                "       d.aggregate_score, d.explanation_json "
                "FROM queries q JOIN decisions d ON d.query_id = q.id "
                "WHERE q.id = ?", (decision_id,)).fetchone()
            if head is None:
                return None

            rows = conn.execute(
                "SELECT module, score, features_json, latency_ms, status "
                "FROM evidence WHERE decision_id = ? ORDER BY id",
                (head["decision_id"],)).fetchall()

        return {
            "decision_id": head["id"],
            "qname": head["qname"],
            "verdict": head["verdict"],
            "score": head["aggregate_score"],
            "modules": [{
                "module": r["module"],
                "score": r["score"],
                "status": r["status"],
                "latency_ms": r["latency_ms"],
                "features": _json_or_none(r["features_json"]) or {},
            } for r in rows],
            "explanation": _json_or_none(head["explanation_json"]),
        }

    # -- statistics --------------------------------------------------------

    def stats(self) -> dict:
        """Aggregate counts computed by the database, never estimated."""
        with self._connect() as conn:
            totals = {
                "queries": conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0],
                "decisions": conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0],
                "evidence": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            }

            verdicts = {r["verdict"]: r["n"] for r in conn.execute(
                "SELECT verdict, COUNT(*) AS n FROM decisions "
                "GROUP BY verdict ORDER BY n DESC")}

            latency_row = conn.execute(
                "SELECT AVG(latency_total_ms) AS avg_total, "
                "       MIN(added_latency_ms) AS min_added, "
                "       AVG(added_latency_ms) AS avg_added, "
                "       MAX(added_latency_ms) AS max_added "
                "FROM queries").fetchone()

            top = [{"qname": r["qname"], "count": r["n"]} for r in conn.execute(
                "SELECT q.qname, COUNT(*) AS n FROM queries q "
                "JOIN decisions d ON d.query_id = q.id "
                "WHERE d.verdict IN ('BLOCK','FLAG') AND q.qname IS NOT NULL "
                "GROUP BY q.qname ORDER BY n DESC LIMIT 10")]

            feeds = [{
                "feed": r["feed"],
                "last_fetch": r["last_fetch_ts"],
                "entries": r["entry_count"],
                "staleness_s": r["staleness_s"],
            } for r in conn.execute("SELECT * FROM feed_state ORDER BY feed")]

            span = conn.execute(
                "SELECT MIN(ts) AS first, MAX(ts) AS last FROM queries").fetchone()

        def rounded(value):
            return round(value, 3) if value is not None else None

        return {
            "totals": totals,
            "verdicts": verdicts,
            "latency_ms": {
                "avg_total": rounded(latency_row["avg_total"]),
                "min_added": rounded(latency_row["min_added"]),
                "avg_added": rounded(latency_row["avg_added"]),
                "max_added": rounded(latency_row["max_added"]),
            },
            "top_flagged_or_blocked": top,
            "feeds": feeds,
            "first_query": span["first"],
            "last_query": span["last"],
            # Guards against a reviewer reading these counts as evaluation
            # results. They describe traffic this resolver happened to see,
            # not detector performance.
            "note": ("Operational counts over observed traffic. These are not "
                     "evaluation metrics: detection accuracy is NOT YET "
                     "MEASURED (Stage 16)."),
        }
