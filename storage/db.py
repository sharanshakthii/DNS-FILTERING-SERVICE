"""
Database layer.

SQLite, accessed through the standard library. The declared stack allows
PostgreSQL or SQLite; SQLite is the right choice for this stage because it
needs no server to be installed, running, or configured — which matters both
for a single-developer build and for a live demo where a missing service is
an unrecoverable failure in front of a panel.

The SQL below is deliberately plain and portable. Migrating to PostgreSQL
later means changing the connection function and the AUTOINCREMENT keyword,
not rewriting the schema or any calling code.

Threading: one writer thread owns the connection (see writer.py). The
connection is created with check_same_thread=False because it is handed to
that thread after construction, not because it is shared between threads.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from .models import QueryRecord

log = logging.getLogger("storage.db")

SCHEMA_VERSION = 2

# Feed state is created now, empty, because Stage 5 needs somewhere to record
# when a threat feed was last fetched and how stale it is. Creating it here
# keeps migrations linear instead of adding a table mid-experiment.
SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  TEXT    NOT NULL,
    client_hash         TEXT    NOT NULL,
    qname               TEXT,
    qtype               TEXT,
    latency_total_ms    REAL    NOT NULL,
    latency_upstream_ms REAL,
    added_latency_ms    REAL    NOT NULL,
    latency_json        TEXT    NOT NULL,
    error               TEXT
);

CREATE TABLE IF NOT EXISTS decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    query_id        INTEGER NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
    engine          TEXT    NOT NULL,
    aggregate_score REAL    NOT NULL,
    verdict         TEXT    NOT NULL,
    rcode           TEXT    NOT NULL,
    -- Stage 7: the derivation behind the verdict (weights, contributions,
    -- thresholds, policy vs enforced verdict). Nullable so decisions written
    -- by a v1 database remain valid rows rather than being back-filled with
    -- an explanation nobody computed.
    explanation_json TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id   INTEGER NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
    module        TEXT    NOT NULL,
    score         REAL    NOT NULL,
    features_json TEXT    NOT NULL,
    latency_ms    REAL    NOT NULL,
    status        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_state (
    feed         TEXT PRIMARY KEY,
    last_fetch_ts TEXT,
    entry_count   INTEGER NOT NULL DEFAULT 0,
    staleness_s   REAL
);

CREATE INDEX IF NOT EXISTS idx_queries_ts      ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_qname   ON queries(qname);
-- Stage 14: beaconing reads one domain's recent history on the DNS query
-- path, so that lookup must be a range scan rather than a table scan. Added
-- with IF NOT EXISTS so an existing database gains it on the next open
-- without a schema version bump or a migration step.
CREATE INDEX IF NOT EXISTS idx_queries_qname_ts ON queries(qname, ts);
CREATE INDEX IF NOT EXISTS idx_queries_client_qname_ts
    ON queries(client_hash, qname, ts);
CREATE INDEX IF NOT EXISTS idx_decisions_query ON decisions(query_id);
CREATE INDEX IF NOT EXISTS idx_decisions_verdict ON decisions(verdict);
CREATE INDEX IF NOT EXISTS idx_evidence_decision ON evidence(decision_id);
"""


class StorageError(Exception):
    """Something went wrong in the storage layer.

    Always caught by the writer thread. It must never reach the query path.
    """


def connect(path: str) -> sqlite3.Connection:
    """Open (creating if needed) the database at `path`.

    ":memory:" is honoured for tests.
    """
    if path != ":memory:":
        parent = Path(path).expanduser().resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        path = str(Path(path).expanduser())

    conn = sqlite3.connect(path, check_same_thread=False, timeout=5.0)
    conn.row_factory = sqlite3.Row

    if path != ":memory:":
        # WAL lets the Stage 10 API read while the writer thread writes.
        # It is unsupported on in-memory databases, hence the guard.
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error as exc:
            log.warning("could not enable WAL: %s", exc)

    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


class Database:
    """Owns the schema and the insert statements. No threading logic here."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.conn = connect(path)
        self.migrate()

    # -- schema ------------------------------------------------------------

    def migrate(self) -> None:
        """Apply the schema and stamp the version.

        PRAGMA user_version is a single integer SQLite stores in the file
        header. It costs nothing and means a later stage can tell a v1
        database from a v2 one instead of guessing from table names.
        """
        try:
            current = self.conn.execute("PRAGMA user_version").fetchone()[0]
            if current > SCHEMA_VERSION:
                raise StorageError(
                    f"database at {self.path} is schema v{current}, but this "
                    f"code understands v{SCHEMA_VERSION}. Refusing to touch it."
                )
            self.conn.executescript(SCHEMA)
            self._upgrade_from(current)
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self.conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"migration failed: {exc}") from exc

    def _upgrade_from(self, current: int) -> None:
        """Bring an older database up to the current schema.

        CREATE TABLE IF NOT EXISTS cannot add a column to a table that already
        exists, so an existing v1 file keeps its old `decisions` table and
        needs the column added explicitly. Guarded by an existence check
        rather than the version alone, because a database created fresh by
        the script above already has it.
        """
        if current >= SCHEMA_VERSION:
            return

        columns = {row[1] for row in
                   self.conn.execute("PRAGMA table_info(decisions)")}
        if "explanation_json" not in columns:
            log.info("migrating decisions table to schema v%d", SCHEMA_VERSION)
            self.conn.execute(
                "ALTER TABLE decisions ADD COLUMN explanation_json TEXT")

    @property
    def schema_version(self) -> int:
        return self.conn.execute("PRAGMA user_version").fetchone()[0]

    # -- writes ------------------------------------------------------------

    def insert_record(self, record: QueryRecord) -> int:
        """Write one query, its decision, and its evidence in one transaction.

        Atomic on purpose: a decision with no query, or evidence with no
        decision, would silently corrupt the Stage 16 ablation counts.
        """
        try:
            with self.conn:  # commits, or rolls back on exception
                cur = self.conn.execute(
                    "INSERT INTO queries (ts, client_hash, qname, qtype, "
                    "latency_total_ms, latency_upstream_ms, added_latency_ms, "
                    "latency_json, error) VALUES (?,?,?,?,?,?,?,?,?)",
                    (record.ts, record.client_hash, record.qname, record.qtype,
                     record.latency_total_ms, record.latency_upstream_ms,
                     record.added_latency_ms, record.latency_json(),
                     record.error),
                )
                query_id = cur.lastrowid

                cur = self.conn.execute(
                    "INSERT INTO decisions (query_id, engine, aggregate_score, "
                    "verdict, rcode, explanation_json) VALUES (?,?,?,?,?,?)",
                    (query_id, record.engine, record.score, record.verdict,
                     record.rcode, record.explanation_json()),
                )
                decision_id = cur.lastrowid

                if record.evidence:
                    self.conn.executemany(
                        "INSERT INTO evidence (decision_id, module, score, "
                        "features_json, latency_ms, status) VALUES (?,?,?,?,?,?)",
                        [(decision_id, e.module, e.score, e.features_json(),
                          e.latency_ms, e.status) for e in record.evidence],
                    )
            return query_id
        except sqlite3.Error as exc:
            raise StorageError(f"insert failed: {exc}") from exc

    def insert_many(self, records: list[QueryRecord]) -> int:
        """Write a batch. A single bad record does not lose the batch."""
        written = 0
        for record in records:
            try:
                self.insert_record(record)
                written += 1
            except StorageError as exc:
                log.warning("dropped one record: %s", exc)
        return written

    def upsert_feed_state(self, feed: str, last_fetch_ts: str | None,
                          entry_count: int, staleness_s: float | None) -> None:
        """Record the state of one feed after a fetch.

        Griffioen et al. (ACNS 2020) showed feed quality varies widely, so a
        verdict is only interpretable alongside what the feed held and how
        old it was when the verdict was made. Storing this is what lets Stage
        16 say that, rather than assume it.
        """
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO feed_state (feed, last_fetch_ts, entry_count, "
                    "staleness_s) VALUES (?,?,?,?) "
                    "ON CONFLICT(feed) DO UPDATE SET "
                    "last_fetch_ts=excluded.last_fetch_ts, "
                    "entry_count=excluded.entry_count, "
                    "staleness_s=excluded.staleness_s",
                    (feed, last_fetch_ts, entry_count, staleness_s))
        except sqlite3.Error as exc:
            raise StorageError(f"feed_state upsert failed: {exc}") from exc

    def feed_states(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM feed_state ORDER BY feed").fetchall()

    # -- reads (used by tests now, by the Stage 10 API later) --------------

    def count(self, table: str) -> int:
        if table not in {"queries", "decisions", "evidence", "feed_state"}:
            raise ValueError(f"unknown table {table!r}")
        return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def recent_queries(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT q.*, d.verdict, d.aggregate_score, d.engine, d.rcode, "
            "d.explanation_json "
            "FROM queries q JOIN decisions d ON d.query_id = q.id "
            "ORDER BY q.id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def evidence_for_query(self, query_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT e.* FROM evidence e "
            "JOIN decisions d ON e.decision_id = d.id "
            "WHERE d.query_id = ? ORDER BY e.id",
            (query_id,),
        ).fetchall()

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass
