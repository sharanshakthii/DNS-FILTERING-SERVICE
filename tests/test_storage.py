"""Stage 3 tests: the storage layer in isolation.

The bar these have to clear is not "rows appear". It is that a broken
database can never damage DNS service, and that the numbers a later
experiment reads out of this database are trustworthy.
"""

import sqlite3
import threading
import time

import pytest

from storage.db import Database, StorageError, SCHEMA_VERSION
from storage.models import EvidenceRow, QueryRecord, hash_client
from storage.writer import AsyncRecorder, NullRecorder


def payload(qname="example.com", verdict="ALLOW", evidence=None, **over):
    base = {
        "client": "192.0.2.10",
        "qname": qname,
        "qtype": "A",
        "verdict": verdict,
        "rcode": "NOERROR",
        "score": 0.0,
        "evidence": evidence or [],
        "latency_ms": {"parse": 0.03, "decide": 0.01, "upstream": 12.5,
                       "total": 12.6},
        "added_latency_ms": 0.1,
        "engine": "allow-all",
    }
    base.update(over)
    return base


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "test.sqlite3"))
    yield database
    database.close()


# -- schema ---------------------------------------------------------------

def test_migration_creates_every_table(db):
    names = {r[0] for r in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"queries", "decisions", "evidence", "feed_state"} <= names


def test_schema_version_is_stamped(db):
    assert db.schema_version == SCHEMA_VERSION


def test_migration_is_idempotent(tmp_path):
    path = str(tmp_path / "twice.sqlite3")
    first = Database(path)
    first.insert_record(QueryRecord.from_log_payload(payload(), "salt"))
    first.close()

    second = Database(path)          # re-open, migrate again
    assert second.count("queries") == 1, "re-migrating destroyed existing data"
    second.close()


def test_refuses_a_newer_schema(tmp_path):
    """Opening a future database read-write could silently corrupt it."""
    path = str(tmp_path / "future.sqlite3")
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION + 5}")
    conn.commit()
    conn.close()

    with pytest.raises(StorageError, match="Refusing"):
        Database(path)


# -- writing --------------------------------------------------------------

def test_insert_writes_query_and_decision(db):
    qid = db.insert_record(QueryRecord.from_log_payload(payload(), "salt"))
    assert qid > 0
    assert db.count("queries") == 1
    assert db.count("decisions") == 1

    row = db.recent_queries()[0]
    assert row["qname"] == "example.com"
    assert row["verdict"] == "ALLOW"
    assert row["latency_total_ms"] == pytest.approx(12.6)
    assert row["latency_upstream_ms"] == pytest.approx(12.5)
    assert row["added_latency_ms"] == pytest.approx(0.1)


def test_evidence_rows_are_linked_to_the_query(db):
    evidence = [
        {"module": "ti", "score": 1.0, "features": {"feed": "urlhaus"},
         "latency_ms": 0.2, "status": "ok"},
        {"module": "nrd", "score": 0.7, "features": {"age_hours": 3},
         "latency_ms": 0.4, "status": "ok"},
    ]
    qid = db.insert_record(QueryRecord.from_log_payload(
        payload(verdict="BLOCK", evidence=evidence, score=0.9), "salt"))

    rows = db.evidence_for_query(qid)
    assert [r["module"] for r in rows] == ["ti", "nrd"]
    assert rows[1]["features_json"] == '{"age_hours":3}'
    assert rows[0]["status"] == "ok"


def test_a_query_with_no_evidence_writes_no_evidence_rows(db):
    """Stage 3 runs under AllowAllEngine, which produces no evidence."""
    db.insert_record(QueryRecord.from_log_payload(payload(), "salt"))
    assert db.count("evidence") == 0


def test_all_verdict_types_persist(db):
    for verdict, rcode in [("ALLOW", "NOERROR"), ("BLOCK", "NXDOMAIN"),
                           ("SERVFAIL", "SERVFAIL"), ("FORMERR", "FORMERR")]:
        db.insert_record(QueryRecord.from_log_payload(
            payload(verdict=verdict, rcode=rcode), "salt"))
    verdicts = {r["verdict"] for r in db.recent_queries()}
    assert verdicts == {"ALLOW", "BLOCK", "SERVFAIL", "FORMERR"}


def test_formerr_with_no_qname_still_persists(db):
    """A malformed query has no name, and must still be counted."""
    db.insert_record(QueryRecord.from_log_payload(
        payload(qname=None, qtype=None, verdict="FORMERR", rcode="FORMERR",
                error="QDCOUNT is 257, only 1 is supported"), "salt"))
    row = db.recent_queries()[0]
    assert row["qname"] is None
    assert "QDCOUNT" in row["error"]


def test_insert_is_atomic(db):
    """A failure partway through must leave no orphaned query row.

    sqlite3.Connection.execute is a read-only C attribute and cannot be
    monkeypatched, so the connection is wrapped instead. Everything is
    delegated to the real connection except the second execute, which fails
    — that is the decisions insert, after the queries row already exists.
    """

    class FailOnSecondExecute:
        def __init__(self, conn):
            self._conn = conn
            self.calls = 0

        def execute(self, sql, *args):
            self.calls += 1
            if self.calls == 2:
                raise sqlite3.OperationalError("simulated failure")
            return self._conn.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self._conn, name)

        def __enter__(self):
            return self._conn.__enter__()

        def __exit__(self, *exc):
            return self._conn.__exit__(*exc)

    real = db.conn
    db.conn = FailOnSecondExecute(real)
    with pytest.raises(StorageError):
        db.insert_record(QueryRecord.from_log_payload(payload(), "salt"))

    db.conn = real
    assert db.count("queries") == 0, "transaction did not roll back"
    assert db.count("decisions") == 0


# -- privacy --------------------------------------------------------------

def test_client_address_is_not_stored_in_the_clear(db):
    db.insert_record(QueryRecord.from_log_payload(payload(), "salt"))
    row = db.recent_queries()[0]
    assert row["client_hash"] != "192.0.2.10"
    assert "192.0.2" not in row["client_hash"]


def test_hash_is_stable_and_salt_dependent():
    assert hash_client("10.0.0.1", "s") == hash_client("10.0.0.1", "s")
    assert hash_client("10.0.0.1", "s") != hash_client("10.0.0.2", "s")
    assert hash_client("10.0.0.1", "s") != hash_client("10.0.0.1", "other")


# -- malformed input ------------------------------------------------------

def test_exotic_feature_values_are_coerced_not_dropped(db):
    """`default=str` means an odd value is stringified rather than lost.

    Keeping a coerced value beats discarding the whole feature dict: the
    Stage 7 evidence trace is more useful with an imperfect field than with
    a missing one.
    """
    import json
    bad = [{"module": "x", "score": 0.5, "latency_ms": 0.1,
            "features": {"sock": object(), "age_hours": 3}}]
    qid = db.insert_record(QueryRecord.from_log_payload(
        payload(evidence=bad), "salt"))
    rows = db.evidence_for_query(qid)
    assert len(rows) == 1
    parsed = json.loads(rows[0]["features_json"])
    assert parsed["age_hours"] == 3, "a usable field was lost"
    assert isinstance(parsed["sock"], str)


def test_circular_features_fall_back_without_losing_the_row(db):
    """A reference cycle defeats `default=str` and must hit the fallback."""
    import json
    cycle: dict = {"self": None}
    cycle["self"] = cycle
    bad = [{"module": "x", "score": 0.5, "latency_ms": 0.1, "features": cycle}]

    qid = db.insert_record(QueryRecord.from_log_payload(
        payload(evidence=bad), "salt"))
    rows = db.evidence_for_query(qid)
    assert len(rows) == 1, "the evidence row was lost"
    assert json.loads(rows[0]["features_json"]) == {"_unserialisable": True}


def test_count_rejects_an_unknown_table(db):
    with pytest.raises(ValueError):
        db.count("robert'); DROP TABLE queries;--")


# -- the async recorder ---------------------------------------------------

def test_recorder_persists_what_it_is_given(tmp_path):
    rec = AsyncRecorder(str(tmp_path / "w.sqlite3"), salt="s", flush_interval=0.05)
    try:
        for i in range(25):
            rec.record(payload(qname=f"host{i}.test"))
        assert rec.flush(timeout=5), "queue did not drain"
        assert rec.stats()["written"] == 25
    finally:
        rec.close()

    db = Database(str(tmp_path / "w.sqlite3"))
    assert db.count("queries") == 25
    db.close()


def test_record_never_blocks_and_never_raises(tmp_path):
    """The query path calls this. It must return immediately, always."""
    rec = AsyncRecorder(str(tmp_path / "fast.sqlite3"), salt="s")
    try:
        start = time.perf_counter()
        for _ in range(500):
            rec.record(payload())
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"500 records took {elapsed:.2f}s — too slow for the query path"
    finally:
        rec.close()


def test_a_full_queue_drops_rather_than_blocks(tmp_path):
    """Overload must cost records, not DNS availability."""
    rec = AsyncRecorder(str(tmp_path / "small.sqlite3"), salt="s",
                        queue_size=5, batch_size=1000, flush_interval=30.0)
    try:
        for _ in range(200):
            rec.record(payload())
        assert rec.stats()["dropped"] > 0, "expected drops on a tiny queue"
    finally:
        rec.close()


def test_a_broken_database_does_not_kill_the_writer(tmp_path):
    """Storage failure must be survivable and visible, not fatal or silent."""
    rec = AsyncRecorder(str(tmp_path / "broken.sqlite3"), salt="s",
                        flush_interval=0.05)
    try:
        rec.record(payload())
        assert rec.flush(timeout=5)

        rec._db.conn.execute("DROP TABLE decisions")   # break it underneath
        rec._db.conn.commit()

        for _ in range(3):
            rec.record(payload())
        time.sleep(0.6)

        assert rec._thread.is_alive(), "writer thread died on a database error"
        assert rec.stats()["failed"] >= 1, "failures were not counted"

        # And it still accepts records without raising.
        rec.record(payload())
    finally:
        rec.close()


def test_malformed_payload_is_counted_not_raised(tmp_path):
    rec = AsyncRecorder(str(tmp_path / "junk.sqlite3"), salt="s",
                        flush_interval=0.05)
    try:
        rec.record({"latency_ms": "not-a-dict", "score": "not-a-number"})
        time.sleep(0.3)
        assert rec.stats()["failed"] >= 1
        assert rec._thread.is_alive()
    finally:
        rec.close()


def test_recorder_is_safe_from_many_threads(tmp_path):
    """Proxy workers call record() concurrently."""
    rec = AsyncRecorder(str(tmp_path / "mt.sqlite3"), salt="s",
                        flush_interval=0.05, queue_size=5000)
    try:
        def worker(n):
            for i in range(50):
                rec.record(payload(qname=f"t{n}-{i}.test"))

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert rec.flush(timeout=10)
        stats = rec.stats()
        assert stats["written"] + stats["dropped"] + stats["failed"] == 400
    finally:
        rec.close()


def test_close_is_idempotent(tmp_path):
    rec = AsyncRecorder(str(tmp_path / "close.sqlite3"), salt="s")
    rec.record(payload())
    rec.close()
    rec.close()      # must not hang or raise


def test_null_recorder_satisfies_the_same_interface():
    null = NullRecorder()
    null.record(payload())
    assert null.stats() == {"enabled": False}
    null.close()
