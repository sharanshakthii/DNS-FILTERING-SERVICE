"""
Read-only query history.

Behavioural detection needs to look backwards, and this project already
records every query it has answered. Rather than a second store, this reads
the `queries` table the DNS path already writes — the same rows the dashboard
shows, so what the module reasons about is exactly what a reviewer can see.

Opened with the `mode=ro` URI, like `api/repository.py`: a detection module
must not be able to write to the table the DNS path depends on.

**Timing.** The proxy decides before it records (`decide()` at
`dns_proxy.py:216`, `_record()` afterwards), and the recorder batches writes
on a background thread. So a module reading this sees *history*, never the
query being decided — which means it cannot double-count the current query,
and means the newest observation may be up to one flush interval behind.
Over a beaconing window measured in minutes that is immaterial, but it is
stated rather than assumed.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class HistoryUnavailable(RuntimeError):
    """The history database is missing or unreadable.

    Distinct from "no observations": one means the module could not look,
    the other means it looked and found nothing.
    """


def parse_timestamp(value: str) -> float | None:
    """ISO-8601 string to a POSIX timestamp, or None if unparseable.

    Returns None rather than raising: a single malformed row must not stop a
    DNS query being answered, and the module reports how many rows it had to
    discard.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


class ObservationStore:
    """Reads past observations of a domain from the decision database."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        path = Path(self.db_path)
        if not path.exists():
            raise HistoryUnavailable(
                f"no history database at {path}; the DNS proxy creates it on "
                f"first run")
        try:
            return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True,
                                   timeout=2.0)
        except sqlite3.Error as exc:
            raise HistoryUnavailable(f"cannot open {path}: {exc}") from exc

    def observations(self, qname: str, since: float, *,
                     client_hash: str | None = None,
                     limit: int = 5000) -> tuple[list[float], int]:
        """Timestamps for `qname` at or after `since`, oldest first.

        Returns (timestamps, rows discarded as unparseable). `limit` bounds
        the work a single DNS query can cause: a domain queried a hundred
        thousand times in the window must not make the resolver read all of
        them, and the newest rows are the ones that matter.

        The query is indexed on (qname, ts), so this is a range scan over one
        domain rather than a table scan.
        """
        name = (qname or "").strip().lower().rstrip(".")
        if not name:
            return [], 0

        cutoff = datetime.fromtimestamp(since, tz=timezone.utc).isoformat()

        sql = ("SELECT ts FROM queries WHERE qname = ? AND ts >= ?")
        params: list = [name, cutoff]
        if client_hash:
            sql += " AND client_hash = ?"
            params.append(client_hash)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(int(limit))

        try:
            with self._connect() as conn:
                rows = conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise HistoryUnavailable(f"history query failed: {exc}") from exc

        stamps, discarded = [], 0
        for (value,) in rows:
            parsed = parse_timestamp(value)
            if parsed is None:
                discarded += 1
            else:
                stamps.append(parsed)

        stamps.sort()
        return stamps, discarded
