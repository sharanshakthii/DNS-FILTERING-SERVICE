"""
Asynchronous recorder.

The whole project rests on measuring what filtering costs a DNS query
(RQ2). A synchronous database write inside the query path would be counted
as part of that cost and would make every reported latency figure wrong —
not slightly wrong, but wrong in a way that flatters us, since a fast disk
would look like a fast filter.

So the query path does exactly one thing with a record: puts it on a bounded
queue and returns. A background thread does the writing. Three consequences,
all deliberate:

  * disk latency never appears in the measured query path
  * a database failure cannot fail a DNS resolution
  * under overload we drop records rather than block resolution

The last one is the uncomfortable trade and it is the right way round. A
dropped log line costs us a row in an experiment. A blocked query path costs
the network its DNS service. The drop counter is exposed so that any
experiment run with drops can be discarded rather than quietly believed.
"""

from __future__ import annotations

import logging
import queue
import threading
import time

from .db import Database, StorageError
from .models import QueryRecord

log = logging.getLogger("storage.writer")

_SENTINEL = object()


class NullRecorder:
    """Records nothing. The default, so the proxy runs without a database."""

    enabled = False

    def record(self, payload: dict) -> None:
        return

    def stats(self) -> dict:
        return {"enabled": False}

    def close(self, timeout: float = 5.0) -> None:
        return


class AsyncRecorder:
    """Queue-and-drain recorder. Safe to call from any proxy worker thread."""

    enabled = True

    def __init__(self, db_path: str, salt: str, queue_size: int = 10000,
                 batch_size: int = 50, flush_interval: float = 0.5) -> None:
        self.salt = salt
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._db: Database | None = None
        self._db_path = db_path

        self.dropped = 0
        self.written = 0
        self.failed = 0
        self._lock = threading.Lock()

        # Opened on the calling thread so a bad path fails loudly at startup
        # rather than silently in a background thread.
        self._db = Database(db_path)

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._drain, name="storage-writer",
                                        daemon=True)
        self._thread.start()

    # -- called from the query path ---------------------------------------

    def record(self, payload: dict) -> None:
        """Enqueue one decision payload. Never blocks, never raises.

        This is the only method the proxy calls. It must remain
        non-blocking and exception-free no matter what state the database
        is in.
        """
        try:
            record = QueryRecord.from_log_payload(payload, self.salt)
        except Exception:
            # A malformed payload is a bug worth seeing, but not worth
            # failing a DNS response over.
            log.exception("could not build a record from the decision payload")
            with self._lock:
                self.failed += 1
            return

        try:
            self._queue.put_nowait(record)
        except queue.Full:
            with self._lock:
                self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                log.warning("storage queue full, dropped %d record(s); "
                            "measurements from this run are incomplete",
                            self.dropped)

    # -- writer thread -----------------------------------------------------

    def _drain(self) -> None:
        batch: list[QueryRecord] = []
        last_flush = time.monotonic()

        while True:
            timeout = max(0.01, self.flush_interval - (time.monotonic() - last_flush))
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                item = None

            if item is _SENTINEL:
                self._flush(batch)
                return

            if item is not None:
                batch.append(item)

            due = (len(batch) >= self.batch_size
                   or time.monotonic() - last_flush >= self.flush_interval)
            if batch and due:
                self._flush(batch)
                batch = []
                last_flush = time.monotonic()

    def _flush(self, batch: list[QueryRecord]) -> None:
        if not batch or self._db is None:
            return
        try:
            written = self._db.insert_many(batch)
            with self._lock:
                self.written += written
                self.failed += len(batch) - written
        except StorageError as exc:
            # The database is unhappy. Count it, log it, keep the thread
            # alive: a writer that dies here would silently stop recording
            # for the rest of the run.
            with self._lock:
                self.failed += len(batch)
            log.error("batch of %d failed to write: %s", len(batch), exc)
        except Exception:
            with self._lock:
                self.failed += len(batch)
            log.exception("unexpected error in the storage writer")

    # -- introspection and shutdown ---------------------------------------

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled": True,
                "written": self.written,
                "dropped": self.dropped,
                "failed": self.failed,
                "queued": self._queue.qsize(),
            }

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until the queue is empty. For tests and clean shutdown only.

        Never call this from the query path.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.empty():
                time.sleep(self.flush_interval + 0.15)
                if self._queue.empty():
                    return True
            time.sleep(0.02)
        return False

    def close(self, timeout: float = 5.0) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        try:
            self._queue.put(_SENTINEL, timeout=1.0)
        except queue.Full:
            log.warning("queue full during shutdown; some records were lost")
        self._thread.join(timeout=timeout)
        if self._db is not None:
            self._db.close()
        log.info("storage writer stopped: %s", self.stats())
