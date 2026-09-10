"""
Latency instrumentation.

RQ2 asks what the filtering path actually costs, so timing is a first-class
component rather than a debugging afterthought. Everything uses
perf_counter, which is monotonic and unaffected by wall-clock adjustments.
"""

from __future__ import annotations

import time
from contextlib import contextmanager


class Stopwatch:
    """Accumulates named durations for a single query's lifetime."""

    def __init__(self) -> None:
        self._marks: dict[str, float] = {}
        self._start = time.perf_counter()

    @contextmanager
    def measure(self, label: str):
        """Time a block and record it in milliseconds under `label`."""
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._marks[label] = self._marks.get(label, 0.0) + elapsed_ms

    def record(self, label: str, ms: float) -> None:
        self._marks[label] = self._marks.get(label, 0.0) + ms

    @property
    def total_ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000.0

    def as_dict(self) -> dict[str, float]:
        out = {k: round(v, 3) for k, v in self._marks.items()}
        out["total"] = round(self.total_ms, 3)
        return out
