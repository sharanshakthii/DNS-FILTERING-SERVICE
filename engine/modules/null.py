"""
The null module.

A complete, honest implementation of `DetectionModule` that detects nothing
and says so. It exists for three real reasons, none of which is a placeholder
for missing detection code:

  1. It proves the contract is implementable end to end, before any detection
     logic exists to confuse a failure with a scoring bug.
  2. It is the control arm. Stage 17 measures the engine's own overhead — the
     cost of dispatch, timing, and evidence assembly with zero detection work
     — and that number is only obtainable with a module that does nothing.
  3. It is the template a module author copies.

It is named `null` and reports `detects: "nothing"` in its features, so no
reading of a database row or a dashboard could mistake it for a detector.
"""

from __future__ import annotations

from .base import DetectionModule, ModuleScore, QueryContext


class NullModule(DetectionModule):
    """Always scores 0.0. Detects nothing, and declares it."""

    name = "null"

    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        return ModuleScore(
            score=0.0,
            features={"detects": "nothing", "qname": ctx.qname},
        )


class FixedScoreModule(DetectionModule):
    """Returns a score set at construction. For tests and calibration only.

    Not registered by default and not reachable from configuration. It exists
    so aggregation behaviour (Stage 7) can be exercised against known inputs
    rather than against whatever a real feed happens to contain that day.
    """

    def __init__(self, name: str, score: float, features: dict | None = None):
        self.name = name
        self._score = score
        self._features = features or {}

    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        return ModuleScore(score=self._score, features=dict(self._features))
