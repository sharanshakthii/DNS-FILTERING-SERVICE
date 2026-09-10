"""
The detection module contract.

Every signal in this project — threat intelligence, newly registered domains,
typosquatting, beaconing — is a module implementing `DetectionModule`. Fixing
the shape now, before any real module exists, is deliberate: Stage 16 compares
what each signal contributes and what it costs, and that comparison is only
meaningful if every module is invoked identically and measured identically.

Division of responsibility:

  A module    decides a score and reports the features behind it. Nothing else.
  The engine  does the timing, the error trapping, the validation, and the
              budget enforcement.

That split is why a module author cannot accidentally omit timing, and why a
module that raises cannot take DNS resolution down with it.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


# Status values an evidence row can carry. Kept as plain strings because they
# go straight into SQLite and into the dashboard, and an enum would only be
# translated back to a string at both ends.
STATUS_OK = "ok"           # ran, produced a usable score
STATUS_ERROR = "error"     # raised unexpectedly; excluded from aggregation
#: Stage 15. The module ran correctly and reported that it *could not* assess
#: this query — no feed loaded, no brands configured, no model, too little
#: history. Distinct from STATUS_ERROR, which means something went wrong.
#: Both are excluded from aggregation, so this changes no arithmetic; it
#: changes what the evidence is able to say. Before this, a deliberate "I
#: have nothing to go on" was indistinguishable from a crash.
STATUS_UNAVAILABLE = "unavailable"
STATUS_INVALID = "invalid" # returned something unusable; excluded
STATUS_SKIPPED = "skipped" # not run, latency budget already spent
STATUS_DISABLED = "disabled"  # switched off for this run (ablation)


class ModuleUnavailable(RuntimeError):
    """The module cannot assess this query, and that is not a fault.

    Base class for the conditions each module already raised separately —
    an unloaded feed, an unconfigured brand list, a missing model, too few
    observations. Grouping them lets the engine report STATUS_UNAVAILABLE
    without every module needing to know about the status vocabulary.
    """


@dataclass(frozen=True)
class QueryContext:
    """Everything a module is allowed to see about one query.

    Deliberately narrow. Modules receive a value object rather than the raw
    packet so that no module can consume, mutate, or depend on wire-format
    details — which would couple detection to the parser and break the
    module boundary frozen at Review 1.

    `client_id` is the pseudonymised client identifier, present because
    beaconing detection (Stage 13) is defined over (client, domain) pairs.
    It is a hash, not an address: modules never see a real IP.
    """

    qname: str
    qtype: str
    client_id: str
    timestamp: float


@dataclass
class ModuleScore:
    """What a module returns.

    `score` is 0.0 (benign) to 1.0 (certainly malicious) on a scale shared by
    every module, so Stage 7 can aggregate without per-module special cases.

    `features` is the evidence: the actual values that produced the score.
    This is not debug output. It is the per-decision evidence trace that the
    project's contribution rests on, so a module that scores without saying
    why has not done its job.
    """

    score: float
    features: dict = field(default_factory=dict)

    def is_valid(self) -> bool:
        """A score must be a real number between 0 and 1.

        NaN is checked explicitly because it fails every comparison silently:
        `0.0 <= float('nan') <= 1.0` is False, but a NaN reaching the
        aggregator would poison a sum without raising anything.
        """
        if isinstance(self.score, bool) or not isinstance(self.score, (int, float)):
            return False
        if math.isnan(self.score) or math.isinf(self.score):
            return False
        return 0.0 <= float(self.score) <= 1.0


@dataclass
class ModuleResult:
    """One module's contribution to one decision — the shape stored as evidence.

    Matches `storage.models.EvidenceRow` field for field so persistence needs
    no translation layer.
    """

    module: str
    score: float
    features: dict
    latency_ms: float
    status: str

    @property
    def counts_toward_score(self) -> bool:
        """Only a clean run contributes to aggregation.

        An errored, invalid, skipped or disabled module must not be silently
        treated as scoring 0.0 — that would look identical to a module that
        ran and found nothing, and would quietly understate the risk on
        exactly the queries where something went wrong.
        """
        return self.status == STATUS_OK

    def to_evidence(self) -> dict:
        return {
            "module": self.module,
            "score": self.score,
            "features": self.features,
            "latency_ms": round(self.latency_ms, 3),
            "status": self.status,
        }


class DetectionModule(ABC):
    """Base class for every signal module.

    Subclasses implement `evaluate` and nothing else. They must not time
    themselves, catch their own exceptions to hide them, or write to the
    database — the engine owns all three.
    """

    #: Short stable identifier. Appears in evidence rows, in the ablation
    #: configuration, and on the dashboard, so it must not change casually.
    name: str = "unnamed"

    #: Set False to keep a module registered but inert (ablation).
    enabled: bool = True

    @abstractmethod
    def evaluate(self, ctx: QueryContext) -> ModuleScore:
        """Score one query. Raising is acceptable; the engine handles it."""

    def close(self) -> None:
        """Release anything held open. Default is nothing."""
        return

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} enabled={self.enabled}>"
