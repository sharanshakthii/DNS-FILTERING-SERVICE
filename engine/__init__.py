"""Detection engine for PRJ_112.

The proxy only ever sees an object with a `decide(query, stopwatch, client_id)`
method, so the engine can be replaced or emptied without touching the query
path.
"""

from .aggregator import RiskAggregator, parse_weights
from .decision import DecisionEngine
from .explain import summarise
from .modules.base import (
    DetectionModule,
    ModuleResult,
    ModuleScore,
    QueryContext,
)

__all__ = [
    "DecisionEngine",
    "summarise",
    "RiskAggregator",
    "parse_weights",
    "DetectionModule",
    "ModuleResult",
    "ModuleScore",
    "QueryContext",
]
