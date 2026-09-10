"""Persistence layer for PRJ_112.

Public surface is deliberately small: the proxy only ever sees an object
with a `record(payload)` method, so storage can be swapped or disabled
without touching the query path.
"""

from .db import Database, StorageError
from .models import EvidenceRow, QueryRecord, hash_client
from .writer import AsyncRecorder, NullRecorder

__all__ = [
    "Database",
    "StorageError",
    "QueryRecord",
    "EvidenceRow",
    "hash_client",
    "AsyncRecorder",
    "NullRecorder",
]
