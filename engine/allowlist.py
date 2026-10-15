"""
Operator allowlist — the false-positive override.

Feeds list subdomains of shared platforms, typosquat scoring fires on a
partner brand, a newly registered company site looks new. A filter with no
way to say "this one is fine" gets switched off by its users within a week,
so an allowlisted name is always ALLOW and never enforced.

The modules still run and their evidence is still stored: the override is
recorded next to the verdict it replaced, so an allowlist entry can never
silently hide what the detectors said.
"""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("engine.allowlist")


def _normalise(name: str) -> str:
    return name.strip().lower().rstrip(".")


class Allowlist:
    """A set of domains; each covers itself and every name beneath it."""

    def __init__(self, domains=()) -> None:
        self.domains = frozenset(d for d in (_normalise(x) for x in domains)
                                 if d and "." in d)

    def __len__(self) -> int:
        return len(self.domains)

    def match(self, qname: str) -> str | None:
        """The allowlist entry covering `qname`, or None."""
        labels = _normalise(qname).split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self.domains:
                return candidate
        return None

    @classmethod
    def from_settings(cls, settings) -> "Allowlist":
        entries = [x for x in (settings.allowlist or "").split(",") if x.strip()]
        path = getattr(settings, "allowlist_file", "")
        if path:
            try:
                for line in Path(path).read_text(encoding="utf-8").splitlines():
                    line = line.split("#", 1)[0].strip()
                    if line:
                        entries.append(line)
            except OSError as exc:
                # A missing allowlist must not stop DNS service, but it must
                # not pass unnoticed either.
                log.error("could not read allowlist %s: %s", path, exc)
        allowlist = cls(entries)
        if allowlist.domains:
            log.info("allowlist loaded: %d domains", len(allowlist))
        return allowlist
