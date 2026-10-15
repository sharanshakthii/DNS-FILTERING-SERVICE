"""
Public Suffix List.

Every module so far reduces a name to its last two labels, and says so: for
`x.co.uk` that yields the suffix `co.uk`, and for `login.pages.dev` it yields
the hosting platform `pages.dev` rather than the customer's site. The PSL
(https://publicsuffix.org) is the maintained answer to "where does the
registrable part of this name begin".

Two views, because they answer different questions:

  private=True   includes the list's PRIVATE section (pages.dev, netlify.app,
                 blogspot.com, ...). The *site* a name belongs to: the part a
                 customer of a shared platform chose. Right for lexical
                 analysis and for limiting how far a feed listing spreads.
  private=False  ICANN section only. The *registration*: what a registry
                 holds a record for. Right for RDAP, because `pages.dev` was
                 registered by Cloudflare and `x.pages.dev` was not
                 registered at all.

The list is pinned (resources/public_suffix_list.dat; version and commit in
its header) and loaded from disk once. Nothing is fetched at runtime, so a
result is reproducible from the repository alone.

Implements the algorithm at https://github.com/publicsuffix/list/wiki/Format:
normal, wildcard (`*.ck`) and exception (`!www.ck`) rules, the implicit `*`
rule for an unlisted TLD, and the longest matching rule prevailing.
"""

from __future__ import annotations

import threading
from functools import lru_cache
from pathlib import Path

DEFAULT_PATH = (Path(__file__).resolve().parent.parent
                / "resources" / "public_suffix_list.dat")

_lock = threading.Lock()
_rules: dict[str, bool] | None = None      # rule -> is_private
_version: str | None = None


def _to_ascii(rule: str) -> str:
    """Rules are published in Unicode; DNS names arrive as punycode."""
    try:
        return ".".join(label if label in ("*",) or label.startswith("!")
                        else label.encode("idna").decode("ascii")
                        for label in rule.split("."))
    except UnicodeError:
        return rule


def load(path: Path | str = DEFAULT_PATH) -> dict[str, bool]:
    """Parse the list once. Returns {rule: is_private}."""
    global _rules, _version
    with _lock:
        if _rules is not None:
            return _rules
        rules: dict[str, bool] = {}
        private = False
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("// VERSION:"):
                _version = line.split(":", 1)[1].strip()
            if "===BEGIN PRIVATE DOMAINS===" in line:
                private = True
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            exception = rule.startswith("!")
            ascii_rule = _to_ascii(rule[1:] if exception else rule)
            rules[("!" if exception else "") + ascii_rule] = private
        _rules = rules
        return _rules


def version() -> str | None:
    load()
    return _version


def _labels(name: str) -> list[str]:
    return [l for l in (name or "").strip().lower().rstrip(".").split(".") if l]


@lru_cache(maxsize=65536)
def suffix_length(name: str, private: bool = True) -> int:
    """Number of labels in the public suffix of `name` (at least 1)."""
    rules = load()
    labels = _labels(name)
    if not labels:
        return 0

    def allowed(rule: str) -> bool:
        is_private = rules.get(rule)
        return is_private is not None and (private or not is_private)

    best = 1                     # the implicit "*" rule
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if allowed("!" + candidate):
            # An exception rule wins outright; the suffix is the rule
            # minus its leftmost label.
            return len(labels) - i - 1
        wildcard = "*." + ".".join(labels[i + 1:]) if i + 1 < len(labels) else None
        if allowed(candidate) or (wildcard and allowed(wildcard)):
            best = max(best, len(labels) - i)
    return best


def public_suffix(name: str, private: bool = True) -> str:
    labels = _labels(name)
    n = suffix_length(".".join(labels), private)
    return ".".join(labels[-n:]) if n else ""


def registrable_domain(name: str, private: bool = True) -> str | None:
    """Suffix plus one label, or None when `name` is itself a suffix."""
    labels = _labels(name)
    n = suffix_length(".".join(labels), private)
    if not labels or len(labels) <= n:
        return None
    return ".".join(labels[-(n + 1):])


def registrable_label(name: str, private: bool = True) -> str:
    """The label a registrant (or platform customer) chose.

    `paypal-login.co.uk` -> `paypal-login`; `brand.pages.dev` -> `brand`.
    Falls back to the first label when the name is itself a suffix.
    """
    domain = registrable_domain(name, private)
    if domain is None:
        labels = _labels(name)
        return labels[0] if labels else ""
    return domain.split(".", 1)[0]


def on_shared_platform(name: str) -> bool:
    """True when `name` sits under a PRIVATE-section suffix (a hosting
    platform), so its ICANN registration belongs to the platform."""
    return registrable_domain(name, True) != registrable_domain(name, False)
