"""
Threat-intelligence feed sources.

A feed is anything that yields a set of domains plus the metadata needed to
judge how much to trust it. That metadata is not decoration: Griffioen,
Booij and Doerr (ACNS 2020) evaluated 24 open-source threat-intelligence
feeds and found wide variation in timeliness and accuracy, geographic bias,
low overlap between feeds, and real collateral damage. A system that
consumes a feed without recording when it was fetched and how many
indicators it held cannot reason about any of that afterwards.

So every fetch produces a `FeedSnapshot` carrying the fetch time and the
entry count, and those are persisted to `feed_state`. Stage 16 can then say
which feed contents produced a given verdict rather than guessing.
"""

from __future__ import annotations

import csv
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from urllib.parse import urlsplit

#: Conservative hostname check. Feeds contain junk — IP addresses, URLs with
#: ports, wildcards, unicode — and anything that is not plausibly a domain is
#: dropped rather than loaded and matched against later.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def normalise_domain(raw: str) -> str | None:
    """Return a clean lowercase domain, or None if it is not one.

    Rejects bare IP addresses. A feed listing an IP is describing a host, not
    a name, and DNS filtering acts on names — matching an IP string against a
    qname would never fire and would inflate the entry count with indicators
    that cannot possibly match.
    """
    if not raw:
        return None

    value = raw.strip().lower().rstrip(".")
    if not value or value.startswith("#"):
        return None

    # Strip a leading wildcard, which several feeds use for subdomains.
    if value.startswith("*."):
        value = value[2:]

    if ":" in value or "/" in value:
        return None

    # Reject dotted-quad IPs: all-numeric labels.
    if all(part.isdigit() for part in value.split(".")):
        return None

    return value if _DOMAIN_RE.match(value) else None


def parse_domain_list(text: str) -> set[str]:
    """One domain per line. Blank lines and `#` comments ignored."""
    out = set()
    for line in text.splitlines():
        domain = normalise_domain(line.split("#", 1)[0])
        if domain:
            out.add(domain)
    return out


def parse_hosts_file(text: str) -> set[str]:
    """Hosts-file format: `0.0.0.0 evil.example`.

    The sinkhole address itself is skipped, as is `localhost`, which every
    hosts-format feed contains and which must never be treated as an
    indicator.
    """
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        for candidate in parts[1:]:
            domain = normalise_domain(candidate)
            if domain and domain not in {"localhost", "localhost.localdomain"}:
                out.add(domain)
    return out


def parse_url_list(text: str) -> set[str]:
    """Extract hosts from a list of URLs, as URLhaus publishes."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "://" not in line:
            line = "http://" + line
        try:
            host = urlsplit(line).hostname
        except ValueError:
            continue
        domain = normalise_domain(host or "")
        if domain:
            out.add(domain)
    return out


#: Header names, lowercased, that carry something we can turn into a domain.
#: `host` is preferred where present because URLhaus already extracted it;
#: `url` is the fallback and needs parsing.
CSV_HOST_COLUMNS = ("host", "hostname", "domain")
CSV_URL_COLUMNS = ("url", "malicious url", "link")


def _domain_from_field(value: str) -> str | None:
    """Turn one CSV field into a domain, whether it is a URL or a bare host."""
    value = (value or "").strip().strip('"')
    if not value:
        return None
    if "://" in value or "/" in value:
        try:
            host = urlsplit(value if "://" in value else "http://" + value).hostname
        except ValueError:
            return None
        return normalise_domain(host or "")
    return normalise_domain(value)


def parse_urlhaus_csv(text: str) -> set[str]:
    """Extract domains from an abuse.ch CSV export.

    abuse.ch publishes several CSV layouts and does not guarantee one across
    endpoints. Two are confirmed:

        # comment lines, then a commented header:
        # id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter

        # ASN feed, header as a normal row:
        Dateadded (UTC),URL,URL_status,Threat,Tags,Host,IPaddress,ASnumber,Country

    The header of the authenticated `/v2/files/exports/.../recent.csv`
    endpoint could not be verified — it is behind the same Auth-Key — so this
    parser is driven by **column names rather than positions**, and falls
    back to scanning every field of a row when no header can be identified.
    Hardcoding an unverified column index would fail silently on a layout
    change, which is exactly the failure being fixed here: the feed
    downloaded successfully and yielded nothing.

    Note that a large share of URLhaus entries are bare IP addresses. Those
    are correctly rejected by `normalise_domain`, because an IP indicator
    cannot match a queried name. A CSV of ten thousand rows legitimately
    produces far fewer domains.
    """
    rows = text.splitlines()

    # The classic dump puts its header in the last comment line before the
    # data, so comments are inspected rather than simply discarded.
    header: list[str] | None = None
    data_lines: list[str] = []
    for line in rows:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            candidate = stripped.lstrip("#").strip()
            fields = [f.strip().strip('"').lower() for f in candidate.split(",")]
            if len(fields) > 1 and any(
                    f in CSV_HOST_COLUMNS or f in CSV_URL_COLUMNS
                    for f in fields):
                header = fields
            continue
        data_lines.append(line)

    if not data_lines:
        return set()

    reader = csv.reader(data_lines)
    records = list(reader)

    # No commented header: the first data row may be one.
    if header is None and records:
        fields = [f.strip().strip('"').lower() for f in records[0]]
        if any(f in CSV_HOST_COLUMNS or f in CSV_URL_COLUMNS for f in fields):
            header = fields
            records = records[1:]

    host_index = url_index = None
    if header:
        for index, name in enumerate(header):
            if host_index is None and name in CSV_HOST_COLUMNS:
                host_index = index
            if url_index is None and name in CSV_URL_COLUMNS:
                url_index = index

    out: set[str] = set()
    for record in records:
        if not record:
            continue

        domain = None
        for index in (host_index, url_index):
            if index is not None and index < len(record):
                domain = _domain_from_field(record[index])
                if domain:
                    break

        # No usable header, or the named columns held nothing: scan the row.
        # Slower, but it degrades to a wrong-but-empty result rather than a
        # silent one if abuse.ch renames a column.
        if domain is None and host_index is None and url_index is None:
            for field in record:
                domain = _domain_from_field(field)
                if domain:
                    break

        if domain:
            out.add(domain)

    return out


PARSERS = {
    "domains": parse_domain_list,
    "hosts": parse_hosts_file,
    "urls": parse_url_list,
    "csv": parse_urlhaus_csv,
}


@dataclass
class FeedSnapshot:
    """The result of one fetch attempt, successful or not."""

    feed: str
    domains: set[str] = field(default_factory=set)
    fetched_at: float = field(default_factory=time.time)
    source: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def entry_count(self) -> int:
        return len(self.domains)

    def age_s(self, now: float | None = None) -> float:
        return (now if now is not None else time.time()) - self.fetched_at


class FeedSource(ABC):
    """A named source of domain indicators."""

    def __init__(self, name: str, fmt: str = "domains") -> None:
        if fmt not in PARSERS:
            raise ValueError(f"unknown feed format {fmt!r}; "
                             f"expected one of {sorted(PARSERS)}")
        self.name = name
        self.fmt = fmt

    @abstractmethod
    def _read(self) -> str:
        """Return the raw feed text. May raise; `fetch` handles it."""

    @property
    def source(self) -> str:
        return self.name

    def fetch(self) -> FeedSnapshot:
        """Fetch and parse. Never raises: a failure is a snapshot with an error.

        A feed being unreachable is an ordinary operating condition — the
        campus network is down, the publisher rate-limited us — and must be
        recorded as such rather than crashing the resolver that depends on it.
        """
        try:
            text = self._read()
        except Exception as exc:
            return FeedSnapshot(feed=self.name, source=self.source,
                                error=f"{type(exc).__name__}: {str(exc)[:200]}")

        try:
            domains = PARSERS[self.fmt](text)
        except Exception as exc:
            return FeedSnapshot(feed=self.name, source=self.source,
                                error=f"parse failed: {str(exc)[:200]}")

        return FeedSnapshot(feed=self.name, domains=domains, source=self.source)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} fmt={self.fmt!r}>"
