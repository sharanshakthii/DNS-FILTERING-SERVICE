"""
Concrete feed sources.

`LocalFileSource` is not a convenience. Stage 16 has to be reproducible, and
a feed that changes hourly makes an experiment impossible to repeat: the same
code over the same traffic gives different answers on Tuesday. So experiments
run against a pinned local snapshot, and the network sources exist to produce
those snapshots and to demonstrate live operation.
"""

from __future__ import annotations

import gzip
import logging
import urllib.error
import urllib.request
from pathlib import Path

from .base import FeedSource

log = logging.getLogger("feeds")

USER_AGENT = "PRJ112-DNS-Filter/0.5 (university project; contact via GitHub)"


class LocalFileSource(FeedSource):
    """Reads indicators from a file on disk. Deterministic, offline."""

    def __init__(self, name: str, path: str, fmt: str = "domains") -> None:
        super().__init__(name, fmt)
        self.path = Path(path)

    @property
    def source(self) -> str:
        return str(self.path)

    def _read(self) -> str:
        if not self.path.exists():
            raise FileNotFoundError(f"feed file not found: {self.path}")
        if self.path.suffix == ".gz":
            with gzip.open(self.path, "rt", encoding="utf-8",
                           errors="replace") as handle:
                return handle.read()
        return self.path.read_text(encoding="utf-8", errors="replace")


class HttpFeedSource(FeedSource):
    """Fetches indicators over HTTP(S).

    `auth_key` is sent as an `Auth-Key` header, which is how abuse.ch's API
    endpoints expect it. Authentication became mandatory for URLhaus on
    30 June 2025; feeds that need no key simply leave it unset.

    **Except when the URL already carries the credential.** abuse.ch's bulk
    export URLs embed the key in the path, and those endpoints reject a
    request that *also* presents an `Auth-Key` header — the same URL that
    returns 200 with no header returns 401 with one. So the header is added
    only when the key is not already part of the URL. Sending a credential
    twice is not more authenticated; here it is less.
    """

    def __init__(self, name: str, url: str, fmt: str = "domains",
                 auth_key: str | None = None, timeout: float = 30.0,
                 max_bytes: int = 64 * 1024 * 1024) -> None:
        super().__init__(name, fmt)
        self.url = url
        self.auth_key = auth_key
        self.timeout = timeout
        self.max_bytes = max_bytes

    @property
    def source(self) -> str:
        return self.url

    @property
    def key_is_in_url(self) -> bool:
        """Whether the configured URL already carries the credential.

        Compared against the configured key rather than pattern-matched, so
        this cannot misfire on a URL that merely looks like it holds one.
        Nothing is logged or returned that could reveal the key itself.
        """
        return bool(self.auth_key) and self.auth_key in self.url

    def build_request(self) -> urllib.request.Request:
        """Assemble the request. Separated so it is testable without network."""
        request = urllib.request.Request(
            self.url, headers={"User-Agent": USER_AGENT})
        if self.auth_key and not self.key_is_in_url:
            request.add_header("Auth-Key", self.auth_key)
        return request

    def _read(self) -> str:
        request = self.build_request()

        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            # Bounded read: a feed that unexpectedly serves gigabytes must not
            # exhaust memory on a laptop.
            raw = response.read(self.max_bytes + 1)
            if len(raw) > self.max_bytes:
                raise ValueError(
                    f"feed exceeded {self.max_bytes} bytes; refusing to load")
            if response.headers.get("Content-Encoding") == "gzip" or \
                    self.url.endswith(".gz"):
                raw = gzip.decompress(raw)

        return raw.decode("utf-8", errors="replace")


# -- named sources --------------------------------------------------------

#: A no-authentication phishing domain list, one domain per line. Verified
#: reachable (HTTP 200) during development. It is the default because the
#: public GitHub repository this project must ship (Final Viva, 10 marks)
#: has to be runnable by a reviewer who has no credentials for anything.
DEFAULT_FEED_URL = (
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
    "master/phishing-domains-ACTIVE.txt"
)


def build_http_source(name: str, url: str, fmt: str = "domains",
                      auth_key: str | None = None) -> HttpFeedSource:
    return HttpFeedSource(name=name, url=url, fmt=fmt, auth_key=auth_key)


def build_urlhaus_source(url: str, auth_key: str, fmt: str = "hosts") -> HttpFeedSource:
    """URLhaus source.

    The endpoint is NOT hardcoded, deliberately. abuse.ch's export URLs are
    per-account since the June 2025 authentication change, and I have not
    verified the current bulk-download URL against their documentation. An
    invented URL would fail silently at 03:00 the night before a review, so
    the URL is supplied by configuration and copied by the operator from
    their own abuse.ch account page.

    Status of the exact endpoint: NOT VERIFIED. Auth-Key requirement:
    VERIFIED from abuse.ch documentation.
    """
    if not url:
        raise ValueError(
            "a URLhaus export URL must be supplied via DNSF_FEED_URL; copy it "
            "from your account at https://auth.abuse.ch/")
    if not auth_key:
        raise ValueError(
            "URLhaus requires an Auth-Key since 30 June 2025; set "
            "DNSF_FEED_AUTH_KEY. Get one free at https://auth.abuse.ch/")
    return HttpFeedSource(name="urlhaus", url=url, fmt=fmt, auth_key=auth_key)
