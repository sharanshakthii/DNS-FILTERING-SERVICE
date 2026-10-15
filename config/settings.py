"""
Configuration.

Environment variables with defaults, no third-party parser. Stage 2 has no
dependencies at all, which means the proxy can be demonstrated on a machine
where `pip install` failed — worth having on review day.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false, got {raw!r}")


@dataclass(frozen=True)
class Settings:
    listen_host: str = "127.0.0.1"
    listen_port: int = 5353          # unprivileged; 53 needs root
    upstream_host: str = "1.1.1.1"
    upstream_port: int = 53
    upstream_timeout: float = 2.0
    workers: int = 16
    log_level: str = "INFO"
    log_file: str = ""               # empty means stdout only

    # -- storage (Stage 3) -------------------------------------------------
    db_enabled: bool = True
    db_path: str = "data/prj112.sqlite3"
    db_queue_size: int = 10000       # records buffered before we start dropping
    db_batch_size: int = 50
    db_flush_interval: float = 0.5   # seconds
    client_salt: str = "prj112-dev-salt"

    # -- detection engine (Stage 4) ---------------------------------------
    #: Comma-separated module names from engine.modules.REGISTRY.
    #: Empty means the Stage 2 AllowAllEngine, so the default behaviour of
    #: the verified proxy is unchanged until this is set deliberately.
    engine_modules: str = ""
    engine_budget_ms: float = 50.0

    # -- threat intelligence feeds (Stage 5) ------------------------------
    feed_name: str = "phishing-domains"
    feed_url: str = ""            # empty uses feeds.sources.DEFAULT_FEED_URL
    feed_file: str = ""           # a local snapshot wins over the network
    feed_format: str = "domains"  # domains | hosts | urls
    feed_auth_key: str = ""       # required by URLhaus since 30 June 2025
    feed_extra_defaults: bool = True  # add the extra public feeds when unconfigured
    feed_refresh_s: float = 3600.0
    feed_stale_after_s: float = 86400.0
    feed_match_parents: bool = True
    feed_parent_score: float = 1.0

    # -- newly registered / observed domains (Stage 6) --------------------
    nrd_url: str = ""             # no default: no verified public NRD list
    nrd_file: str = ""            # a local snapshot wins over the network
    nrd_format: str = "domains"
    nrd_auth_key: str = ""
    nrd_refresh_s: float = 21600.0
    nrd_new_within_s: float = 7 * 24 * 3600.0
    nrd_established_after_s: float = 30 * 24 * 3600.0
    nrd_max_tracked: int = 200_000

    # -- risk aggregation (Stage 7) ---------------------------------------
    aggregator_weights: str = ""          # e.g. "ti=1.0,nrd=0.4"
    aggregator_flag_at: float = 0.5
    aggregator_block_at: float = 0.8
    aggregator_default_weight: float = 0.5
    #: Decisions are always computed and recorded. This governs whether a
    #: BLOCK is acted on. Default false: Stage 8 is where enforcement lands.
    aggregator_ti_decisive: bool = True   # a feed hit sets the floor of the score
    aggregator_enforce: bool = False
    aggregator_fail_mode: str = "open"    # open | closed (requirement SR3)

    # -- typosquat / brand impersonation (Stage 12) -----------------------
    #: Empty by default: the module has no opinion until brands are given,
    #: and there is no defensible built-in list of "the brands that matter".
    typosquat_brands: str = ""
    #: Registrable domains that are the brands' own, always scored 0.0.
    typosquat_official_domains: str = ""
    # -- web authentication (Stage 17) ------------------------------------
    #: Both must be set for authentication to be enabled. With no hash the
    #: API runs open and logs a warning at startup, so an existing developer
    #: is not locked out of their own project by an upgrade.
    auth_username: str = ""
    #: pbkdf2_sha256$<iterations>$<salt>$<key>, from tools/make_password_hash.py.
    #: Never a plaintext password, and never committed.
    auth_password_hash: str = ""
    auth_session_ttl_s: float = 8 * 3600.0
    #: Set true behind TLS so the session cookie is not sent over HTTP.
    auth_cookie_secure: bool = False

    # -- beaconing / periodicity (Stage 14) -------------------------------
    #: One hour: long enough to hold several intervals of a typical check-in
    #: period, short enough that a domain queried steadily all day does not
    #: dominate. An engineering convention, tuned in Stage 16.
    beacon_window_s: float = 3600.0
    #: Four observations give three intervals — the fewest from which a
    #: standard deviation means anything.
    beacon_min_observations: int = 4
    #: Intervals needed for full confidence in the regularity measurement.
    beacon_evidence_intervals: int = 8
    #: Mean intervals below this are treated as a burst, not a beacon.
    beacon_min_interval_s: float = 5.0
    #: Scope observations to one client as well as the domain. Off by
    #: default: on a small test network per-domain history is the useful
    #: view, and it keeps API /lookup meaningful.
    beacon_per_client: bool = False

    # -- registration age via RDAP -----------------------------------------
    #: Empty uses engine.modules.rdap.DEFAULT_BASE_URL (rdap.org).
    rdap_base_url: str = ""
    rdap_new_within_s: float = 30 * 24 * 3600.0
    rdap_established_after_s: float = 365 * 24 * 3600.0
    rdap_timeout_s: float = 6.0

    # -- operator allowlist ------------------------------------------------
    #: Comma-separated domains that are always ALLOW (a name and everything
    #: beneath it). The false-positive override; see engine/allowlist.py.
    allowlist: str = ""
    #: File with one domain per line, '#' comments allowed. Merged with the
    #: list above.
    allowlist_file: str = ""

    # -- DGA detection (Stage 13) -----------------------------------------
    #: Exported JSON artifact produced by tools/train_dga.py.
    dga_model_path: str = "models/dga/dga_model.json"
    #: Labels the score in the evidence only; the raw probability is always
    #: what the aggregator receives.
    dga_threshold: float = 0.5

    typosquat_keywords: str = (
        "apk,login,signin,verify,verification,secure,security,account,accounts,"
        "support,update,billing,payment,wallet,download,free,gift,recovery,alert")

    # -- enforcement (Stage 8) --------------------------------------------
    #: How an enforced BLOCK is expressed on the wire.
    #: nxdomain | sinkhole | refused. See README for the trade-offs.
    block_response: str = "nxdomain"
    block_sinkhole_ipv4: str = "0.0.0.0"
    block_sinkhole_ipv6: str = "::"
    block_ttl: int = 60

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            listen_host=os.environ.get("DNSF_LISTEN_HOST", cls.listen_host),
            listen_port=_int("DNSF_LISTEN_PORT", cls.listen_port),
            upstream_host=os.environ.get("DNSF_UPSTREAM_HOST", cls.upstream_host),
            upstream_port=_int("DNSF_UPSTREAM_PORT", cls.upstream_port),
            upstream_timeout=_float("DNSF_UPSTREAM_TIMEOUT", cls.upstream_timeout),
            workers=_int("DNSF_WORKERS", cls.workers),
            log_level=os.environ.get("DNSF_LOG_LEVEL", cls.log_level).upper(),
            log_file=os.environ.get("DNSF_LOG_FILE", cls.log_file),
            db_enabled=_bool("DNSF_DB_ENABLED", cls.db_enabled),
            db_path=os.environ.get("DNSF_DB_PATH", cls.db_path),
            db_queue_size=_int("DNSF_DB_QUEUE_SIZE", cls.db_queue_size),
            db_batch_size=_int("DNSF_DB_BATCH_SIZE", cls.db_batch_size),
            db_flush_interval=_float("DNSF_DB_FLUSH_INTERVAL",
                                     cls.db_flush_interval),
            client_salt=os.environ.get("DNSF_CLIENT_SALT", cls.client_salt),
            engine_modules=os.environ.get("DNSF_ENGINE_MODULES",
                                          cls.engine_modules),
            engine_budget_ms=_float("DNSF_ENGINE_BUDGET_MS",
                                    cls.engine_budget_ms),
            feed_name=os.environ.get("DNSF_FEED_NAME", cls.feed_name),
            feed_url=os.environ.get("DNSF_FEED_URL", cls.feed_url),
            feed_file=os.environ.get("DNSF_FEED_FILE", cls.feed_file),
            feed_format=os.environ.get("DNSF_FEED_FORMAT", cls.feed_format),
            feed_auth_key=os.environ.get("DNSF_FEED_AUTH_KEY",
                                         cls.feed_auth_key),
            feed_extra_defaults=_bool("DNSF_FEED_EXTRA_DEFAULTS",
                                      cls.feed_extra_defaults),
            feed_refresh_s=_float("DNSF_FEED_REFRESH_S", cls.feed_refresh_s),
            feed_stale_after_s=_float("DNSF_FEED_STALE_AFTER_S",
                                      cls.feed_stale_after_s),
            feed_match_parents=_bool("DNSF_FEED_MATCH_PARENTS",
                                     cls.feed_match_parents),
            feed_parent_score=_float("DNSF_FEED_PARENT_SCORE",
                                     cls.feed_parent_score),
            nrd_url=os.environ.get("DNSF_NRD_URL", cls.nrd_url),
            nrd_file=os.environ.get("DNSF_NRD_FILE", cls.nrd_file),
            nrd_format=os.environ.get("DNSF_NRD_FORMAT", cls.nrd_format),
            nrd_auth_key=os.environ.get("DNSF_NRD_AUTH_KEY", cls.nrd_auth_key),
            nrd_refresh_s=_float("DNSF_NRD_REFRESH_S", cls.nrd_refresh_s),
            nrd_new_within_s=_float("DNSF_NRD_NEW_WITHIN_S",
                                    cls.nrd_new_within_s),
            nrd_established_after_s=_float("DNSF_NRD_ESTABLISHED_AFTER_S",
                                           cls.nrd_established_after_s),
            nrd_max_tracked=_int("DNSF_NRD_MAX_TRACKED", cls.nrd_max_tracked),
            aggregator_weights=os.environ.get("DNSF_AGGREGATOR_WEIGHTS",
                                              cls.aggregator_weights),
            aggregator_flag_at=_float("DNSF_AGGREGATOR_FLAG_AT",
                                      cls.aggregator_flag_at),
            aggregator_block_at=_float("DNSF_AGGREGATOR_BLOCK_AT",
                                       cls.aggregator_block_at),
            aggregator_default_weight=_float("DNSF_AGGREGATOR_DEFAULT_WEIGHT",
                                             cls.aggregator_default_weight),
            aggregator_ti_decisive=_bool("DNSF_AGGREGATOR_TI_DECISIVE",
                                         cls.aggregator_ti_decisive),
            aggregator_enforce=_bool("DNSF_AGGREGATOR_ENFORCE",
                                     cls.aggregator_enforce),
            aggregator_fail_mode=os.environ.get("DNSF_AGGREGATOR_FAIL_MODE",
                                                cls.aggregator_fail_mode),
            typosquat_brands=os.environ.get("DNSF_TYPOSQUAT_BRANDS",
                                            cls.typosquat_brands),
            typosquat_official_domains=os.environ.get(
                "DNSF_TYPOSQUAT_OFFICIAL_DOMAINS",
                cls.typosquat_official_domains),
            typosquat_keywords=os.environ.get("DNSF_TYPOSQUAT_KEYWORDS",
                                              cls.typosquat_keywords),
            dga_model_path=os.environ.get("DNSF_DGA_MODEL_PATH",
                                          cls.dga_model_path),
            dga_threshold=_float("DNSF_DGA_THRESHOLD", cls.dga_threshold),
            auth_username=os.environ.get("DNSF_AUTH_USERNAME",
                                         cls.auth_username),
            auth_password_hash=os.environ.get("DNSF_AUTH_PASSWORD_HASH",
                                              cls.auth_password_hash),
            auth_session_ttl_s=_float("DNSF_AUTH_SESSION_TTL_S",
                                      cls.auth_session_ttl_s),
            auth_cookie_secure=_bool("DNSF_AUTH_COOKIE_SECURE",
                                     cls.auth_cookie_secure),
            beacon_window_s=_float("DNSF_BEACON_WINDOW_SECONDS",
                                   cls.beacon_window_s),
            beacon_min_observations=_int("DNSF_BEACON_MIN_OBSERVATIONS",
                                         cls.beacon_min_observations),
            beacon_evidence_intervals=_int("DNSF_BEACON_EVIDENCE_INTERVALS",
                                           cls.beacon_evidence_intervals),
            beacon_min_interval_s=_float("DNSF_BEACON_MIN_INTERVAL_SECONDS",
                                         cls.beacon_min_interval_s),
            beacon_per_client=_bool("DNSF_BEACON_PER_CLIENT",
                                    cls.beacon_per_client),
            rdap_base_url=os.environ.get("DNSF_RDAP_BASE_URL",
                                         cls.rdap_base_url),
            rdap_new_within_s=_float("DNSF_RDAP_NEW_WITHIN_S",
                                     cls.rdap_new_within_s),
            rdap_established_after_s=_float("DNSF_RDAP_ESTABLISHED_AFTER_S",
                                            cls.rdap_established_after_s),
            rdap_timeout_s=_float("DNSF_RDAP_TIMEOUT_S", cls.rdap_timeout_s),
            allowlist=os.environ.get("DNSF_ALLOWLIST", cls.allowlist),
            allowlist_file=os.environ.get("DNSF_ALLOWLIST_FILE",
                                          cls.allowlist_file),
            block_response=os.environ.get("DNSF_BLOCK_RESPONSE",
                                          cls.block_response).lower(),
            block_sinkhole_ipv4=os.environ.get("DNSF_BLOCK_SINKHOLE_IPV4",
                                               cls.block_sinkhole_ipv4),
            block_sinkhole_ipv6=os.environ.get("DNSF_BLOCK_SINKHOLE_IPV6",
                                               cls.block_sinkhole_ipv6),
            block_ttl=_int("DNSF_BLOCK_TTL", cls.block_ttl),
        )

    @property
    def module_names(self) -> list[str]:
        """Parsed module list, empty when the engine is not configured."""
        return [n.strip() for n in self.engine_modules.split(",") if n.strip()]
