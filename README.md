# PRJ_112 — DNS Filtering Service Using Threat Intelligence Feeds and AI/ML Techniques

Stage 1 (environment + skeleton) and Stage 2 (proxy hardening) of the 18-stage
implementation plan.

## What works right now

- UDP DNS proxy that parses queries safely and forwards them upstream
- Fresh random transaction ID upstream; client's ID restored on the way back
- Upstream reply validated against the outstanding question before it is trusted
- Malformed packets answered with FORMERR instead of crashing a worker
- Upstream timeout answered with SERVFAIL
- One JSON log line per query with a per-phase latency breakdown
- **Stage 3:** every decision persisted to SQLite by a background writer,
  with the client address pseudonymised and the latency breakdown preserved
- **Stage 4:** a module framework with per-module timing, fault isolation, a
  latency budget, and configuration-driven ablation — plus a null reference
  module. No detection logic yet.
- **Stage 5:** threat-intelligence feed ingestion with refresh, staleness
  tracking, an in-memory indicator cache, and a TI detection module
- **Stage 6:** domain-age scoring — first-seen observation tracking with a
  cold-start guard, an optional external NRD list, and per-registration ages
- **Stage 7:** risk aggregation — a weighted mean over contributing modules,
  verdict bands, and a persisted decision trace
- **Stage 8:** enforcement — a blocked query is answered locally and never
  forwarded upstream. **Disabled by default**; observation mode records the
  decision and forwards normally.
- **Stage 9:** end-to-end checkpoint (`tools/checkpoint.py`) — one repeatable
  run that verifies Stages 1-8 work together and reports PASS/FAIL per link
- **Stage 10:** FastAPI backend over the stored decisions, read-only against
  the database, with a live `/lookup` and an ablation `/mode` surface
- **Stage 11:** DNS filtering console — one HTML file served by the API,
  showing live decisions and the weighted derivation behind each one
- **Stage 12:** typosquat / brand-impersonation module — deterministic
  lexical scoring against a configured brand list, with explainable evidence
- **Stage 13:** DGA detection — a scikit-learn logistic regression trained
  offline on lexical features and exported to JSON, so inference in the proxy
  needs no framework
- **Stage 14:** DNS beaconing — periodicity scoring over the query history
  the resolver has already persisted
- **Stage 15:** hybrid integration and explainable evidence — a distinct
  `unavailable` status, and a human-readable summary of every decision
- **Stage 16:** evaluation and ablation — an offline harness that replays a
  labelled dataset through the real engine and reports what each
  configuration detects
- **Stage 17:** authentication — backend-enforced sessions in front of every
  endpoint that exposes stored data
- **Stage 18:** latency measurement — per-module and end-to-end distributions,
  answering RQ2

## What does not work yet, and is not pretended to

There is **no filtering**. The decision engine is `AllowAllEngine`, which allows
every query and is named so nobody mistakes it for detection. Threat
intelligence lands in Stage 5, NRD in Stage 6, risk aggregation in Stage 7, and
blocking in Stage 8. No detection numbers exist yet: **NOT YET MEASURED.**

The `evidence` table fills only if `DNSF_ENGINE_MODULES` is set. With the
default (empty) it stays empty, because the allow-all engine produces no
evidence. The `null` module produces an evidence row that says it detects
nothing — useful for measuring engine overhead, useless as detection.

## Requirements

Python 3.12. Stage 2 needs no third-party packages at runtime; `pytest` is only
needed for the test suite.

```bash
cd prj112
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python -m proxy.dns_proxy
```

Defaults: listens on `127.0.0.1:5353`, forwards to `1.1.1.1:53`.

Configuration is by environment variable:

| Variable | Default | Notes |
|---|---|---|
| `DNSF_LISTEN_HOST` | `127.0.0.1` | |
| `DNSF_LISTEN_PORT` | `5353` | Port 53 needs root; use 5353 for development |
| `DNSF_UPSTREAM_HOST` | `1.1.1.1` | |
| `DNSF_UPSTREAM_PORT` | `53` | |
| `DNSF_UPSTREAM_TIMEOUT` | `2.0` | Seconds |
| `DNSF_WORKERS` | `16` | Thread pool size |
| `DNSF_LOG_LEVEL` | `INFO` | |
| `DNSF_LOG_FILE` | *(unset)* | Also write JSON lines to this file |
| `DNSF_DB_ENABLED` | `true` | Set to `false` to run with no database |
| `DNSF_DB_PATH` | `data/prj112.sqlite3` | Created automatically |
| `DNSF_DB_QUEUE_SIZE` | `10000` | Records buffered before dropping starts |
| `DNSF_DB_BATCH_SIZE` | `50` | Rows per write transaction |
| `DNSF_DB_FLUSH_INTERVAL` | `0.5` | Seconds between forced flushes |
| `DNSF_CLIENT_SALT` | `prj112-dev-salt` | Salt for the client-address hash |
| `DNSF_ENGINE_MODULES` | *(empty)* | Comma-separated module names. Empty keeps the Stage 2 allow-all engine |
| `DNSF_ENGINE_BUDGET_MS` | `50.0` | Total time modules may spend per query |
| `DNSF_FEED_NAME` | `phishing-domains` | Label used in evidence rows |
| `DNSF_FEED_URL` | *(built-in)* | Feed URL; required for URLhaus |
| `DNSF_FEED_FILE` | *(unset)* | Local snapshot; wins over the network |
| `DNSF_FEED_FORMAT` | `domains` | `domains`, `hosts`, or `urls` |
| `DNSF_FEED_AUTH_KEY` | *(unset)* | Required by URLhaus since 30 June 2025 |
| `DNSF_FEED_REFRESH_S` | `3600` | 0 disables periodic refresh |
| `DNSF_FEED_STALE_AFTER_S` | `86400` | Age at which evidence is flagged stale |
| `DNSF_FEED_MATCH_PARENTS` | `true` | Match subdomains of a listed domain |
| `DNSF_FEED_PARENT_SCORE` | `1.0` | Score for a parent (inferred) match |
| `DNSF_NRD_URL` | *(unset)* | External NRD list; no default exists |
| `DNSF_NRD_FILE` | *(unset)* | Local NRD snapshot; wins over the network |
| `DNSF_NRD_NEW_WITHIN_S` | `604800` | Age (7d) at or below which score is 1.0 |
| `DNSF_NRD_ESTABLISHED_AFTER_S` | `2592000` | Age (30d) at or above which score is 0.0 |
| `DNSF_NRD_MAX_TRACKED` | `200000` | First-seen store capacity |
| `DNSF_AGGREGATOR_WEIGHTS` | `ti=1.0,nrd=0.4` | Per-module weights |
| `DNSF_AGGREGATOR_FLAG_AT` | `0.5` | Score at or above which a query is FLAG |
| `DNSF_AGGREGATOR_BLOCK_AT` | `0.8` | Score at or above which policy says BLOCK |
| `DNSF_AGGREGATOR_DEFAULT_WEIGHT` | `0.5` | Weight for an unlisted module |
| `DNSF_AGGREGATOR_ENFORCE` | `false` | Whether a BLOCK is acted on (Stage 8) |
| `DNSF_AGGREGATOR_FAIL_MODE` | `open` | `open` or `closed` (requirement SR3) |
| `DNSF_TYPOSQUAT_BRANDS` | *(empty)* | Comma-separated brand names |
| `DNSF_TYPOSQUAT_OFFICIAL_DOMAINS` | *(empty)* | Registrable domains always scored 0.0 |
| `DNSF_TYPOSQUAT_KEYWORDS` | apk, login, verify, … | Suspicious words paired with a brand |
| `DNSF_DGA_MODEL_PATH` | `models/dga/dga_model.json` | Exported classifier artifact |
| `DNSF_DGA_THRESHOLD` | `0.5` | Labels the score in the evidence; never changes it |
| `DNSF_BEACON_WINDOW_SECONDS` | `3600` | Analysis window |
| `DNSF_BEACON_MIN_OBSERVATIONS` | `4` | Below this, no score is produced |
| `DNSF_BEACON_EVIDENCE_INTERVALS` | `8` | Intervals for full confidence |
| `DNSF_BEACON_MIN_INTERVAL_SECONDS` | `5` | Below this a run is a burst, not a beacon |
| `DNSF_BEACON_PER_CLIENT` | `false` | Scope history to one client as well as the domain |
| `DNSF_AUTH_USERNAME` | *(empty)* | Console username; auth is off unless set |
| `DNSF_AUTH_PASSWORD_HASH` | *(empty)* | PBKDF2 hash from `tools/make_password_hash.py` |
| `DNSF_AUTH_SESSION_TTL_S` | `28800` | Session lifetime, 8 hours |
| `DNSF_AUTH_COOKIE_SECURE` | `false` | Set true behind TLS |
| `DNSF_BLOCK_RESPONSE` | `nxdomain` | `nxdomain`, `sinkhole`, or `refused` |
| `DNSF_BLOCK_SINKHOLE_IPV4` | `0.0.0.0` | Address returned in sinkhole mode |
| `DNSF_BLOCK_SINKHOLE_IPV6` | `::` | AAAA address returned in sinkhole mode |
| `DNSF_BLOCK_TTL` | `60` | TTL on a synthesised sinkhole answer |
| `DNSF_FEED_EXTRA_DEFAULTS` | `true` | With no feed configured, also load four more no-auth feeds |
| `DNSF_AGGREGATOR_TI_DECISIVE` | `true` | A TI listing sets the score to 1.0; `false` is formula (2) exactly |
| `DNSF_RDAP_BASE_URL` | `https://rdap.org/domain/` | RDAP service for registration age |
| `DNSF_RDAP_NEW_WITHIN_S` | `2592000` | Registered within 30 days scores 1.0 |
| `DNSF_RDAP_ESTABLISHED_AFTER_S` | `31536000` | Registered over a year ago scores 0.0 |
| `DNSF_RDAP_TIMEOUT_S` | `6.0` | Per-lookup timeout (background, never on the query path) |
| `DNSF_TCP_ENABLED` | `true` | DNS over TCP on the same port (RFC 7766) |
| `DNSF_TCP_IDLE_TIMEOUT` | `10.0` | Seconds a TCP connection may idle between queries |
| `DNSF_TCP_MAX_CONNECTIONS` | `64` | Concurrent TCP connections; extras are closed |
| `DNSF_PSL_MODE` | `off` | `off` (last two labels, as published), `icann`, or `full` (incl. hosting platforms) |
| `DNSF_ALLOWLIST` | *(empty)* | Comma-separated domains always allowed, with subdomains |
| `DNSF_ALLOWLIST_FILE` | *(unset)* | Same, one domain per line, `#` comments allowed |

## Verify

```bash
dig @127.0.0.1 -p 5353 example.com
dig @127.0.0.1 -p 5353 AAAA cloudflare.com
```

Expected: a normal answer, and a log line on stdout like

```json
{"ts":"...","level":"INFO","logger":"proxy","event":"query","client":"127.0.0.1",
 "qname":"example.com","qtype":"A","verdict":"ALLOW","rcode":"NOERROR","score":0.0,
 "evidence":[],"latency_ms":{"parse":0.036,"decide":0.002,"upstream":0.195,"total":0.303},
 "added_latency_ms":0.108,"engine":"allow-all"}
```

`added_latency_ms` is total minus upstream — the cost this proxy adds. That
figure is what RQ2 is about, so it is captured from the first stage rather than
retrofitted later.

## Test

```bash
python -m pytest tests/ -q
```

Expected: **1066 passed, 2 skipped** (the paper's 938, plus the 128 added
since: see the last six rows of the table).

| File | Tests | Covers |
|---|---|---|
| `test_packet.py` | 32 | Packet parsing and response building |
| `test_proxy_integration.py` | 10 | End-to-end resolution against a stub upstream |
| `test_conn_reset.py` | 5 | Windows `ConnectionResetError` handling |
| `test_storage.py` | 23 | Schema, inserts, atomicity, async writer |
| `test_proxy_persistence.py` | 9 | Proxy plus storage, and storage failure isolation |
| `test_engine.py` | 40 | Module contract, fault isolation, budget, ablation |
| `test_feeds.py` | 62 | Feed parsing, indicator cache, TI module, feed_state |
| `test_servfail_recording.py` | 6 | Evidence and latency attribution on SERVFAIL |
| `test_nrd.py` | 33 | First-seen store, age curve, cold-start guard |
| `test_module_registration.py` | 11 | Every module is reachable by its configured name |
| `test_aggregator.py` | 52 | Weighted mean, verdict bands, decision trace, migration |
| `test_enforcement.py` | 31 | Block responses, upstream isolation, both modes |
| `test_checkpoint.py` | 20 | The Stage 9 harness, including that it can fail |
| `test_api.py` | 82 | All seven endpoints, privacy, empty and unreadable DB |
| `test_dashboard.py` | 42 | The page is served, uses only real API data |
| `test_typosquat.py` | 73 | Brand safety, the detections, evidence, ablation |
| `test_dga.py` | 99 | Features, dataset, artifact, inference, training |
| `test_beaconing.py` | 77 | Temporal features, history store, index, scoring |
| `test_explainability.py` | 42 | Unavailable status, contributions, summaries |
| `test_experiments.py` | 53 | Metrics, harness, ablation, sweeps, artifacts |
| `test_auth.py` | 57 | Hashing, sessions, backend enforcement, logout |
| `test_latency.py` | 26 | Percentiles, warm-up, phase collection, runner shape |
| `test_improvements.py` | 29 | RDAP age, allowlist, device alerts, extra feeds, decisive TI |
| `test_real_eval.py` | 9 | Real-data evaluator, checksum refusal, collection-time ages |
| `test_psl.py` | 38 | Public Suffix List algorithm, incl. the PSL project's own vectors |
| `test_psl_modes.py` | 23 | `DNSF_PSL_MODE` in typosquat, TI, nrd and rdap; `off` unchanged |
| `test_tcp.py` | 16 | DNS over TCP both ways, TC fallback, UDP size limit, connection limits |
| `test_dga_v2.py` | 13 | DGA v2 features, depth invariance, v1 still the published model |

No internet access required — a stub upstream runs on loopback.

## Acceptance criteria for Stage 2

| Criterion | Evidence |
|---|---|
| Resolves correctly | `test_resolves_a_query_end_to_end` |
| Malformed input does not crash | `test_random_junk_never_crashes`, `test_proxy_survives_a_flood_of_junk` |
| TXID mismatch rejected | `test_mismatched_upstream_reply_is_not_passed_through` |
| Latency logged | `test_log_record_is_valid_json_with_latency_breakdown` |
| Client ID not leaked upstream | `test_upstream_sees_a_different_txid` |
| Concurrent queries not crossed | `test_handles_concurrent_queries` |

## Troubleshooting

**`PermissionError` on bind** — ports under 1024 need root. Use
`DNSF_LISTEN_PORT=5353`, or `sudo setcap 'cap_net_bind_service=+ep' $(which python3)`.

**`Address already in use`** — something else holds the port. Check with
`ss -ulpn | grep 5353` (Linux) or `netstat -ano | findstr 5353` (Windows).

**`dig` hangs, SERVFAIL in the log** — the upstream is unreachable. Test the
upstream directly: `dig @1.1.1.1 example.com`. On a campus network that blocks
outbound port 53, set `DNSF_UPSTREAM_HOST` to the resolver in
`/etc/resolv.conf`.

**Tests fail with a bind error** — a previous run did not shut down. The tests
bind to port 0 so this should not happen; if it does, check for stray
`python -m proxy.dns_proxy` processes.

## Storage (Stage 3)

Four tables: `queries`, `decisions`, `evidence`, `feed_state`. One query row and
one decision row per DNS query; evidence rows arrive from Stage 5 onward.

Writes are **asynchronous**. The query path puts a record on a bounded queue and
returns; a background thread does the database work. This is not an optimisation
— a synchronous write would be counted inside the measured query latency and
would make every figure RQ2 reports wrong. Under overload, records are dropped
rather than blocking resolution, and the drop count is reported at shutdown so a
run with drops can be discarded instead of trusted.

Client addresses are stored as a salted SHA-256 digest truncated to 16 hex
characters. This is pseudonymisation, not anonymisation: the IPv4 space is small
enough to brute-force if the salt leaks. The report must say so.

To inspect the database, use DB Browser for SQLite (https://sqlitebrowser.org)
and open `data/prj112.sqlite3`.

## Threat intelligence (Stage 5)

The TI module scores 1.0 when the queried name, or a parent of it, appears on
a loaded feed. Feeds are fetched into an in-memory set; lookup never touches
the network or the database, because a round trip per query would dominate
the latency figures RQ2 reports.

**URLhaus requires an Auth-Key.** abuse.ch made authentication mandatory on
30 June 2025. Get a free key at https://auth.abuse.ch/, then set
`DNSF_FEED_AUTH_KEY` and `DNSF_FEED_URL` to your personal export URL. The
default feed is a no-authentication phishing domain list so that the public
GitHub repository is runnable by a reviewer with no credentials.

**Known false-positive source.** Parent matching uses a label-count floor,
not a public-suffix list. A feed listing a shared-hosting domain will match
every customer under it. This is the collateral damage Griffioen et al.
(ACNS 2020) documented at IP level, reproduced at name level. It is reported
as a limitation, not solved.

## Domain age (Stage 6)

The `nrd` module scores by how new a domain is. Bilge et al. (NDSS 2011)
found most detected malicious domains lived under two days, which is the
window a threat-intelligence feed structurally cannot cover: a feed lists a
domain only after somebody has reported it.

**Two different quantities, never conflated.** With no external list
configured, the age reported is *observation* age at this resolver
(`age_source: "first_seen"`) — a proxy for registration age, not a
measurement of it. With `DNSF_NRD_FILE` or `DNSF_NRD_URL` set, a registry-
derived list takes precedence and is labelled `age_source: "nrd_list"`. The
report must not describe observation age as registration age.

**No default NRD list URL.** ICANN CZDS needs an approved account per TLD.
A public mirror checked during development returned HTTP 404 — which is
exactly how an invented default fails: silently, later. Supply your own.

**Cold-start guard.** A resolver that has just started has seen nothing, so
every domain would look new. The module refuses to score until its
observation window exceeds the age threshold, and reports `warming_up: true`
with the remaining time. Out of the box that is seven days.

**Ages are per registration**, not per hostname: `www.example.com` and
`mail.example.com` share one date. Same public-suffix limitation as the TI
module's parent matching.

## Risk aggregation (Stage 7)

Module scores are combined by a **weighted mean over contributing modules**,
compared against two thresholds, and recorded with a full derivation.

**The method is not novel.** Combining weighted detector scores against a
threshold is standard in commercial DNS reputation systems and in the
literature back to Antonakakis et al. (Notos, USENIX Security 2010). It is
used here because it is transparent: every term is separately reportable. The
weights are configured defaults — **not learned, not optimised**. Stage 16 is
where they are tuned against measured false positives.

**A failed module is never a zero.** Modules that errored, returned nonsense,
were skipped or disabled are excluded from both numerator and denominator.
When modules are registered but none produced a usable score, the verdict is
`UNKNOWN`, not `ALLOW` — "we could not find out" and "this is fine" are
different claims.

**Deciding is not enforcing.** The policy verdict is always computed and
stored. `DNSF_AGGREGATOR_ENFORCE` (default `false`) governs whether a BLOCK
is acted on, so the system can be measured against real traffic before it is
trusted to interrupt it. `DNSF_AGGREGATOR_FAIL_MODE` is the explicit
fail-open/fail-closed choice required by SR3.

**Known property.** Because the mean normalises by contributing weight, a
module configured as the only enabled signal produces its own score
regardless of its weight. The weighting protects against a weak signal
dominating a hybrid configuration, not against one being used alone.

Storage moved to **schema v2**: `decisions.explanation_json` holds the
derivation. Existing v1 databases are migrated in place by `ALTER TABLE`,
with rows preserved.

## Enforcement (Stage 8)

Stage 7 decides; Stage 8 acts. The two are deliberately separate: the policy
verdict is always computed and recorded, and `DNSF_AGGREGATOR_ENFORCE`
(default **false**) governs whether a BLOCK is acted on. In observation mode a
BLOCK is stored as a BLOCK with `enforcement.applied: false`, and the query is
forwarded normally — so a run can be measured against real traffic before the
system is trusted to interrupt it.

An enforced block is answered locally and **returns before the upstream call**,
so the queried name is not leaked to the upstream resolver.

**Block representations.** `DNSF_BLOCK_RESPONSE`:

- **`nxdomain`** (default) — the cleanest failure; the client gives up
  immediately without needing another server. This is the action RPZ
  expresses as `CNAME .`. **Caveat:** RFC 8020 states NXDOMAIN means the
  queried name *and every name beneath it* do not exist, and caching
  resolvers SHOULD treat the whole subtree as unreachable. Blocking
  `bad.example.com` can therefore suppress `good.bad.example.com` downstream.
- **`sinkhole`** — answers with a non-routable address (0.0.0.0 / ::), which
  suits a block-page deployment. Known failure mode: a client may connect to
  itself, reaching a local service instead of nothing. Only A and AAAA can be
  sinkholed; other types fall back to NXDOMAIN, and the log records the
  representation actually sent, never the one configured.
- **`refused`** — declines to answer without asserting the name does not
  exist. Many stub resolvers treat REFUSED as a server fault and fail over to
  another resolver, defeating the block.

**FLAG is never escalated to BLOCK**, with or without enforcement.

**This is not production-safe and not spoof-proof.** A client that speaks
DoH or DoT to a third party never reaches this resolver, so the block does
not apply. TXID randomisation raises the bar for off-path spoofing only. No
DNSSEC validation is performed, and no Extended DNS Error (RFC 8914) is
emitted to tell the client it was filtered — that is future scope.

## End-to-end checkpoint (Stage 9)

```bash
python tools/checkpoint.py
```

Runs a real proxy process through the whole chain — packet, module,
aggregation, decision, enforcement, persistence, evidence — in both
enforcement modes, and prints PASS or FAIL for each of 24 checks. Exit code 0
only if every check passes.

Offline and deterministic by default: a loopback stub upstream and a
controlled local feed fixture. `--upstream 1.1.1.1:53` resolves against a real
resolver instead, at the cost of depending on the network; two checks that
require inspecting the upstream then report SKIP rather than PASS.

**The demo domains are IANA-reserved (RFC 2606) and are not malicious.**
`example.com` is listed in the controlled fixture so the BLOCK is
deterministic; `example.net` is deliberately absent. No real threat feed and
no real malicious domain is involved.

**What it proves and what it does not.** It proves the components are
integrated and that a decision survives from the wire to the database with
its evidence intact. It says nothing about detection accuracy — the demo
domain is blocked because a fixture lists it, not because anything detected
anything. Accuracy is Stage 16: **NOT YET MEASURED**.

Some checkpoint tests start real processes and are marked `slow`; the full
suite therefore takes roughly 90 seconds. To skip them:

```bash
python -m pytest tests/ -q -m "not slow"
```

## API (Stage 10)

```bash
pip install -r requirements.txt
python -m uvicorn api.main:app --reload --port 8000
```

Interactive docs at http://127.0.0.1:8000/docs.

| Endpoint | Purpose |
|---|---|
| `GET /health` | API liveness and whether the database is readable |
| `GET /decisions` | Stored decisions, newest first; `limit`, `offset`, `verdict`, `qname` |
| `GET /decisions/{id}/evidence` | Per-module evidence and the aggregation derivation |
| `GET /stats` | Counts computed by the database |
| `POST /lookup` | Live evaluation via the engine's `decide()`; enforces nothing |
| `GET /mode` | This process's engine configuration |
| `PUT /mode` | Enable/disable a module, toggle enforcement |

```bash
curl http://127.0.0.1:8000/health
curl "http://127.0.0.1:8000/decisions?limit=5&verdict=BLOCK"
curl http://127.0.0.1:8000/decisions/1/evidence
curl http://127.0.0.1:8000/stats
curl -X POST http://127.0.0.1:8000/lookup \
     -H "Content-Type: application/json" -d '{"domain":"example.com"}'
curl http://127.0.0.1:8000/mode
curl -X PUT http://127.0.0.1:8000/mode \
     -H "Content-Type: application/json" -d '{"modules":{"ti":false}}'
```

The API opens the database **read-only** (`mode=ro`), so a presentation-layer
bug cannot corrupt a decision record. The proxy does not import `api/`; the
dependency runs one way only, which keeps dashboard load off the DNS query
path.

### Limitations

**`PUT /mode` does not affect a running DNS proxy.** The API and the proxy
are separate OS processes; the API has no handle on the proxy's memory. It
changes the engine `/lookup` uses — useful as the Stage 16 ablation control
surface — and every mode response carries `affects_running_proxy: false`.
Reaching the proxy would need IPC or a shared control table.

**`POST /lookup` is a live evaluation, not a database read**, using this
process's own engine. It calls `decide()`, the one method every engine
implements, so an API process started without `DNSF_ENGINE_MODULES` returns
the allow-all engine's genuine ALLOW with `modules: []` and
`explanation: null`, and names the engine that answered rather than
manufacturing a derivation. Feed indicators match the proxy's because both load the
same file; observation-age state does not, because the first-seen store is
per-process. Nothing is enforced and no DNS response is sent.

**No authentication.** Local development only. Do not expose this port.

**`/stats` figures are operational counts over observed traffic, not
evaluation metrics.** Detection accuracy is **NOT YET MEASURED** (Stage 16),
and the endpoint says so in its own response.

Only `modules` and `enforce` are mutable at runtime. Thresholds and weights
are deliberately fixed: changing them mid-run would make stored decisions
incomparable with each other.

## Console (Stage 11)

Start the API and open http://127.0.0.1:8000/ — it redirects to the console.

```bash
python -m uvicorn api.main:app --port 8000
```

One file, `dashboard/index.html`: plain HTML, CSS and `fetch()`. **No React,
no npm, no build step, no dependency, and no external asset of any kind** —
no CDN, no web font, no image. It is served by FastAPI from the same origin as
the API, so there is no host to configure and no CORS.

### What it shows, and why it moves

A five-stage rail — Query, Signals, Aggregation, Verdict, Enforcement — draws
itself once on load to teach the pipeline, then settles into the header and
becomes the component that reports pipeline progress. Selecting a decision
lights each stage in turn while the evidence request is in flight, so the
loading state and the explanation are the same object.

The centrepiece is the **weight track**, which draws the weighted mean to
scale rather than as a gauge: each module's slot is its weight, each fill is
its score, and the filled fraction of the track is the aggregate. The flag and
block thresholds are marked across it. An **excluded module takes no weight at
all** and is drawn hatched, so "not counted" can never be mistaken for "scored
zero" — the distinction the aggregator is most careful about.

Motion carries information. A newly arrived decision slides in and its verdict
edge flares; nothing moves when a poll returns no new rows. The score counts
from its previous value to the new one. The status pill animates only when the
connection state actually changes. Only `transform` and `opacity` are
animated — a test asserts no layout property is transitioned.

### Limitations

**No authentication, local development only.** The page says so at the top.

**Polling, not live updates** — every five seconds.

**The configuration switches change the API process only**, exactly as
`PUT /mode` does; the running DNS proxy is unaffected and the panel says so.

**Nothing on the page is sample data.** An empty database renders an empty
state telling you to start the proxy, never fabricated rows, and a test greps
the file for hardcoded decisions. Modules on the roadmap that are not yet
implemented are labelled as such and carry no score and no slot. When the
database becomes unreadable, the last known view stays and dims rather than
vanishing — stale data is more useful than a blank panel, provided it is
marked stale.

**Reduced motion is respected.** Under `prefers-reduced-motion: reduce` the
intro is skipped, transitions collapse to 1ms, the score is set rather than
counted, and a new row holds its verdict colour instead of sliding in.
Nothing that carries meaning is conveyed by motion alone.

## Typosquat detection (Stage 12)

The `typosquat` module scores how far a queried name deviates from a
configured brand. Threat intelligence answers "has anyone reported this?" and
domain age answers "has it existed long enough for anyone to find out?";
neither helps against a name registered an hour ago that is one keystroke from
a bank. Agten et al. (NDSS 2015) measured typosquatting across .com and found
it pervasive, which is why lexical similarity is a standard signal — **this is
an implementation of well-known techniques, not a new algorithm.**

```bash
DNSF_ENGINE_MODULES=ti,typosquat
DNSF_TYPOSQUAT_BRANDS=spotify,google,microsoft,amazon
DNSF_TYPOSQUAT_OFFICIAL_DOMAINS=spotify.com,google.com,microsoft.com,amazon.com
```

**A brand string is not evidence of malice.** `spotify.com` is the brand and
scores 0.0; `open.spotify.com` is the brand's own subdomain and scores 0.0. A
score here is a *detection signal*, never a finding that a domain is
malicious. A test asserts the evidence never uses the words "malicious",
"confirmed" or "proven".

### How the score is produced

Each check produces a candidate score; the module takes the highest, adds
**0.15 when two or more independent checks fire**, and caps at 1.0.

| Check | Score | Example |
|---|---|---|
| Official domain / brand's own label | 0.00 | `spotify.com` |
| Transposition | 0.85 | `spotfiy.com` |
| Confusable characters (0/o, 1/l, rn/m) | 0.85 | `sp0tify.com` |
| Edit distance 1 / 2 / 3 | 0.90 / 0.70 / 0.50 | `spotifz.com` |
| Brand + suspicious keyword | 0.75 | `spotifyapk.com` |
| Brand in a subdomain of an unrelated domain | 0.60 | `login.spotify.attacker.example` |
| Contains the brand, nothing else fired | 0.40 | |

The maximum edit distance scales with brand length, since one character
matters more in a five-letter brand. **These numbers and the combination
bonus are conventions, not derived optima** — like the aggregator weights,
they are tuned in Stage 16 and are untuned today.

Everything is computed in-process: no external service, no brand API, no
machine learning, and no dependency beyond the standard library.

### Limitations

**No default brand list.** There is no defensible built-in set of "the brands
that matter", so an unconfigured module raises rather than scoring every
domain 0.0 — the same choice the threat-intelligence module makes with no
feed loaded. The engine records that as `status: error` and excludes it.

**`typosquat` is deliberately absent from the aggregator's default weights**
and takes the 0.5 unlisted-module default. Adding an entry would change
existing aggregation defaults, which Stage 12 has no evidence to justify. A
consequence worth knowing: running `ti,typosquat` with default weights, a
typosquat score of 0.75 against a TI score of 0.0 aggregates to 0.25 and does
not reach FLAG. Use `DNSF_AGGREGATOR_WEIGHTS` to change that deliberately.

**A look-alike character combined with an extra word is not caught.**
`paypa1.com` (confusable) and `paypal-login.com` (brand + keyword) each
score, but `paypa1-login.com` scores 0.0: the confusable check compares the
whole label to the brand, and the keyword check needs the brand spelled
correctly. Found during a pre-release check; left unchanged so the module
still matches the published evaluation.

**Same public-suffix approximation** as the other modules: the registrable
domain is the last two labels, so a name under `co.uk` is measured against
the suffix rather than the registration.

**Confusables are ASCII-only** and restricted to substitutions genuinely used
in impersonation. A full Unicode confusables table would produce false
positives on ordinary names. Punycode labels are compared in decoded form.

## DGA detection (Stage 13)

A supervised classifier over lexical features, trained offline and integrated
as one signal among several. **Nothing here is novel** — lexical DGA
classification has a large literature, and this is an implementation of it.

```bash
pip install -r requirements-train.txt     # scikit-learn, training only
python tools/make_dga_dataset.py          # regenerate the dataset
python tools/train_dga.py                 # retrain and re-export
```

### Pipeline

```
datasets/dga_dev.csv → features → stratified split → logistic regression
  → held-out evaluation → models/dga/dga_model.json → inference → evidence
```

**Ten features**, all computed on the registrable label: `length`,
`digit_ratio`, `vowel_ratio`, `consonant_ratio`, `unique_char_ratio`,
`entropy`, `max_consonant_run`, `max_digit_run`, `hyphen_count`,
`label_count`. Extracted by `engine/modules/dga_features.py`, which is
imported by **both** the trainer and the runtime module — one implementation,
so training and serving cannot drift.

**Logistic regression**, chosen for two reasons. It is per-decision
explainable: each feature has one signed coefficient, so the evidence can
show which features moved this score. And a fitted model is fully described
by weights, an intercept and the scaler parameters, so it exports to JSON —
inference is a standardisation, a dot product and a sigmoid, and **the DNS
query path keeps the zero-dependency property it has had since Stage 1**. The
trainer asserts the exported form reproduces `predict_proba` before writing
the artifact; the last run agreed to 2.2e-16.

### Measured metrics — and what they are not

Held-out test set, 300 rows, seed 20260904:

| accuracy | precision | recall | F1 | 5-fold CV F1 (train) |
|---|---|---|---|---|
| 0.9400 | 0.9286 | 0.9533 | 0.9408 | 0.9115 ± 0.015 |

Confusion matrix: TN 139, FP 11, FN 7, TP 143.

**These are not an evaluation of DGA detection.** The dataset is
**synthetic** — 600 generated pronounceable names and 600 drawn from
near-uniform character distributions — and its two classes are far more
separable than real DNS traffic. The numbers show the pipeline runs end to
end. They say nothing about performance against a real DGA family, and the
report must not present them as if they did. Real evaluation is Stage 16.
The same caveat is stored in `models/dga/dga_model.meta.json` and asserted by
a test.

### Interpretation

The score is a **DGA likelihood score** — the model's estimate that the label
was algorithmically generated. It is *not* a probability that the domain is
malicious: legitimate names can look random and some malware uses dictionary
words. The evidence says so in every record.

### Limitations

**Synthetic training data**, as above. No real DGA corpus is bundled, because
downloading one at build time would break reproducibility and put unvetted
domains in the repository.

**No n-gram or dictionary features.** They are stronger predictors and appear
throughout the literature, but they need a corpus this project does not have.
Adding them would look sophisticated without evidence that it helps here.

**`dga` is deliberately absent from the aggregator's default weights** and
takes the 0.5 unlisted default, for the same reason as `typosquat`: Stage 13
has no evidence to justify a weight. A consequence visible in testing —
running `ti,dga`, a DGA score of 1.0 against a TI score of 0.0 aggregates to
0.333 and does not reach FLAG.

**A missing artifact is a module error, never a score of zero.** The proxy
still starts and still resolves; the module is excluded and the verdict
becomes UNKNOWN rather than ALLOW, so a broken deployment cannot look like a
clean verdict.

## Beaconing detection (Stage 14)

The only behavioural signal. The other four judge a *name*; this judges a
*pattern* — whether a domain is queried on a clock. It reads the `queries`
table the DNS path already writes, so what the module reasons about is
exactly what the dashboard shows.

**Periodic DNS traffic is not malicious.** Software updaters, telemetry
agents and NTP-adjacent libraries all poll on a schedule. The score is a
*periodicity signal* and every evidence record says so. A high score is a
reason to look, not a finding. The technique is standard — regularity of
inter-arrival times is what open-source beacon analysers use — and nothing
here is novel.

### The score

Three bounded factors, multiplied, each separately readable in the evidence:

```
regularity   = 1 / (1 + CV)                     CV = stdev(gaps) / mean(gap)
confidence   = min(1, intervals / 8)            8 = DNSF_BEACON_EVIDENCE_INTERVALS
burst_factor = min(1, mean_gap / 5s)            5 = DNSF_BEACON_MIN_INTERVAL_SECONDS
score        = regularity x confidence x burst_factor
```

`confidence` exists because four evenly spaced queries are weak evidence of a
clock and twenty are strong. `burst_factor` exists because fifty queries
fired in two seconds are extremely *regular* and are not a beacon —
regularity alone gets that case badly wrong. **These constants are
engineering conventions, not derived optima**; they are configurable and are
tuned in Stage 16.

Defaults: **one-hour window**, **minimum four observations** (three intervals
— the fewest from which a standard deviation means anything).

### Thin history is not a finding

Fewer than the minimum observations raises `InsufficientObservations`, which
the engine records as `status: error` and excludes from aggregation. Returning
0.0 would claim the timing had been measured and found irregular; silence
about a domain seen twice is not that claim, and a confident zero would drag
the aggregate down on every rarely-seen domain on the network.

The status word "error" is a poor fit for an ordinary condition. Adding a
distinct status would mean changing the engine contract that Stages 4–13 are
built on, which Stage 14 has no reason to do; the mismatch is recorded here
instead.

### Timing and performance

The proxy decides **before** it records, so the module sees history and never
the query being decided — it cannot double-count. The recorder batches on a
background thread, so the newest observation can be up to one flush interval
behind; over a window measured in minutes that is immaterial.

Two composite indexes were added, `(qname, ts)` and `(client_hash, qname, ts)`,
so the per-query lookup is a range scan over one domain rather than a table
scan. Both use `IF NOT EXISTS`, so **an existing database gains them on the
next open** with no schema version bump and no migration step. History is read
through a `mode=ro` connection: a detection module cannot write to the table
the DNS path depends on.

### Demonstrating it

Beaconing needs hours of history, so it is the one signal that cannot be shown
by typing a query. `tools/seed_observations.py` writes synthetic observations
through the project's own persistence path, marked `engine: "seeded-fixture"`
so they are distinguishable from real traffic:

```bash
python tools/seed_observations.py --domain periodic-demo.test  --pattern periodic
python tools/seed_observations.py --domain irregular-demo.test --pattern irregular
python tools/seed_observations.py --domain sparse-demo.test    --pattern sparse
```

Never take measurements from a seeded database.

### Limitations

- Periodic traffic is not evidence of malware; legitimate software polls.
- A short window reduces confidence; a low-volume domain gives none at all.
- NAT and shared resolvers put many hosts behind one client identifier, so
  per-client attribution is unreliable on a real network.
- The seeded fixtures validate the pipeline; they are not evaluation data.
- `beaconing` is deliberately absent from the aggregator's default weights and
  takes the 0.5 unlisted default, like `typosquat` and `dga`.

## Hybrid integration and explainable evidence (Stage 15)

Stage 15 adds no detector. It makes the five existing signals answer one
question: **why did the system produce this verdict?**

### "Could not assess" is not "found nothing"

Module results carry a new status, `unavailable`, alongside `ok`, `error`,
`invalid`, `skipped` and `disabled`. A feed that has not loaded, an
unconfigured brand list, a missing model file and too little history are all
the module working correctly and reporting that it has nothing to go on —
which is a different fact from a crash, and a very different fact from a
clean score.

**No arithmetic changed.** Both `unavailable` and `error` were already
excluded from aggregation and still are. What changed is that the evidence
can now say which happened. Five existing assertions moved from
`STATUS_ERROR` to `STATUS_UNAVAILABLE`; each is annotated with why, and each
still asserts the behaviour that matters — excluded from the aggregate, never
scored 0.0.

### Contribution accounting

Already present since Stage 7 and unchanged: every module appears in
`explanation.contributions` with its score, its configured weight, its
weighted contribution, its status, and whether it counted, alongside
`counted_weight`, `weighted_sum` and the thresholds. Stage 15 asserts these
agree with the aggregate rather than altering them.

**The weighting policy is untouched.** `ti` 1.0, `nrd` 0.4, everything else
the 0.5 unlisted-module fallback. The weights are engineering defaults, are
**not learned and not tuned**, and every decision still carries
`weights_are_tuned: false`. Tuning is Stage 16.

### The decision summary

`explanation.summary` is one sentence built from the module results:

```
Flagged because threat intelligence matched multi-signal-demo.test on the
phishing-domains feed, domain age has never seen this domain before and
query periodicity saw 12 queries about 300s apart (variation 0.00). 3 of 4
usable signals were elevated, giving a combined risk of 0.79, at or above
the flag threshold 0.5. The dga model could not assess this query and did
not contribute.
```

It is a **rendering, not a second source of truth**: every clause comes from
a `ModuleResult` or from the aggregation, so it cannot claim a signal fired
that did not. A test asserts the counts in the sentence match the contribution
table — if they ever disagree, the table is right and the summary is broken.
`summarise()` receives nothing but the results, so it has no other input to
invent from.

Signals are never collapsed. Threat-intelligence, domain-age, brand,
model and periodicity evidence each keep their own feature vocabulary all the
way to the database and the API.

### Limitations

**Correlation is not handled, and Stage 15 does not claim to handle it.** The
aggregator treats every module as an independent weighted signal. Two
detectors can fire on the same underlying property — a newly registered
domain is more likely to be unlisted *and* to look generated — and the
weighted mean will count both. No correlation coefficient is estimated and no
statistical correction is applied. Both signals are preserved and the
double-count is visible in the contribution table rather than hidden.

The `ELEVATED_AT` constant (0.5) chooses wording only. It never affects a
score, a verdict, or which modules count.

Detection evidence and enforcement stay separate: the summary describes risk,
never whether the query was blocked. A test asserts the sentence is identical
with enforcement on and off.

## Evaluation and ablation (Stage 16)

```bash
python tools/make_eval_dataset.py     # regenerate the labelled dataset
python tools/run_experiments.py       # ablation + sweeps + artifacts
python tools/run_experiments.py --ablation-only
python tools/run_experiments.py --sweep-only
```

Writes `experiments/results/{ablation,ablation_deltas,sweep}.csv`, the JSON
equivalents, and `metadata.json` recording the seed, the dataset SHA-256 and
the caveat below.

The harness replays the dataset through the **real** `DecisionEngine` and
`RiskAggregator`. Nothing is reimplemented, and **no project weight or
threshold is changed** — every configuration builds its own aggregator.
`experiments/sweep.py` deliberately has no `best()` function: picking the
top-scoring configuration on synthetic data is overfitting, not tuning.

### What these numbers are not

**The labels come from the generator, not from observed ground truth.** No
labelled DNS corpus is bundled. A "typosquat" row is labelled malicious
*because* it was generated as a brand variant — the same rule the module
applies. Two things push back on that circularity: benign rows that are newly
seen or that poll on a schedule, so domain age and beaconing produce real
false positives; and malicious rows no single module can catch. It is not
enough to make the absolute figures meaningful.

**Threat intelligence cannot be evaluated here at all.** Its score is feed
membership and the dataset declares the feed, so its precision is 1.0 by
construction. Reported with that warning rather than omitted.

**Report the deltas, not the absolutes.** The generator's bias is shared
across arms, so a difference between two configurations is far more
defensible than either number.

### The finding that matters

Measured on 720 rows, project defaults, all five modules:

| arm | precision | recall | F1 | FPR |
|---|---|---|---|---|
| baseline_all (five modules) | 1.000 | **0.029** | 0.057 | 0.000 |
| only_nrd | 0.808 | 0.525 | 0.636 | 0.250 |
| only_dga | 0.932 | 0.287 | 0.439 | 0.042 |
| without_ti (four modules) | 1.000 | 0.485 | 0.654 | 0.000 |

**Every leave-one-out arm scores higher than the full configuration.** That
is not a bug; it is the aggregation formula behaving as designed. The
weighted mean normalises by the summed weight of contributing modules, so
with five modules running (total weight 2.9) one module scoring 1.0 yields
1.0 / 2.9 = 0.34 — below the 0.5 flag threshold. **A single confident signal
cannot flag anything once enough quiet modules are also running.** Adding a
detector makes the system less sensitive.

The threshold sweep shows the same effect from the other side: at the
project default (flag 0.5) recall is 0.029; at flag 0.30 it is 0.740 with
precision still 1.000.

**Nothing has been changed in response.** Adopting a threshold or a weighting
on the strength of synthetic data would be exactly the overfitting this stage
is written to avoid. The finding is reported; the decision is separate, and
should be made against real traffic.

### Limitations

- Synthetic labels, as above — the largest by far.
- No temporal split, so no concept-drift claim.
- Beaconing is evaluated against timings the dataset declares, making it the
  weakest of the five evaluations.
- One-at-a-time weight variation, not a joint search: five modules over five
  weights is 3,125 configurations and a joint optimum on this data would be
  meaningless.

## Authentication (Stage 17)

**Academic / local-development authentication.** It is real backend
enforcement — an unauthenticated request to a protected endpoint is refused
by FastAPI before the handler runs, not hidden by JavaScript — but it is not
production-grade, and the limitations below are not boilerplate.

### Configuring credentials

```bash
python tools/make_password_hash.py
```

Prompts for a password (never a command-line argument, which would land in
shell history and the process list), prints a hash, writes nothing to disk.
Then, in the terminal that runs the API:

```powershell
$env:DNSF_AUTH_USERNAME="admin"
$env:DNSF_AUTH_PASSWORD_HASH="pbkdf2_sha256$..."
python -m uvicorn api.main:app --port 8000
```

In bash use single quotes around the hash: the `$` separators would otherwise
be expanded as shell variables.

Open http://127.0.0.1:8000/ — unauthenticated visitors are redirected to
`/login`. Sign out from the control beside the connection pill.

**With no hash configured the API runs open and logs a warning at startup.**
That is deliberate: an upgrade must not lock a developer out of their own
project. It is an announced state, not a silent bypass, and `/health` reports
`authentication: "disabled"`.

**Never commit the password or the hash.**

### What is protected

| Endpoint | |
|---|---|
| `/decisions`, `/decisions/{id}/evidence`, `/stats`, `/lookup`, `GET|PUT /mode` | session required |
| `/dashboard/` | redirects to `/login` without a session |
| `/health`, `/login`, `/auth/login`, `/openapi.json` | public |

`/health` stays public for operational monitoring and was **trimmed** in this
stage: it no longer returns the database path or the error detail, because
neither should be readable by an unauthenticated caller.

The dashboard redirect is a convenience, not the boundary. Every endpoint is
guarded independently, so going straight at the API with `curl` and skipping
the login page gains nothing — `test_protection_does_not_depend_on_the_login_page`
asserts exactly that.

### Mechanism

**Password hashing:** PBKDF2-HMAC-SHA256 (RFC 8018, recommended by NIST
SP 800-63B), 480,000 iterations, random 16-byte salt per password, from
`hashlib`. Verified with `hmac.compare_digest`.

**Sessions:** an opaque 32-byte token held server-side, sent in an
`HttpOnly; SameSite=Strict; Path=/` cookie. Not a JWT — a JWT cannot be
revoked at logout without a server-side store anyway, needs a signing secret
to manage, and would have to be readable by JavaScript. Logout removes the
token from the store, so a cookie captured beforehand is useless afterwards.

A wrong password and an unknown username return the same message and both
run a key derivation, so neither the body nor the response timing reveals
which usernames exist.

### Limitations

- **PBKDF2, not bcrypt or Argon2.** Both are memory-hard and PBKDF2 is not,
  making it the weaker choice against a GPU. Either would add a runtime
  dependency to a project whose DNS path has run on the standard library
  since Stage 1. A real trade-off, recorded rather than glossed.
- **Sessions live in process memory.** Restarting the server signs everyone
  out, and it does not work across multiple uvicorn workers.
- **CSRF is mitigated by `SameSite=Strict` and single-origin serving, not by
  tokens.** Adequate for local use; not for deployment.
- **No HTTPS, no rate limiting, no account lockout, one account.** Set
  `DNSF_AUTH_COOKIE_SECURE=true` behind TLS.
- Do not expose this port.

## Latency measurement (Stage 18)

```bash
python tools/run_latency.py              # both modes
python tools/run_latency.py --mode a     # engine only, fast
python tools/run_latency.py --queries 500 --repeats 3
```

**Deliberately not part of `pytest`.** Mode B spawns real proxy processes and
sends thousands of queries; running it on every change would make the suite
minutes long and would time the system under whatever load the test runner
is creating. `tests/test_latency.py` covers the statistics and the runner's
structure; this command performs the measurement.

Writes `experiments/results/latency_engine.csv`,
`latency_end_to_end.csv` and `latency.json`.

### Method

**Mode A — engine only.** Times `evaluate()` and `aggregate()` over the Stage
16 dataset, per configuration. No sockets, no upstream, so detection cost is
isolated from network cost.

**Mode B — end to end.** Starts the real proxy against a loopback stub
upstream, sends queries, reads the per-phase breakdown back out of SQLite.

Everything is reported as **p50 / p90 / p99 with min, max and count** —
never a mean alone. A mean hides the tail, and the tail is where a filtering
resolver is felt: one query in a hundred taking 40 ms is a visible stall that
a 0.4 ms mean conceals. The first 20 observations per configuration are
discarded, because the DGA artifact loads lazily and feeds parse once.

### Results, on the development machine

**Mode A, per module, one `evaluate()` call (ms):**

| module | p50 | p90 | p99 |
|---|---|---|---|
| nrd | 0.0023 | 0.0027 | 0.0072 |
| beaconing | 0.0021 | 0.0484 | 0.0752 |
| ti | 0.0025 | 0.0033 | 0.0087 |
| dga | 0.0240 | 0.0303 | 0.0490 |
| typosquat | 0.0508 | 0.0705 | 0.0940 |

All five together, dispatch plus aggregation: **p50 0.143 ms, p99 0.251 ms**,
against an engine-only floor of 0.001 ms with no modules.

**Mode B, end to end (ms):**

| case | p50 | p90 | p99 | added p50 | upstream calls |
|---|---|---|---|---|---|
| no modules | 0.084 | 0.337 | 1.766 | 0.034 | 300 / 300 |
| all five, forwarded | 1.208 | 2.168 | 4.166 | 1.090 | 300 / 300 |
| enforced block | 0.278 | 3.041 | 7.573 | 0.278 | **0 / 300** |
| module unavailable | 0.242 | 0.784 | 2.493 | 0.191 | 300 / 300 |

Two results worth stating plainly. **Typosquatting is the most expensive
signal — roughly twenty times threat intelligence and twice the ML model.**
That is not the ranking a reader would guess, and it comes from comparing
every configured brand against every label rather than from anything the DGA
classifier does. And an **enforced block made zero upstream calls out of
300**, which is the measured form of the Stage 8 claim that a blocked query
never reaches the upstream resolver.

### What these figures are

Unlike detection accuracy, a timing measurement does not depend on the
dataset labels being right, so these are **real measurements of this
implementation** — the most defensible numbers in the project.

They are still one machine's. Absolute milliseconds will differ elsewhere,
and Mode B resolves against a loopback stub rather than a real resolver, so
upstream time is unnaturally small and stable. That is deliberate — it stops
internet variance swamping the added latency — but it means the total is not
a realistic end-user figure. **The portable results are the comparisons: the
per-module ranking, and added latency relative to a resolution.**

## Live mode and paper mode

`start.ps1` launches the proxy and the API in two windows, in one of two
explicitly pinned configurations:

```powershell
& "E:\prj112 (26)\prj112\start.ps1"              # live (default)
& "E:\prj112 (26)\prj112\start.ps1" -Mode paper  # reproduces the paper
```

| | paper | live |
|---|---|---|
| Modules | ti, nrd, typosquat, dga, beaconing | the same, plus `rdap` |
| Threat intelligence | pinned `datasets/urlhaus_20260921.csv` snapshot | five live no-auth feeds, hourly |
| Aggregation | weighted mean, formula (2) | weighted mean, a TI listing decisive |
| Purpose | every number in the paper | demonstration and real use |

**Every result in the paper was produced in paper mode, and the experiment
harness is unaffected by live mode**: `experiments/` constructs its own
`RiskAggregator()`, whose default is the plain weighted mean. Re-running the
ablation after these changes reproduced all 14 arms exactly.

### Several live feeds

One list rarely contains a given malicious domain. With no feed configured,
TI loads Phishing.Database plus four more no-auth feeds: the
malware-filter mirrors of URLhaus and of its phishing list, Phishing Army,
and OpenPhish (about 580,000 indicators in total). Configuring
`DNSF_FEED_URL`, `DNSF_FEED_FILE` or `DNSF_FEED_AUTH_KEY` means the operator
chose a feed, and nothing is added to it.

### A listing is decisive

Stage 16 found that a single confident signal is diluted below the flag
threshold once quiet modules also run. For threat intelligence that is the
wrong outcome: a listing is a third party's explicit assertion, not a hint.
With `DNSF_AGGREGATOR_TI_DECISIVE=true` a TI score of 1.0 sets the aggregate
to 1.0, and the explanation records `decisive_hit` so the override is never
silent. The heuristic modules are still averaged exactly as before.

### Registration age (`rdap`)

Closes the gap the `nrd` module states about itself: it measures observation
age, and refuses to judge for its first seven days. RDAP (RFC 9082/9083) is
the registries' free, no-account successor to WHOIS and returns the real
registration date; the evidence carries `age_source: "rdap"`.

- **Never on the query path.** The first query for a domain starts a
  background lookup and reports `RegistrationPending` (unavailable, excluded,
  never 0.0). Later queries read the cache: seven days for an answer, one
  hour for a failure.
- **Privacy.** A lookup discloses the registrable domain (not the hostname,
  nothing about the client) to the RDAP service. Internal names (`.local`,
  `.lan`, `.home`, `.test`, …) and IP literals are never sent.
- A recent registration is a risk signal, not proof: new legitimate sites
  exist. `rdap` takes the 0.5 unlisted-module weight.

### DNS over TCP

Large answers (big TXT records, DNSKEY, long record sets) do not fit in a
UDP reply. Before this, a truncated upstream reply reached the client, the
client retried over TCP, and nothing was listening — the lookup failed.

- **Upstream:** a UDP reply with TC set is re-asked over TCP, with the same
  random transaction ID and question check as UDP (`proxy/upstream.py`).
- **Clients:** the proxy listens on TCP at the UDP port. Messages carry the
  two-byte length prefix; several queries may share a connection; idle
  connections close after `DNSF_TCP_IDLE_TIMEOUT`; connections beyond
  `DNSF_TCP_MAX_CONNECTIONS` are refused. If TCP cannot bind, UDP keeps
  serving and a warning is logged.
- **UDP size limit:** a reply larger than the client advertised (512 bytes
  without EDNS, RFC 6891 otherwise) is replaced by a TC reply, so the
  client moves to TCP rather than receiving an oversized datagram.

Both transports run one decision path: the same modules, verdict,
enforcement (a block over TCP never reaches upstream) and record, which
gains a `transport` field. Mode B latency was unchanged within run-to-run
noise (enforced-block p50 ranged 7.6–9.6 ms on both the old and new code).

### Public Suffix List (`DNSF_PSL_MODE`)

Every module used to reduce a name to its last two labels, which is wrong
under multi-label suffixes (`x.co.uk` became `co.uk`) and on hosting
platforms (`site.pages.dev` became `pages.dev`). `feeds/psl.py` implements
the PSL algorithm over a pinned copy of the list
(`resources/public_suffix_list.dat`, version 2026-10-07, MPL-2.0). With
`full` (live mode):

- **typosquat** analyses the label the site owner chose; a brand inside a
  site name on a shared platform keeps the 0.6 it had before.
- **TI** parent matching never climbs to a public suffix, so a listed
  `pages.dev` cannot block every site hosted there.
- **nrd** tracks first-seen per site.
- **rdap** looks up the ICANN registration (`local.gov.uk`, not `gov.uk`),
  and for a site on a shared platform reports `RegistrationShared` —
  cannot assess — instead of the platform's age scored as clean.

`off` is the default and reproduces every earlier result; paper mode pins it.

Measured on the real dataset (`real_eval_psl_full.json`, TI off): RDAP's
detections are unchanged (recall 0.238), but 170 malicious and 4 benign
shared-platform rows move from a false "assessed, clean" to "cannot assess", so among the domains RDAP
can judge it fires on 52.0% of malicious against 2.0% of benign. Typosquat
keeps its 4 detections and loses its one false positive (`google.com.ph`).

### Sign-in intro

`/login` opens with a short animated intro (the team image, "DNS FILTERING
SERVICE", an "Enter Securely" button) that slides up to reveal the
unchanged sign-in form. It is four marked blocks in `dashboard/login.html`
(`PRJ intro (1/4)`…`(4/4)`); the form and its script are untouched. The
image is embedded as a data URI because the API serves only its two HTML
routes; the source is `dashboard/assets/intro-team.jpg`.

It is shown only when JavaScript runs, can be skipped with **Skip intro** or
Escape, plays without motion under `prefers-reduced-motion`, and a failsafe
uncovers the form within 4 s if the intro script ever fails. While the
intro covers the page the form is not drawn, which keeps the intro at
~60 fps on 4K integrated graphics.

### Allowlist

`DNSF_ALLOWLIST` / `DNSF_ALLOWLIST_FILE` name domains that are always ALLOW
and never enforced — the override for a false positive such as a shared
hosting platform. Modules still run and their evidence is stored; the
explanation records the entry and the verdict the detectors would have
given. Empty by default, which leaves the engine unchanged.

### Devices needing attention (`GET /alerts`)

Lists pseudonymised clients that reached at least `min_domains` (default 3)
distinct BLOCK or FLAG domains within `window_s` (default one hour) — the
pattern of an infected machine or unwanted software rather than one stray
click. Session required; computed from stored decisions, nothing new
collected; raw addresses never appear. Behind NAT one client hash can be
many devices, and an alert is a reason to inspect a device, not proof.

## Real-world evaluation

```bash
python tools/make_real_dataset.py   # collect once; needs the network
python tools/run_real_eval.py       # replay offline; writes experiments/results/real_eval.*
```

Collected 2026-10-15 into `datasets/real_20261015.*` (seed 20261015):
500 malicious domains, 100 from each live feed, and 500 benign from Tranco
list N26XW (250 from ranks 1–10k, 250 from 10k–100k), with an RDAP
registration date frozen for every registrable domain. The runner refuses
to evaluate files whose checksums differ from the metadata.

**TI is off in every arm**: the malicious rows came from the feeds, so TI
would catch all of them by construction. TI is measured only where it is not
circular — its false-positive rate on Tranco — which was **0 / 500**.
`nrd` and `beaconing` need query history and timing, so they are not
evaluated. Shipped defaults throughout; nothing fitted.

| arm (TI off) | precision | recall | F1 | FPR |
|---|---|---|---|---|
| only_dga | 0.799 | 0.708 | 0.751 | 0.178 |
| only_typosquat | 0.800 | 0.008 | 0.016 | 0.002 |
| only_rdap | 0.943 | 0.232 | 0.372 | 0.014 |
| dga + typosquat | 0.929 | 0.052 | 0.099 | 0.004 |
| dga + typosquat + rdap | 0.964 | 0.106 | 0.191 | 0.004 |

What the numbers say:

- **The DGA figure is an artefact.** The artifact's largest coefficient is
  `label_count` (2.68), learned from the synthetic training set, so every
  name with three or more labels fires (324/324 malicious, 51/51 benign;
  `mail.google.com` scores 0.83). On two-label names it fires on 17.1% of
  malicious and 8.5% of benign — a weak signal. The 0.94 synthetic accuracy
  does not transfer. Not retrained here, because that would change the
  paper's reported DGA results.
- **Registration age is the strongest real signal**: of malicious domains
  with a date, 29.4% scored at least 0.5 (registered within about 197
  days) versus 2.0% of benign, at 0.943 precision. Ages are measured after
  listing, so at first sighting these domains were younger still.
- **The Stage 16 dilution finding reproduces on real data.** Combining
  signals under the weighted mean *lowers* recall (0.106 for all three
  against 0.232 for rdap alone), for the reason the paper gives.
- **43% of malicious rows (213/500) are subdomains of shared platforms**
  (`pages.dev`, `web.app`, `netlify.app`, …). Registration age sees the
  platform's old registration, so the heuristics catch 3 of them. Feeds,
  not heuristics, are what covers this class.
- Typosquat fired on 4 of 500 against ten configured brands: real phishing
  mostly impersonates brands outside any fixed list.

Labels are feed listings and Tranco ranks — real domains, asserted labels,
not verified ground truth.

### DGA model v2

**Cause of the artefact.** In `tools/make_dga_dataset.py` the TLD list
includes `co.uk`, so every three-label training row (157 of 1,200) was
`<x>.co.uk`, and `registrable_label` analysed the label `co` for all of
them. Those rows were lexically identical whatever their class, and the only
feature separating them was `label_count` — so logistic regression gave it
the largest weight, which then extrapolated to every real subdomain.

**v2** (`models/dga/dga_model_v2.json`) changes only the features: no
`label_count`, and the label located with the PSL (site view). Same
dataset, seed, split and model. A retrain of v1 with the current
scikit-learn reproduced the published metrics exactly and its coefficients
to 4e-14, so the difference is the features alone. Acceptance criteria were
fixed before training:

| criterion | v1 | v2 |
|---|---|---|
| C1 score independent of subdomain depth | no (`google.com` 0.002 → `a.b.google.com` 0.9999) | yes |
| C2 synthetic held-out F1 ≥ 0.90 | 0.9408 | **0.9728** |
| C3 real benign FPR, 3+ labels vs 2 labels | 100% vs 8.5% | **9.8% vs 7.1%** |
| C3 real benign FPR overall (DGA only) | 0.178 | **0.074** |

On the real phishing set v2 fires on 25.0% (v1: 70.8%, nearly all of it the
artefact). Phishing domains are not algorithmically generated, so that is
not a DGA metric; a real DGA corpus is still needed to measure recall.

v1 is the default and the published model; paper mode pins it explicitly,
live mode uses v2. Results: `experiments/results/real_eval_dga_v2.json`.

## Layout

```
prj112/
├─ proxy/       packet.py · upstream.py · timing.py · enforce.py ·
│               dns_proxy.py
├─ config/      settings.py
├─ tests/       test_packet.py · test_proxy_integration.py
├─ storage/     models.py · db.py · writer.py
├─ engine/      decision.py · aggregator.py · allowlist.py · explain.py ·
│               modules/ (ti · nrd · typosquat · dga · beaconing · rdap)
├─ feeds/       base.py · sources.py · cache.py · manager.py · psl.py ·
│               first_seen.py · nrd_source.py
├─ api/         main.py · repository.py · auth.py · module_presentation.py
├─ dashboard/   index.html (console) · login.html (sign-in + intro) · assets/
├─ datasets/    eval_dev.csv · dga_dev.csv · real_20261015.* · urlhaus_20260921.*
├─ models/dga/  dga_model.json (v1, published) · dga_model_v2.json
├─ resources/   public_suffix_list.dat (pinned)
├─ tools/       checkpoint · experiments · latency · real-data eval · training
├─ experiments/ harness · ablation · sweep · latency · real_eval · results/
└─ start.ps1    launcher: -Mode live (default) | -Mode paper
```

## Security note for the report

TXID randomisation plus question matching raises the bar for **off-path**
spoofing only. An on-path attacker who can observe the query still wins. Say
this plainly in the report rather than describing the proxy as spoofing-proof.
