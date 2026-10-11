# Recon-AI — Project Context

AI-assisted bug bounty **reconnaissance** platform.
Python 3.12. Package name `recon-ai` (pyproject.toml). Private git repo: github.com/SameerEmVi/recon-ai.

Workflow: root domain + authorized scope → enumerate subdomains → resolve/probe
live hosts → fingerprint → content discovery/fuzzing → (optional) LLM triage →
structured results → historical scan diff.

## Core principle — deterministic vs. LLM split

Deterministic code owns everything security-relevant: scope enforcement,
enumeration, probing, parsing, rate limiting, dedup, execution. The LLM only
*reasons* (triage, prioritization, correlation, strategy) and can **propose**
targets but **never decides** scope. MCP is the standardized external interface.

## Non-negotiable invariants

- **Scope is decided by code, never the LLM.** `scope/engine.py::ScopeEngine.evaluate()`
  is the single gate. Deny-first order is a security property: normalize →
  DENY → DISTANCE (recursion bound) → ALLOW → default OUT. Fail closed.
- **One scope chokepoint.** Every event goes through the controller's
  `stamp_and_publish()`. No module, tool, or agent can bypass it. The EventBus
  drops any event whose `scope_status != IN`.
- **Target output is hostile input.** All target-controlled strings are
  sanitized (control-char strip + length cap, `_MAX_STR=2048`) by Pydantic
  validators in `events/types.py` at event construction. Raw tool output never
  travels past that module and never reaches the LLM as instructions.
- **All AI is opt-in** via `--ai/--no-ai`. Everything works fully without an API key.
- Never design to bypass scope, rate limits, auth, or security controls.

## Rate limiting & adaptive WAF backoff

The `ratelimit/` package (`RateLimiter` + `ratelimit/waf.py`) is the single
throttling chokepoint. One `RateLimiter` is created per scan (owned by
`ScanController`, exposed as `controller.rate_limiter`) and shared by every
module, recon wrapper, and agent tool via one `guard()` context manager:

- **rps spacing** — min-interval between op starts, per bucket (host/tool)
- **concurrency cap** — a global semaphore over in-flight ops
- **adaptive WAF backoff** — `observe_http(status, headers, body)` → `waf.detect`
  turns a response into a backoff signal; on a block it multiplies the spacing
  (×2 per block, capped ×32) and recovers slowly on clean responses. If no static
  rate was set, a detected block self-imposes a 1s/op baseline so the scan
  *automatically slows down* against a WAF. **A CDN is not a firewall:** `waf.py`
  splits its fingerprint DB into **WAF/security products** (`active=True` —
  Imperva, Sucuri, AWS WAF, ModSecurity, DataDome, FortiWeb…) and **CDN/LB
  presence headers** (`active=False` — CloudFront `x-amz-cf-id`, Cloudflare
  `cf-ray`, Akamai, ELB, API-GW). A bare CDN/LB fingerprint is **never** a block
  signal on its own: a 403/404/503 from a CDN is routine (missing S3 object,
  origin error, app auth) and content discovery deliberately probes hundreds of
  dead paths, so treating it as a block would self-throttle every CDN-fronted
  target to a crawl. Backoff fires only on **real** block evidence — a block-page
  body, a 429, or a WAF-product fingerprint (optionally beside a block status).

Wiring: `BaseModule.guard()` / `BaseModule.inspect_response()` for HTTP modules;
`BaseReconTool._run` and the `GauWrapper`/`NucleiWrapper` subprocess wrappers take
the limiter; `httpx_probe` feeds the target's own responses into WAF detection.
User controls: CLI `--rate-limit/-r` (req/s) and `--max-concurrency/-c`, mirrored
in the MCP `start_scan` tool. Unset = unlimited static rate, but adaptive WAF
backoff still applies.

Test-safety: `get_limiter(obj)` returns the shared **inert** `NOOP` limiter unless
`obj.rate_limiter` is a real `RateLimiter` (MagicMock controllers fall through).
`NOOP` is `frozen=True` and must never throttle/adapt — a non-frozen shared
fallback silently slowed the whole test suite once (WAF signals mutated it).

## Adaptive Reconnaissance Planner

`planner/planner.py::ReconPlanner` (one per scan, owned by `ScanController`,
exposed as `controller.planner`) decides *which* modules are worth running for a
discovery instead of blindly firing every module on every matching event. It
**gates dispatch only** — scope (`stamp_and_publish`) and rate limiting
(`guard()`) are untouched and still apply to whatever it approves.

- **Observe → decide.** `controller.stamp_and_publish` calls `planner.observe(event)`
  (building per-host technology/asset/event context) *before* publishing, then
  the wrapped reactive handler calls `planner.evaluate(module, event)`; seed
  modules pass through `planner.allow_seed(module)`. A `run=False` decision skips
  the module (scope/limiter never consulted for it).
- **Signals considered:** module cost (`estimated_cost`, else derived from flags:
  slow→HIGH, passive→LOW, else MEDIUM), expected value, `supported_technologies`
  (tech-conditional activation — e.g. a GraphQL-only module runs only once GraphQL
  is seen on that host), `prerequisites` (event types that must already exist for
  the host), per-(module,host) execution state, and remaining budget.
- **Modes:** `passive-first` (only passive modules), `default` (permissive —
  preserves prior behaviour), `aggressive` (higher caps/budget). CLI:
  `--plan-mode`, `--budget` (max total executions).
- **Loop prevention / dedup:** per-(module,host) cap (mode-scaled) on top of the
  scope distance bound and bus event-dedup.
- **Explainability:** every decision carries a reason ("run graphql on api.x.com
  because technology 'graphql' present"); `planner.explain()` / `planner.stats`
  summarize selections + skip reasons, printed in the SCAN SUMMARY when the
  planner gated anything.

Module planner metadata lives on `BaseModule` (`estimated_cost`, `expected_value`,
`supported_technologies`, `prerequisites`); unset fields fall back to
flag-derived defaults, so existing modules are unaffected (default mode changes
nothing).

## Shared per-scan HTTP body cache

`recon/fetch.py::ResponseCache` (one per scan, owned by `ScanController`, exposed
as `controller.response_cache`) is the single place a URL body is fetched. Every
body-consuming web module (secretfinder, jsintel, apifinder, linkfinder, …) now
GETs through `BaseModule.fetch(url, …)` instead of opening its own httpx client,
so a page referenced by several modules is downloaded **once** — one rate-limit
slot, one WAF observation, one latency hit — and the immutable `FetchResult` is
fanned out to the rest.

- **In-flight de-dup.** `get_or_fetch(key, fetcher)` runs `fetcher` exactly once
  per `(method, url)` key even under concurrency: the first caller executes it,
  concurrent callers await its shared future, later callers get the cached result.
- **Full body cached, per-caller cap at read.** The network op (in `BaseModule.fetch`,
  which owns the limiter `guard()` + `inspect_response()`) stores the **full** body
  up to a global ceiling (`CACHE_MAX_BODY_KB`, 8 MB) and each caller applies its
  own `max_body_kb` at read time — otherwise whichever module fetched first would
  bake in its cap and starve a later module with a larger one (linkfinder's 512 KB
  vs jsintel's 2048 KB). `FetchResult.text` is populated for **any** status within
  the cap (secretfinder deliberately scans 4xx/5xx bodies — stack traces leak).
- **Bounded.** LRU-capped (`max_entries`, 4096) so a huge scan can't grow it
  without limit. Never raises — a transport failure is a `FetchResult(ok=False)`.
- **Test-safety.** `get_response_cache(obj)` returns the cache only when
  `obj.response_cache` is a real `ResponseCache` (mirrors `ratelimit.get_limiter`);
  a MagicMock controller falls through to an uncached direct fetch, so unit tests
  with mock controllers are unaffected.

Modules that need **bytes** rather than text, or send custom per-request headers
(metascan's file download, corscanner's `Origin` probes, csprecon), keep their own
client on purpose — a URL-keyed GET cache would be wrong for them.

## Evidence-based vulnerability assessment (`vulnscan/`)

`vulnscan/` is a *reasoning + light-verification* layer on top of recon — it turns
the reconnaissance intelligence recon-ai already produces into structured,
evidence-backed vulnerability results. It is **not** a scanner bolt-on, and it
preserves the deterministic-vs-LLM split: deterministic code owns detection,
verification and the **status** field; the LLM only annotates (via the existing
triage pass) and can never invent a finding or promote one to CONFIRMED.

- **Consistent check interface** (`vulnscan/checks.py::Check`): id / name /
  category / **tier** (`passive` · low-impact `active` · `intrusive`) /
  `supported_technologies` / `prerequisites` / `required_evidence` /
  `verification` / `applies(ctx)` / `run(ctx)`. Checks register in an internal
  check registry (`register_check`); the *capability* plugs into the existing
  module registry as one module, **vulnassess**.
- **Result schema** (`vulnscan/schema.py::VulnResult`): asset + affected URL,
  category + check id, evidence + detection method, **confidence** (0..1),
  severity + rationale, **verification status** (`OBSERVED` / `POTENTIAL` /
  `UNCONFIRMED` / `CONFIRMED`), remediation, references (CVE/CWE), source module
  + timestamp. A VulnResult is **projected onto the existing `FINDING_CANDIDATE`
  event** (`to_finding_data`, category `vuln:<check_id>`), folding all structured
  fields into the finding's `evidence` JSON — so scope, dedup
  (`host:title:category`), persistence, history/diff, the aggregator and AI
  triage all apply **with no event/DB schema change**.
- **Native checks** (`vulnscan/checks.py`): `security-headers`, `cookie-security`
  (names only, never cookie values), `info-disclosure` (version banners),
  `known-cve` (version→CVE correlation — **never CONFIRMED on a version string**;
  `vulnscan/cve.py` is tolerant-semver + conservative, returns POTENTIAL /
  UNCONFIRMED with backport/patch caveats), `exposed-interface`
  (admin/debug/diagnostic, reachability-gated), `api-exposure` (GraphQL/OpenAPI
  surface — introspection is **not** sent), `reflected-input` (a **benign,
  non-executing canary** echoed verbatim → POTENTIAL indicator, never an XSS
  claim), and `normalize-existing` (consumes CORS / exposed-file / secret /
  source-map / cloud / takeover findings other modules already emitted into the
  unified schema, `emit=False` so they enrich the report **without** duplicating
  events).
- **Technology-aware selection** (`vulnscan/engine.py`): events accumulate into a
  per-host `AssessmentState` during the scan; at `finish()` (full fingerprint
  known) one `CheckContext` per host is built and only applicable checks run
  (tier + technology + prerequisite gated — "not every check on every URL").
  Active header/cookie checks share **one** low-impact GET per service through
  `BaseModule.fetch` (limiter / WAF backoff / cache). Each check is isolated (a
  raised check is recorded `failed`, never breaks the run), and results dedupe
  across checks/hosts (strongest severity+confidence wins).
- **Safety / tiers** (requirement): passive + low-impact active run by default;
  the **intrusive tier is disabled** unless BOTH `intrusive=True` **and**
  `authorized_intrusive=True`, and no destructive payloads are implemented. All
  network I/O is through the shared limiter; candidates only ever target
  already-in-scope hosts; emission is scope-gated via `self.emit`.
- **Reporting** (`vulnscan/report.py`): structured JSON + a human-readable report
  (executive summary · findings by severity/confidence · affected assets ·
  evidence + verification status · remediation · checks executed/skipped/failed ·
  limitations). The **vulnassess** module attaches it to the aggregator's single
  writer (`attach_vuln_report` → `vulnerabilities.txt`/`.json` + a summary
  section, mirroring `attach_intelligence`); the `recon-ai report` CLI renders it
  from persisted findings.

Controller wiring: `ScanController` exposes `aggregator` (read-only) and calls
`bus.drain()` **again after** the `finish()` loop so finish-time emissions
(vulnassess, cloud_intel) and their persist tasks flush before teardown.

## Execution modes & central capability policy (`policy/`)

Recon-ai is **mode-based**. The CLI `--mode` selects one of four modes, which is
both the **default module set** and a **capability ceiling enforced centrally**
(not merely CLI filtering), so e.g. an `osint` scan is *technically unable* to
launch active target probes — including via the AI agent, event callbacks, or
fallback paths.

- **Capabilities** (`policy/policy.py`): `PASSIVE_EXTERNAL`, `TARGET_DNS_QUERY`,
  `TARGET_HTTP_REQUEST`, `ACTIVE_DISCOVERY`, `FUZZING`, `PORT_SCANNING`,
  `VULNERABILITY_CHECK`, `INTRUSIVE_TEST`. Each module is classified by
  **behaviour** (what it does to the target), never by name/flags — the
  authoritative table is `MODULE_CAPABILITIES`, and a module may self-declare via
  a `capabilities` ClassVar (precedence: ClassVar > table > fail-closed). This is
  why `subfinder` (flagged "active") is `PASSIVE_EXTERNAL`, and `metascan` /
  `csprecon` (which hit the target directly) are not passive.
- **Modes → allowed capabilities**: `osint` = `{PASSIVE_EXTERNAL}`; `vuln` =
  `{PASSIVE_EXTERNAL, TARGET_DNS_QUERY, TARGET_HTTP_REQUEST, VULNERABILITY_CHECK}`;
  `active` / `full` = all except `INTRUSIVE_TEST`. `INTRUSIVE_TEST` unlocks only
  with `--intrusive` **and** mode ∈ {active, full}. A module runs only if **all**
  its capabilities ⊆ the mode's allowed set.
- **Enforcement points** (central, fail-closed): (1) the controller filters which
  modules load/subscribe (`CapabilityPolicy.module_allowed`), recording disabled
  modules + reasons; (2) `BaseModule.fetch` denies `TARGET_HTTP_REQUEST` and
  `run_proc` re-checks `module_allowed` at the moment of action; (3)
  `build_tool_registry` omits agent tools whose capability the mode forbids and
  each tool re-checks at call time. `CapabilityPolicy("<bad>")` raises
  (`CapabilityDenied`); an unclassified module is permitted only in `full`.
  `get_policy(controller)` returns `ALLOW_ALL` for mock controllers (test-safety,
  mirrors `ratelimit.get_limiter`). The **ScopeEngine stays authoritative for
  scope** — mode never widens scope; it is an orthogonal, additional gate.
- **osint guarantees**: no direct target HTTP, no DNS resolution/brute, no
  fuzzing/port scanning/vuln checks; `cloud_intel`'s optional active bucket
  verify is forced off. Unavailable passive sources warn-and-skip (no active
  fallback).
- **CLI / migration**: `--mode` is the primary selector. Legacy `--profile`,
  `--full`, `--passive`, `-m` still choose *candidate* modules but are filtered by
  the mode ceiling (a note is printed). With **no** `--mode`, behaviour is
  unchanged (ceiling defaults to `active`, legacy selection applies) — fully
  backward-compatible. `--mode full` supersedes `--full`.

## Architecture (BBOT-style, event-driven)

`Event` (12 types in `events/types.py`: SUBDOMAIN, DNS_RECORD, IP, OPEN_PORT,
HTTP_SERVICE, TECHNOLOGY, URL, ENDPOINT, PARAMETER, ANOMALY, FINDING_CANDIDATE,
EMAIL) is the atom. Modules emit events; the `EventBus` (`events/bus.py`) fans out to
handlers and dedups by `dedup_key` (bounds recursion / graph cycles).

`EMAIL` (`EmailData`: `address`/`source`/`found_in`) carries a discovered email.
Emails are **PII**, so the type is explicit and producers must stay in-scope: an
EMAIL is scoped by its **domain** (`ScanController._candidate_from` returns the
part after `@`), so the gate drops third-party addresses automatically — an
`user@evil.com` found on an in-scope page is *not* kept. Dedup key is the
lowercased address. Producers: **jsintel** (`web-body` — `mailto:` + inline) and
**metascan** (`document-metadata` — author/creator fields).

Two module kinds (`modules/base.py::BaseModule`):
- **Seed** (`watched_events=[]`): run once in parallel at scan start (subfinder, crt_sh, …).
- **Reactive** (`watched_events=[...]`): subscribed to the bus, fire on matching
  events (dnsx: SUBDOMAIN→IP/DNS_RECORD; httpx_probe: IP/OPEN_PORT→HTTP_SERVICE; …).

`ScanController` (`controller/controller.py`) owns the lifecycle and wires
scope + bus + modules + (optional) AI/agent.

**Vhost-aware probing:** `httpx_probe` watches `SUBDOMAIN` (not just `IP`/`OPEN_PORT`), so `HTTP_SERVICE` is keyed on the **hostname** and the whole web chain (ffuf/nuclei/fingerprint/katana/corscanner/bypass403/secretfinder) hits the real name-based vhost with the correct Host header — and works on domain-only scope without adding the resolved IP. (Fuzzing the bare IP hit the empty default vhost and found nothing.)

### Two-layer tool design (important)
- `recon/` = low-level **subprocess wrappers** that execute the actual binaries
  (subfinder, dnsx, httpx, gau, nuclei, bbot). This is the execution layer.
- `modules/` = the **event-driven module layer** that wraps those recon wrappers
  (and pure-Python passive sources) into the BBOT-style system.
  `modules/active/dnsx.py` etc. delegate to `recon/dnsx.py`. `recon/` is not
  legacy — `modules/` depends on it.

Module registry (`modules/registry.py`): auto-discovery via `@register` +
`pkgutil`. Load by name, by flag (`passive|active|web|dns|slow|fast`), or defaults.
- `DEFAULT_MODULES = [subfinder, dnsx, httpx_probe]`
- `PASSIVE_MODULES = [crt_sh, certspotter, hackertarget, wayback]` (pure-Python, no binaries)
- Groups: `EXTRA_PASSIVE`, `DEEP_DNS`, `WEB`, `CRAWL`, `DISCOVERY`, `FULL`
- Secret scanning: **secretfinder** (`modules/web/secretfinder.py` + `recon/secrets.py`) watches `HTTP_SERVICE`+`URL`, fetches bodies/JS/maps, regex+entropy detects exposed keys/tokens → `FINDING_CANDIDATE` (category `exposed-secret`). Secrets are **redacted** before hitting any event (never stored/logged/sent to LLM). 4xx/5xx bodies are scanned too (debug/stack-trace pages are a prime leak spot; `evidence.http_status` records it), and the finding title embeds the redacted value so distinct keys of one type on a host don't collapse under the `host:title:category` finding dedup key.
- Secret scanning (binary): **trufflehog** (`modules/web/trufflehog.py` + pure wrapper `recon/trufflehog.py`) subclasses secretfinder (same triggers + shared-limiter fetch via `_target_url`/`_fetch_text`) but detects with trufflehog's ~800 detectors. Start-up (~1s) dwarfs per-doc scan time, so bodies are written to a private temp dir and scanned **`batch_size` (25) per `trufflehog filesystem` run** (one guarded op), remainder flushed in `finish()`; results map back to URL/event by file name; identical bodies per host scanned once. trufflehog's JSON carries the full secret (`Raw`/`RawV2`/`SecretParts`) — `parse_trufflehog_json` redacts `Raw` immediately and drops the rest. Title embeds the redacted value so distinct keys don't collapse under the finding dedup key. **Verification is OFF by default** (`--no-verification`); `verify=True` sends candidates to provider APIs (third-party traffic using a leaked credential — check program rules). Severity: verified→critical, unverified high-impact detector→high, else medium. Warn-and-skips without the binary. In `DISCOVERY` / `--full` (runs alongside secretfinder; `-m trufflehog` alone).
- Smart content fuzzing (binary): **ffuf** (`modules/web/ffuf.py` + wrapper `recon/ffuf.py`) is recon-ai's **single content-discovery fuzzer** (the former native `dirsearch` module was removed — ffuf is the one forced-browser). Watches `HTTP_SERVICE`; the distinguishing feature is **smart catch-all calibration** — before fuzzing it probes N random paths through the shared limiter (`self.guard`/`inspect_response`) and `recon/ffuf.py::derive_calibration` decides the noise filters: an app that answers **the same status to everything** (the "301/403/404 for every path" case) is detected and filtered: a **redirect/error catch-all** (3xx/4xx/5xx) is filtered by **status code** (`-fc` — matches "filter out the 301s and hunt for other codes", and robust to CDN/error-page body-size drift under load, which a single `-fs` value leaks), while a **2xx wildcard/SPA** is filtered by **size** (`-fs`, since all-2xx can't be blanket-dropped); when no baseline can be learned it defers to ffuf's own `-ac`. `build_command`/`parse_ffuf_json`/`is_real_find` are pure and unit-tested. ffuf runs with `-mc all` minus the calibrated filters; the whole run is one guarded op and its `-rate`/`-t` derive from the shared `RateLimiter` (`rate_per_sec`/`max_concurrency`). Before emitting, every parsed row passes an **unconditional noise gate** (`recon/ffuf.py::is_real_find`) independent of the per-host calibration: statuses that never indicate a resource (`NOISE_STATUS` = 400/404/429/5xx) and **empty-bodied 2xx** catch-all stubs (e.g. a CloudFront `200 len=0`) are dropped even though `-mc all` surfaces them and a mis-learned baseline could let them through; 401/403/405 ("exists but protected / wrong method") are deliberately kept. Emits scope-gated `URL` events (`found_via="ffuf"`). Internal recursion into discovered directories via ffuf's own `-recursion` (off by default; `recursion`/`recursion_depth` options, raised in the `paranoid` profile). Consumes the **wordlist_learner** export (`wordlist=<path>` option) when you point it at one. **Requires the `ffuf` binary** — warn-and-skips without it, so install ffuf for any content-discovery run (it is no longer optional now that the no-binary dirsearch fallback is gone). In the `DISCOVERY` group / `--full`.
- Intelligent extension fuzzing (pure Python, no binary): **extfuzz** (`modules/web/extfuzz.py` + pure engine `recon/extfuzz.py`) finds the files that sit *beside* a path recon-ai already knows — `/js/app.js` → `/js/app.js.map`/`.bak`, `/download.php` → `/download.bak`/`.old` — which a dictionary fuzzer (ffuf) never reaches because they aren't words. Complements ffuf (paths) rather than duplicating it. Watches `URL`+`ENDPOINT`+`HTTP_SERVICE`+`TECHNOLOGY`. **Three strategies** (`generate_candidates`, all pure/unit-tested): **append** (`app.js`→`app.js.bak`, and `admin`→`admin.php`), **replace** (`app.js`→`app.bak`), **extensionless** (`download.php`→`download`), de-duplicated and query/fragment-stripped; a pure directory or a static image/font base is skipped. **Configurable + technology-aware extensions**: the base list (`extensions` option) is prioritized per host by `tech_extensions` (PHP→`php/phtml/inc`, ASP.NET→`aspx/config`, Java→`jsp/war`, SPA→`js/map`), and the AI may **propose** extra extensions via the `ai_extensions` option which are always run through the deterministic `normalize_extension` gate (strict charset/length/count) before any request — AI never reaches the network or scope. **Intelligent response analysis** (`recon/extfuzz.py::classify`, pure): records status/content-type/length/redirect and returns a verdict + confidence — the cardinal rule is **a bare 200 is never a file** (requirement #3); a confirmed `file` needs corroboration (matching content-type or a structural body signature: JSON/XML/PDF/source-map/SQL-dump/key=value config), a 200 that merely returns a non-HTML non-baseline body is only `ambiguous` (a lead), and HTML served for a non-HTML extension, an empty 2xx, or a response matching the host's learned catch-all **baseline** (`build_baseline`, random-path probes like apifinder/ffuf) is a `soft-404`; `redirect`/`auth` (401/403 or login page)/`waf` (429 or block-page body) are classified distinctly. **Adaptive selection** also pulls high-confidence `FILES` vocabulary from the `KnowledgeBase` (prior scans; optional, bounded) as extra origin stems, and **feeds confirmed files back** to the KB. **Emission**: scope-gated `URL` (`found_via="extension-fuzz"`, re-enters for secretfinder/jsintel/apifinder) for real/ambiguous/protected/redirect hits ≥ `emit_min_confidence`, and a `FINDING_CANDIDATE` (`exposed-file:<category>` — backup/archive/database-dump/config/source-map/log-file, severity low–medium) **only** for a corroborated interesting file ≥ `finding_min_confidence`, with evidence (status/type/length/confidence/reason) and wording that never claims exposure without verification. Safety: candidates only ever target the same already-in-scope host as their seed, all GETs go through `BaseModule.fetch` (shared limiter / WAF backoff / response cache, `follow_redirects=False`), per-path/per-host/total candidate budgets bound the work, and it never executes, authenticates to, or exploits a discovered file. Cascade-safe (skips seeds whose `found_via` is its own, plus a per-candidate `_tested` set). In the `DISCOVERY` group / `--full` (broader extension list + higher per-host cap in `paranoid`).
- Parameter discovery: **paramfinder** (`modules/web/paramfinder.py`) watches `URL`+`ENDPOINT`, extracts query-string params and endpoint parameter names (pure Python, no network) → `PARAMETER` events. It is the producer for the `PARAMETER` type (the dedup key + `ParameterData` already existed). `sample_value` is sanitized/capped by the `ParameterData` validator like every other target string. In the `DISCOVERY` group / `--full`.
- JS & API endpoint discovery: **apifinder** (`modules/web/apifinder.py`) watches `HTTP_SERVICE`+`URL`, fetches JS/HTML/JSON bodies via the shared limiter and regex-extracts (deterministic, no LLM) JS-referenced URLs (absolute/proto-rel/root-rel/path-rel, all resolved), API paths (`/api/`, `/api/vN`), GraphQL/Swagger/OpenAPI/api-docs locations, and query params → emits existing `URL`/`ENDPOINT`/`PARAMETER`/`TECHNOLOGY` events. Also probes a configurable well-known API/doc path list (`options["well_known_paths"]`, not the sole mechanism) per live service and emits **only the paths that actually respond** (a 404/dead host is dropped, so it no longer fabricates phantom endpoints); a live 2xx spec (swagger/openapi) is additionally mined for real refs. All emission goes through `self.emit`→`stamp_and_publish`→ScopeEngine, so discovered URLs are scope-gated + dedup'd and re-enter the pipeline (linkfinder/paramfinder/secretfinder/httpx_probe react). Pure extraction helpers (`discover`, `resolve_ref`, `classify_api_url`, `params_from_url`) are unit-tested directly. In the `DISCOVERY` group / `--full`.
- JavaScript Intelligence Engine: **js_intel** (`modules/web/jsintel.py` + pure engine `recon/jsintel.py`) is the first-class JS analysis pipeline (complements apifinder's generic URL mining). Watches `HTTP_SERVICE`+`URL`; fetches HTML/JS via the shared limiter, **dedups JS resources** (per-URL + per-body-hash cache), and runs `recon/jsintel.py::analyze` — an **extensible extractor architecture** (`Extractor` subclasses in `DEFAULT_EXTRACTORS`; add/swap one — e.g. an AST-based extractor — without touching the engine). Extracts, deterministically: relative/absolute API paths + versions, GraphQL op/type names, **WebSocket URLs** (`ws://`/`wss://`, incl. `new WebSocket()`), **source-map references** (`//# sourceMappingURL=`, quoted `.map`), **configuration indicators** (`apiBaseUrl`/`__CONFIG__`/`import.meta.env.X`/`process.env.X` — names only, never values; secrets stay with secretfinder), **email addresses** (`EmailExtractor` — `mailto:` + inline, noise like `foo@2x.png`/sentry keys rejected), **route names**, **service/client names**, **technology indicators** (Webpack/React/Vue/Angular/Next/Nuxt/Firebase/Sentry/Stripe/Apollo…), and JS identifiers (reusing `recon/vocabulary.extract_from_js`). Handles **inline** `<script>` (folded into analysis) and **external** `<script src>` (emitted as `URL` to re-enter). Emits structured `URL`/`ENDPOINT`/`PARAMETER`/`TECHNOLOGY`/`ANOMALY`/`EMAIL` (source maps → `exposed-source-map`; config → `js-config-indicator`) all via `self.emit`→scope gate (provenance via `source_event_id` + `found_via`), and **feeds the learning system** (`controller.knowledge_base.learn_many`). Endpoints come only from URL-shaped/structural contexts (no blindly treating arbitrary strings as endpoints). Pure engine unit-tested with a realistic bundle fixture. In the `DISCOVERY` group / `--full`.
- Tech fingerprinting: **fingerprint** (`modules/web/fingerprint.py`) watches `HTTP_SERVICE` → `TECHNOLOGY`. There is no bespoke fingerprint DB — httpx's bundled **Wappalyzer** DB is the source: `recon/httpx_wrap.py` runs `httpx -td`, `parse_httpx_json` captures the `tech` array into `HttpServiceData.technologies`, and fingerprint normalizes each (split `Name:version`, best-effort category) → `TECHNOLOGY` with `source="httpx"`. A small regex signature set (server header / title / URL path) is the no-binary fallback (`source="heuristic"`). Optional **whatweb** (`modules/web/whatweb.py` + `normalize.parse_whatweb_json`) is a second source (`source="whatweb"`, warn-and-skips without the binary). `TechnologyData.source` records provenance; dedup is by `host:name:version` (source excluded) so the same tech from multiple tools collapses to one event. All emission goes through the scope gate.
- Document/image metadata: **metascan** (`modules/web/metascan.py` + pure engine `recon/metadata.py`) watches `URL` and, for URLs whose extension is in `metadata.META_EXTS` (PDF, Office OOXML `.docx/.xlsx/.pptx` + legacy, JPEG/PNG/TIFF), downloads the file (scope-gated, rate-limited, size-capped via its **own** httpx client — it needs bytes, not the shared text cache) and extracts embedded metadata. Backend: **exiftool** if present (`exiftool -json -n`, richest), else the pure-Python fallback (`recon/metadata.py` — EXIF/OOXML/PDF). It keeps only a **sensitive-tag allowlist** (`_EXIFTOOL_MAP`: author/creator/lastModifiedBy/company/producer/software/make/model/artist/GPS/title/created) and **stays silent when a file has only technical tags** (ImageWidth/FileSize/… → no event), so scrubbed web assets produce nothing — that is correct, not a failure. Emits: `TECHNOLOGY` (authoring software, folded in from the former exifmeta module — `creator` needs a software hint so a human name is never emitted as tech), one `document-metadata` `ANOMALY` per file, a `metadata-disclosure` `FINDING_CANDIDATE` when `metadata.sensitive()` fields are present (low), and `EMAIL` for addresses embedded in metadata values. Feeds single-token author/lastModifiedBy values to the learning system as likely usernames. In the `DISCOVERY` group / `--full`. (exiftool install path + stale-PATH note under **Windows toolchain gotchas**.)
- Port scanning combo: **naabu** discovers open ports fast → **nmap** (`modules/active/nmap.py` + `recon/nmap.py`) watches `OPEN_PORT` and runs `-sV` for service/version → `TECHNOLOGY` events. nmap is `-sV -Pn -n` only (no NSE/OS-detect) unless opted in.
- Extra subdomain-enum techniques (all warn-and-skip without their binary, all scope-gated via `self.emit`): **zonetransfer** (dig AXFR seed → SUBDOMAIN + `dns-zone-transfer` FINDING_CANDIDATE), **tlsx** (TLS SAN → SUBDOMAIN), **hakip2host** (reverse-IP → SUBDOMAIN), **github_subdomains** (needs `GITHUB_TOKEN`), **takeover** (dangling-CNAME fingerprint, then HTTP-verifies the service's unclaimed-resource page before emitting: confirmed→HIGH, live/claimed→dropped, no-signature/unreachable→LOW unverified → `subdomain-takeover` FINDING_CANDIDATE), **puredns** (wildcard-safe massdns brute), **gotator** (permutation engine → dnsx resolve), **urlfinder**/**waymore** (passive URL enum → URL), **csprecon** (pure-Python CSP-header host extraction → SUBDOMAIN), and cloud buckets **s3scanner**/**cloud_enum** (`CLOUD` group → `cloud-bucket` FINDING_CANDIDATE; no Alibaba OSS). Shared subprocess helper: `BaseModule.run_proc()`.
- Cloud Asset Intelligence: **cloud_intel** (`modules/web/cloudintel.py` + pure engine `recon/cloudintel.py`) is an evidence-based correlation subsystem (passive; no binary) that identifies the cloud infrastructure behind an authorized target. Watches `SUBDOMAIN`+`DNS_RECORD`+`HTTP_SERVICE`+`TECHNOLOGY`+`URL` and correlates signals from DNS/CNAME targets, HTTP `server` headers + header names (`x-amz-*`/`x-goog-*`/`x-azure-ref`/`cf-ray`…), fingerprinted technologies, and cloud URLs referenced in JS/config. Fingerprint DB (`recon/cloudintel.py`) covers **AWS** (S3, CloudFront, ELB/ALB, API Gateway, Global Accelerator), **Azure** (Blob/Storage, App Service, Front Door/CDN, Traffic Manager, API Mgmt, SQL, Key Vault), **GCP** (GCS, App Engine, Cloud Run, Functions, APIs), **Firebase** (RTDB, Hosting, Storage), and CDNs (Cloudflare/Fastly/Akamai/StackPath/BunnyCDN/KeyCDN/CDN77). `CloudCorrelator` folds independent signals per `(host, provider, service)` with a **noisy-OR confidence** (capped at 1.0), retaining evidence + provenance sources; **dedup** is per asset key. Represents assets in the knowledge graph as live `TECHNOLOGY` events (cloud stack on the host) + one `cloud-asset` `ANOMALY` per asset (≥ `min_confidence`, default 0.5) at `finish()`. **Passive identification is separate from active verification**: `options["verify"]` (default off) does a single scope-approved, **read-only benign GET** to check for a public bucket listing → `exposed-cloud-storage` FINDING_CANDIDATE; it never enumerates, writes, authenticates, or takes destructive cloud action. All emission is scope-gated via `self.emit`. In the `CLOUD` group / `--full`.
- Censys host enrichment: **censys** (`modules/passive/censys.py` + pure parser `recon/censys.py`) enriches discovered IPs via the Censys **Platform** API free-tier **host lookup** (`GET /v3/global/asset/host/{ip}`). Watches `DNS_RECORD` (A/AAAA) + `IP`, and for each IP emits scope-gated `ANOMALY` (`host-org` — ASN/organization + service count, the "organisation IP" intel), `OPEN_PORT`/`TECHNOLOGY` (Censys-observed services), and `SUBDOMAIN` (Censys DNS names — the scope gate drops co-tenant/junk names from shared IPs and keeps only in-scope org hostnames, which re-enter the pipeline). Note: Censys **domain search** is a paid feature (free keys get 403), so this enriches known IPs rather than enumerating from a domain. Credentials via env: `CENSYS_API_KEY` (Platform PAT `censys_…`; the module warn-and-skips without it, never logs the key), optional `CENSYS_ORG_ID` (`X-Organization-ID`, paid tiers). The key's **1-concurrent-request** limit is enforced by a dedicated `asyncio.Lock` (on top of the shared RateLimiter); `max_lookups` caps quota use. In `EXTRA_PASSIVE` / `--full` / `-p fast`.
- Persistent reconnaissance learning system: **wordlist_learner** (`modules/web/wordlist.py` + pure engine `recon/vocabulary.py` + service `database/knowledge_base.py`) watches `URL`+`ENDPOINT`+`PARAMETER`+`TECHNOLOGY` (events the bus already scope-checked) and learns *reusable* recon vocabulary into a cross-scan store so discovery improves over time. Deterministic, network-free extraction (`recon/vocabulary.py`, no LLM): splits paths into directory/file/endpoint/api-path/api-version/resource tokens, extracts parameter **names** (and values only when `is_safe_value` — short, low-entropy, non-secret), plus JS identifiers / GraphQL names / OpenAPI paths / cloud naming patterns (13 `CATEGORIES`). Pipeline: normalize → quality-filter (rejects numeric ids, UUIDs, hash/hex blobs, hashed-asset chunks, stop-words, static assets) → **4 knowledge scopes** (`global` / `technology`=tech name / `target`=seed domain / `organization`=operator label) → dedup (DB `UniqueConstraint` on `(scope_type,scope_key,category,value)` + `(…,target)`) → **confidence scoring** (`confidence(target_count,occurrence_count)`, breadth-weighted, 0..1; a learned string is a *candidate*, never proof a resource exists) → persistence. `KnowledgeBase.generate_wordlist(category, scope, min_target/occurrence/confidence, limit)` builds a ranked, filtered list (broadest/most-confident first) exportable to a file the **ffuf** module consumes via `wordlist=<path>`. Writes are lock-serialized on its own AsyncSession. Needs `--db-url`; without it the module warn-and-skips. CLI: `recon-ai wordlist stats|export <category> [--scope … --scope-key … --min-confidence …]`. In the `DISCOVERY` group / `--full`.
- Vulnerability assessment: **vulnassess** (`modules/web/vulnassess.py` + the `vulnscan/` package) consumes recon events (`TECHNOLOGY`/`HTTP_SERVICE`/`URL`/`ENDPOINT`/`PARAMETER`/`ANOMALY`/`FINDING_CANDIDATE`) and, at `finish()`, runs technology-aware native checks → structured, evidence-backed `FINDING_CANDIDATE`s (category `vuln:<check_id>`, with confidence + `OBSERVED`/`POTENTIAL`/`UNCONFIRMED`/`CONFIRMED` status in `evidence`). Passive + low-impact active by default; intrusive tier off unless explicitly authorized. See the **Evidence-based vulnerability assessment** section above. In the `ASSESS` group / `--full`.
- Profiles: `fast` (passive only) · `default` · `full` · `paranoid`

## Directory map

| Path | Role |
|---|---|
| `scope/` | Scope engine + types — the deterministic gate. The heart of the system. |
| `events/` | Event model (`types.py`), pub/sub `bus.py`, `dedup.py` |
| `recon/` | Subprocess wrappers around external binaries + `vocabulary.py` (learning extractor) + `jsintel.py` (JS-intelligence engine) + `cloudintel.py` (cloud-asset correlation engine) + `extfuzz.py` (extension-fuzzing engine — candidate generation + intelligent response classification) + `fetch.py` (shared per-scan HTTP body cache — one GET per URL, fanned out to every body-consuming module via `BaseModule.fetch`) |
| `modules/` | Event-driven modules: `passive/`, `active/`, `web/` + `base.py`, `registry.py` |
| `controller/` | `controller.py` (scan lifecycle) |
| `database/` | SQLModel models, repositories, persister, session, diff, `knowledge_base.py` (persistent recon-learning service) (asyncpg/aiosqlite) |
| `ai/` | `assessor.py` (forced-schema LLM call), `triage.py` (post-scan), `prompts/` |
| `agent/` | Phase-4 agent loop: `loop.py`, `approval.py`, `stopping.py`, `tools.py` |
| `mcpserver/` | FastMCP server exposing 8 tools; `context.py` in-process scan registry |
| `ratelimit/` | `RateLimiter` + `waf.py` — throttling & adaptive WAF backoff (used everywhere) |
| `planner/` | `ReconPlanner` — Adaptive Reconnaissance Planner (gates which modules run; cost/value/technology/budget-aware) |
| `policy/` | Central mode & capability policy — maps modules/actions to capabilities and enforces the selected `--mode` (osint/active/vuln/full) at module load, the network primitives, and the agent tools. ScopeEngine stays the scope gate. |
| `vulnscan/` | Evidence-based vulnerability assessment: `schema.py` (VulnResult + status/severity), `checks.py` (Check interface + native checks + registry), `cve.py` (version→CVE correlation, uncertainty-aware), `engine.py` (per-host context + tech-aware selection + isolation), `report.py` (JSON + human report). Driven by the `vulnassess` module. |
| `normalize/` | Output parsers |
| `cli/main.py` | Typer CLI (entry: `recon-ai`) |
| `alembic/` | DB migrations |
| `tests/` | `security/` (scope engine) + `unit/` (609 tests, all passing) |
| `wordlists/` | `combined.txt` (deduped content-discovery list, ffuf default), `dns_names.txt` |

Entry points (pyproject): `recon-ai = cli.main:app`, `recon-ai-mcp = mcpserver.server:main`.

Repo root is clean — earlier stray duplicates (`types.py`, `engine.py`,
`__init__.py`, `test_scope_engine.py`) that shadowed the `scope/` package and
`tests/` have been removed. The canonical files live under `scope/` and `tests/`.

## Running it

```bash
python -m cli.main scan example.com                 # deterministic, no AI/DB (active ceiling, default modules)
python -m cli.main scan example.com --mode osint    # PASSIVE ONLY — technically unable to probe the target
python -m cli.main scan example.com --mode active   # passive + full active recon + non-intrusive vuln checks
python -m cli.main scan example.com --mode vuln     # minimal discovery + vulnerability assessment
python -m cli.main scan example.com --mode full     # complete authorized pipeline
python -m cli.main scan example.com --mode full --intrusive   # + intrusive tier (explicit authorization)
python -m cli.main scan example.com --passive       # (legacy) + passive modules
python -m cli.main scan example.com --full          # (legacy; = --mode full) all modules
python -m cli.main scan example.com -p fast         # a profile
python -m cli.main scan example.com -m crt_sh -m dnsx   # explicit modules (replaces defaults)
python -m cli.main scan example.com -r 5 -c 20      # 5 req/s per bucket, max 20 concurrent ops
python -m cli.main scan example.com --plan-mode passive-first   # planner: passive modules only
python -m cli.main scan example.com --full --plan-mode aggressive --budget 500   # cost-capped aggressive
python -m cli.main modules [--profiles]             # list modules / profiles
python -m cli.main scan example.com --ai   --db-url "sqlite+aiosqlite:///recon.db"
python -m cli.main scan example.com --agent --db-url "sqlite+aiosqlite:///recon.db"
python -m cli.main history example.com --db-url ...
python -m cli.main diff <scan_a> <scan_b> --db-url ...
python -m cli.main wordlist stats --db-url ...                          # KB size per category/scope
python -m cli.main wordlist export directories --db-url ... [--scope technology --scope-key wordpress] [--min-confidence 0.6] [-O dirs.txt]
python -m cli.main triage <scan_id> --db-url ...
python -m cli.main report <domain|scan_id> --db-url ...          # vulnerability report (text)
python -m cli.main report <domain|scan_id> --db-url ... --json -O report.json   # structured JSON
```
`--ai`/`--agent` need `ANTHROPIC_API_KEY` + `--db-url`. Default AI model string
in code is `claude-sonnet-4-6`. Scope defaults to `[*.domain, domain]` if
`--in-scope` omitted; `--out-scope` deny always wins (an exact out-scope host also excludes its whole subtree, e.g. `x.abc.com` ⇒ `*.x.abc.com` OUT); `--max-distance` default 5.

Every scan prints a readable end-of-scan **SCAN SUMMARY** (subdomains, ports, HTTP services, technologies, emails, findings) via `ScanController.print_summary()`; per-event logging is DEBUG-only (`-v` to see it).

Tests: `pytest` (config in pyproject; `asyncio_mode=auto`).

## Windows toolchain gotchas (this machine)

- **Prepend Go bins first:** `export PATH="/c/Users/samee/go/bin:$PATH"` — else
  ProjectDiscovery `httpx` is shadowed by Python's `httpx` CLI and silently
  produces no HTTP_SERVICE events.
- `nuclei` won't `go install` here (32-bit MinGW / CGO) — use the prebuilt release.
- `naabu` SYN scans need Npcap.
- Built & working in go/bin: subfinder, dnsx, httpx(PD), naabu, katana, ffuf, trufflehog (v3.97.9 prebuilt release, checksum-verified — `go install` has the same 32-bit issue as nuclei). **ffuf is the sole content-discovery fuzzer** (the native dirsearch fallback was removed), so the `ffuf` binary is **required** for any content discovery, not optional.
  Missing/optional (modules warn-and-skip): gau, gowitness, amass, assetfinder, findomain.
- **exiftool** (v13.59, `OliverBetz.ExifTool` via winget) is installed at
  `C:\Users\samee\AppData\Local\Programs\ExifTool\exiftool.EXE` and on the User
  PATH. The **metascan** module auto-prefers it (`shutil.which("exiftool")` →
  `exiftool -json -n`); without it, metascan falls back to the pure-Python
  extractor (`recon/metadata.py`). A shell started before the install has a stale
  PATH — prepend `export PATH="/c/Users/samee/AppData/Local/Programs/ExifTool:$PATH"`
  (like the go/bin note) for scans launched from it; new terminals pick it up.
- **Scope note:** resolved IPs are OUT under a domain-only scope (deny-first).
  Add `--in-scope <ip/CIDR>` to let httpx_probe/naabu touch a host.

## Status

All 5 phases complete (scope engine → events/DB/recon → AI triage → agent loop →
module system + MCP). 609 tests passing. See persistent memory
`project-recon-ai` and `reference-toolchain-env` for the fuller record.
