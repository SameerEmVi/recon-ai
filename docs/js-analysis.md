# JavaScript Analysis Subsystem — Developer Reference

How recon-ai turns a target's JavaScript (and HTML) into reconnaissance signal,
traced end to end **from the moment the scan reaches a host**. Grounded in the
current code: `modules/web/jsintel.py` (event-driven module) and
`recon/jsintel.py` (pure engine).

> TL;DR — `js_intel` reacts to a live web service, fetches its HTML/JS through
> the shared HTTP layer, runs a pipeline of small regex **extractors** over the
> body, and emits scope-gated `URL` / `ENDPOINT` / `PARAMETER` / `TECHNOLOGY` /
> `ANOMALY` / `EMAIL` events that re-enter the scan. It is **regex/heuristic**,
> **deterministic** (no LLM), and complements three sibling modules:
> `apifinder`, `linkfinder`, `jsluice` (AST), and `retirejs` (vuln libs).

---

## 1. Where it sits

recon-ai is event-driven. JS analysis is **not** a crawler — it is a set of
reactive modules that consume events other modules produce and emit new ones:

```
subfinder/dnsx ─▶ SUBDOMAIN/IP ─▶ httpx_probe ─▶ HTTP_SERVICE ─┐
                                                               ├─▶ js_intel  (this doc)
wayback/gau/katana/apifinder ─▶ URL ───────────────────────────┤   linkfinder
                                                               ├─▶ apifinder
                                                               ├─▶ jsluice (AST, binary)
                                                               └─▶ retirejs (vuln libs, binary)
```

| Module | Layer | Technique | Produces | Binary? |
|---|---|---|---|---|
| **js_intel** | `modules/web/jsintel.py` + `recon/jsintel.py` | regex extractors, inline+external JS | URL, ENDPOINT, PARAMETER, TECHNOLOGY, ANOMALY, EMAIL | no |
| linkfinder | `modules/web/linkfinder.py` | single endpoint regex | ENDPOINT | no |
| apifinder | `modules/web/apifinder.py` | generic URL/API mining + well-known probing | URL, ENDPOINT, PARAMETER, TECHNOLOGY | no |
| jsluice | `modules/web/jsluice.py` + `recon/jsluice.py` | tree-sitter **AST** | ENDPOINT (+ params), URL | **yes** (`jsluice`) |
| retirejs | `modules/web/retirejs.py` + `recon/retirejs.py` | library fingerprint → CVE | TECHNOLOGY, FINDING_CANDIDATE | **yes** (`retire`) |

This document focuses on **js_intel**; §8 covers how the siblings differ.

---

## 2. Two-layer design

Like the rest of recon-ai's tooling, JS analysis is split so the logic is pure
and unit-testable and the I/O lives in the module:

- **`recon/jsintel.py` — the engine (pure).** No network, no DB, no LLM; never
  raises on bad input. Takes a text body + its source URL, returns a
  `JsAnalysis` dataclass of typed observations. This is where the extractors and
  all parsing live.
- **`modules/web/jsintel.py` — the module (I/O + orchestration).** Subscribes to
  the event bus, fetches bodies through the shared HTTP layer, calls
  `jsintel.analyze(...)`, dedups/caches, and emits events through the scope gate.

The boundary matters: you can add a new signal by writing one `Extractor`
subclass in the engine and registering it in `DEFAULT_EXTRACTORS` — the module,
the scope gate, and the tests stay unchanged.

---

## 3. End-to-end flow (from "scan hits the host")

### Step 0 — Trigger
`js_intel.watched_events = ["HTTP_SERVICE", "URL"]`. It fires when:
- **`httpx_probe` emits `HTTP_SERVICE`** for a live host (e.g.
  `https://amaru.co.nz/`) — analyzed as **HTML**; or
- **any module emits a `URL`** (wayback, katana, apifinder, js_intel itself) that
  is *fetchable* JS/HTML/JSON — analyzed as JS or HTML by extension.

Before the handler runs, the **Adaptive Planner** decides whether js_intel is
worth running for that event (cost/value/budget/per-host cap), and the scope
engine has already confirmed the event is in scope.

### Step 1 — Fetchability gate (`_is_fetchable`)
For `URL` events, js_intel only fetches bodies that look analyzable:
- if a `content-type` is known → must contain `javascript`, `html`, or `json`;
- else by path extension → `""`, `.js`, `.mjs`, `.cjs`, `.json`, `.html`, `.htm`
  (the service root `/` always qualifies).

This stops it downloading images/fonts/binaries.

### Step 2 — Resource dedup (`_analyzed_urls`)
The URL is normalized (`_norm_url`: strip query + fragment) and checked against a
per-scan set. **Each JS resource is fetched at most once**, even if many pages
reference it.

### Step 3 — Fetch (shared HTTP layer)
`self.fetch(url, timeout, max_body_kb=2048)` → `BaseModule.fetch` →
the shared per-scan `ResponseCache` + `RateLimiter` + WAF backoff + **proxy**
(if configured). So:
- one network GET per URL across *all* body-consuming modules (shared cache);
- the request obeys the scan's rate/concurrency limits and WAF backoff;
- it routes through Burp when `--proxy` is set.
Only `2xx` bodies with text proceed.

### Step 4 — Body-hash cache (`_body_hashes`)
`sha256(body)` is checked against a per-scan set. **Identical bodies are analyzed
once** — e.g. the same bundle served under two URLs, or a CDN-duplicated asset.

### Step 5 — Analyze (`recon.jsintel.analyze`)
The body (capped at `max_len = 4,000,000` chars) is run through the extractor
pipeline. **If it's HTML, inline `<script>` bodies are folded into the analyzed
text** (`inline_scripts`), so inline JavaScript is first-class input. External
`<script src>` URLs are *not* analyzed here — they're returned separately.

### Step 6 — Follow external scripts
If the body was HTML and `follow_script_src` is on (default), each resolved
`<script src>` URL is emitted as a `URL` event (`found_via="js-intel"`). Those
re-enter the bus and come back to js_intel at Step 0 — that's how external
bundles get analyzed (one hop later), after passing the scope gate.

### Step 7 — Emit (scope gate chokepoint)
Every observation is emitted via `self.emit → stamp_and_publish → ScopeEngine`.
Nothing bypasses scope; JS-controlled strings are sanitized by the event
validators like any other input. Emissions are **capped at `max_emit = 400` per
body** to bound fan-out. Mapping:

| `JsAnalysis` field | Emitted as | Notes |
|---|---|---|
| `urls` | `URL` (`found_via=js-intel`) | absolute http(s), static assets dropped |
| `endpoints` | `ENDPOINT` + `TECHNOLOGY` | API-classified URLs; GraphQL/Swagger tags → tech |
| `routes` | `URL` (`found_via=js-route`) | resolved against the page origin |
| `params` | `PARAMETER` (`location=query`) | query-param names only |
| `websockets` | `URL` (`found_via=js-websocket`) | `ws://`/`wss://` |
| `source_maps` | `URL` (`found_via=js-sourcemap`) + `ANOMALY` `exposed-source-map` | if `flag_source_maps` |
| `config_indicators` | `ANOMALY` `js-config-indicator` | **names only, never values** |
| `technologies` | `TECHNOLOGY` (`source=js_intel`) | dedup per (host, tech) |
| `emails` | `EMAIL` (`source=web-body`) | scope-gated by email domain |

### Step 8 — Feed the learning system
`_feed_learning` converts endpoints/routes/params/services/identifiers/graphql
names into `vocabulary.Candidate`s and calls `knowledge_base.learn_many(...)`
(only when `--db-url` gave the scan a `KnowledgeBase`). This is how discovery
vocabulary improves across scans (and feeds ffuf's wordlist export).

---

## 4. The extractor pipeline (`DEFAULT_EXTRACTORS`)

Each extractor is a small class with `extract(content, base_url, analysis)` that
**mutates `analysis` in place and must never raise** (the engine wraps each in
try/except so one bad extractor can't break the run). Order is fixed; dedup is
per-field via `JsAnalysis.add`.

| Extractor | What it finds | How |
|---|---|---|
| `UrlExtractor` | absolute / protocol-relative URLs in quotes | regex; resolved to absolute; static exts dropped; API-classified |
| `ApiPathExtractor` | root-relative + multi-segment relative **API** paths | regex; kept only if `classify_api` tags it; also harvests query-param names |
| `WebSocketExtractor` | `ws://`/`wss://` and `new WebSocket("…")` | regex; relative refs resolved then scheme-swapped |
| `EmailExtractor` | `mailto:` links + inline `user@host.tld` | regex; rejects `@2x.png`, sentry keys, asset filenames |
| `SourceMapExtractor` | `//# sourceMappingURL=…` and quoted `*.map` | regex; resolved to absolute |
| `ConfigIndicatorExtractor` | config-ish identifier **names** (`apiBaseUrl`, `__CONFIG__`, `import.meta.env.X`, `process.env.X`) | regex on assignment keys + known globals — **names only** |
| `RouteExtractor` | `path:"/x"`, `@Get("/x")` style route declarations | regex on structural keys/decorators |
| `ServiceNameExtractor` | `*Service`/`*Client`/`*Api`/`*Repository`/`*Controller`/`*Gateway`/`*Store` class names | regex |
| `TechnologyExtractor` | Webpack/Next/Nuxt/React/Vue/Angular/Svelte/GTM/Sentry/Firebase/Stripe/Apollo | signature regex set |
| `VocabularyExtractor` | JS identifiers + GraphQL op/type names | delegates to `recon.vocabulary.extract_from_js` |

### Shared parsing rules
- **`resolve(ref, base_url)`** — turns any ref into an absolute, fragment-less
  http(s) URL; returns `None` for non-http(s)/hostless/unparseable refs (so
  `tel:`, `data:`, relative junk never become "URLs").
- **`_has_static_ext`** — drops `.png/.css/.woff/.mp4/.pdf/.zip/…` so assets
  aren't mistaken for endpoints.
- **`classify_api(url)`** — tags a URL `graphql | swagger | openapi | api-docs |
  api-version | api` or `None`. Only API-tagged paths become `ENDPOINT`s — the
  engine deliberately **does not treat arbitrary strings as endpoints**.

---

## 5. HTML vs JS handling

- **HTML** (service root or `.html`): inline `<script>` bodies are concatenated
  into the analyzed text, and external `<script src>` URLs are emitted to be
  fetched on the next hop. So a single homepage fetch yields (a) inline-JS
  signal immediately and (b) a set of bundle URLs to analyze next.
- **JS** (`.js/.mjs/.cjs`): analyzed directly.
- **JSON**: fetched and run through the same extractors (URLs/params/etc. in JSON
  config are caught).

---

## 6. Configuration (`options`)

| Option | Default | Meaning |
|---|---|---|
| `timeout` | 20 | per-fetch HTTP timeout (s) |
| `max_body_kb` | 2048 | skip bodies larger than this (per-caller cap at read) |
| `max_emit` | 400 | cap emitted URLs/endpoints/etc. per analyzed body |
| `follow_script_src` | true | emit external `<script src>` URLs to re-enter the pipeline |
| `flag_source_maps` | true | emit an `ANOMALY` for each referenced source map |

Planner metadata: `expected_value = 8` (high — rich structured surface), cost is
flag-derived (MEDIUM). Capability: `TARGET_HTTP_REQUEST` (it fetches from the
target), so it runs in `vuln`/`active`/`full`, never `osint`.

---

## 7. Safety & determinism properties

- **Deterministic, no LLM.** Pure regex/heuristics; reproducible.
- **Scope-gated output.** Every emission goes through `stamp_and_publish`; a
  JS-referenced URL to a third party is dropped by the scope engine.
- **Never raises.** Engine and each extractor are exception-isolated.
- **Secrets stay out.** Config indicators are **names only** — values are never
  captured (secret *values* are owned by `secretfinder`/`trufflehog`). Emails
  are PII and scope-gated by domain.
- **Bounded.** Resource dedup, body-hash cache, `max_len`, `max_emit`, shared
  rate limiter.

---

## 8. How the siblings differ (so you pick the right one)

- **linkfinder** — one broad endpoint regex over JS; emits `ENDPOINT` only.
  Lightweight, noisier. js_intel supersedes most of it with structural context.
- **apifinder** — generic URL/API mining **plus** active probing of a
  configurable well-known path list (`/api`, swagger/openapi/graphql locations),
  emitting only paths that actually respond. js_intel is JS-structure-focused;
  apifinder is URL/well-known-focused. They overlap on URLs but complement on
  intent.
- **jsluice** (AST, needs the `jsluice` binary) — tree-sitter parse recovers
  request URLs **with method + query/body param names**, including dynamically
  built ones regex misses. It fetches JS bodies the **same way** (its module
  calls `self.fetch` / `BaseModule.fetch`), so recon-ai supplies the response
  body; you only need the binary installed.
- **retirejs** (needs the `retire` binary) — fingerprints JS *libraries* by
  content/hash and maps the version to CVEs. Orthogonal to js_intel's URL/endpoint
  mining.

All of them read bodies through the one shared fetch path, so a given JS file is
downloaded once and fanned out.

---

## 9. Worked example (amaru.co.nz full scan)

- `httpx_probe` found `https://amaru.co.nz/` (WordPress) → js_intel analyzed the
  HTML, extracted inline JS + `<script src>` bundles, and surfaced **emails**
  (`hello@`, `cc@`) via `EmailExtractor`, plus GTM/Sentry/React via
  `TechnologyExtractor`.
- A `URL` for the Keycloak auth endpoint on `marketplace.amaru.co.nz`
  (`/auth/realms/sr624/protocol/openid-connect/auth?…`) flowed in; `paramfinder`
  (not js_intel) pulled `redirect_uri`, `state`, `client_id`, `code_challenge`.
- The engine resolved source-map references on the WordPress assets → `URL`
  (`found_via=js-sourcemap`) + `exposed-source-map` ANOMALYs.

---

## 10. Known limitations (read before trusting a clean result)

1. **Coverage is gated by the Adaptive Planner's per-host cap** (default 60 per
   module per host). On a content-heavy site the handler is skipped after the
   cap, so **most discovered JS/HTML URLs are never fetched/analyzed**. Observed
   on a 5,000-URL scan where js_intel analyzed only a handful of resources. This
   is the single biggest coverage risk (and why an email/secret on an un-fetched
   page is missed).
2. **js_intel only fetches the service root + JS/JSON/HTML URLs** — it does not
   deliberately fetch high-value *content* pages (`/contact`, `/careers`). An
   inline email/secret on such a page is reached only if that URL happens to be
   fetched within the cap.
3. **Regex, not a parser.** Obfuscated/minified/dynamically-assembled URLs and
   endpoints are missed — that's exactly the gap `jsluice` (AST) fills.
4. **Depends on fetchability.** If the origin blocks/throttles the scan (CDN WAF,
   or post-scan firewall block), bodies don't download and nothing is extracted.
5. **Classification is conservative.** Only API-tagged paths become `ENDPOINT`s;
   generic relative paths are intentionally not promoted (fewer false endpoints,
   but some real ones are left as plain URLs/routes).

---

## 11. Extending it

Add a signal in three steps, no module changes:

1. Write an `Extractor` subclass in `recon/jsintel.py` with `name` and
   `extract(self, content, base_url, analysis)`; append to a `JsAnalysis` field
   (add a field to the dataclass if it's a new type).
2. Register it in `DEFAULT_EXTRACTORS`.
3. If it's a new field, map it to an event in
   `JsIntelModule._emit_analysis` (and, if useful, `_feed_learning`).

Keep it pure and exception-safe; add a unit test against a realistic bundle
fixture (see `tests/unit/test_jsintel.py`).
