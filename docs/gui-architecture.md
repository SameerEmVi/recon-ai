# Recon-AI Web GUI — Architecture & Build Log

A dark, SOC-style web GUI for Recon-AI. The GUI is a **presentation/control layer
over the existing engine** — it never reimplements scanning. The backend is a
**sibling of `mcpserver/`**: it builds and runs the existing `ScanController`,
reads results through the existing repositories, and taps the existing event bus
for live updates.

This doc is the living record for the build (assessment · structure · API ·
security · per-increment status).

---

## 1. Architecture assessment

The scanning engine already exposes everything a GUI needs; the MCP server proves
the pattern (construct a `ScanController`, run it as a background task, read via
repositories). The web backend reuses that, adding only HTTP/WebSocket framing,
auth, and a richer scan manager (it keeps the live controller + task so a scan
can be cancelled).

| GUI need | Existing hook (reused) |
|---|---|
| Launch / run a scan | `ScanController(...).run(domain)` as a background task |
| Track running scans | `api/scans.py::ScanManager` (keeps controller + task) |
| Live events | `controller.bus` → `EventBus.subscribe(type, handler)` |
| Live jobs / workers | `controller.scheduler_report`, `JobRepository.list_for_scan` |
| Assets | `HostRepository.list_for_scan` |
| Findings / vulns | `FindingRepository.list_for_scan` (+ `vulnscan` evidence JSON) |
| History / diff | `ScanRepository.recent/get`, `database/diff.py` |
| Diagnostics | `controller.diagnostics` → JSONL under `results/<domain>/run-<id>/diagnostics/` |
| Scope (authoritative) | `ScopeEngine.evaluate` — re-checked on the backend per scan |
| Rate / WAF stats | `controller.rate_limiter.stats()` |
| Redaction | `net/redact.py` (already applied before persistence/logging) |

**Decisions (locked):** single local bearer token (no user table); **cancel-only**
for now (pause/resume is a real engine gap — deferred, not faked); `frontend/`
in-repo, FastAPI serves the Vite build.

**Known gaps (honest):**
- **Pause/resume is not implemented in the engine** (`JobState.PAUSED` is modelled
  but never triggered). The UI will not show a working pause until that backend
  feature is built. **Cancel works** (cancels the background task; the controller's
  `finally` tears down cleanly — subprocess-tree kill + DB-engine dispose).
- **Single-process model:** scans run in the API server's event loop (like the MCP
  server). Fine for a localhost single-user tool; a worker-process model is a
  possible later hardening.
- **No new DB models required** — scans/events/hosts/findings/jobs/assessments
  already persist; DB compatibility is preserved.

---

## 2. Folder structure

```
api/                     # FastAPI control/presentation layer (sibling of mcpserver/)
  app.py                 # create_app() factory + main() (uvicorn, localhost)
  config.py              # Settings (token, db_url, host/port, CORS, results dir)
  auth.py                # bearer-token dependency (constant-time) + WS token check
  scans.py               # ScanManager: build scope (fail-closed) → ScanController → task; cancel
  schemas.py             # Pydantic request/response models
  routes/
    health.py            # GET /api/health (unauthenticated, non-sensitive)
    scans.py             # POST/GET/cancel scans (token-gated)
frontend/                # React+TS+Vite+Tailwind, dark SOC theme — built to dist/, served by FastAPI
  vite.config.ts         # dev proxy /api + /ws -> 127.0.0.1:8787; vitest (jsdom) config
  tailwind.config.js     # dark palette tokens (charcoal bg, green/amber/red accents)
  src/
    main.tsx             # QueryClient + Router providers
    App.tsx              # routes behind the TokenGate
    index.css            # theme CSS variables
    lib/                 # cn, auth (token store), api (fetch client w/ bearer)
    components/          # Layout (sidebar+topbar+health dot), TokenGate, ui/ (button/card/badge)
    pages/               # Overview, Scans, Monitor, Assets, Vulnerabilities, Diagnostics, Settings (stubs)
    __tests__/           # vitest shell tests
docs/gui-architecture.md # this file
tests/unit/test_api_*.py # backend tests (in the repo's existing test tree)
```
Entry point: `recon-ai-web = api.app:main`. Optional deps: `pip install -e .[web]`
(fastapi/uvicorn/websockets — already present in this environment).

---

## 3. API (so far)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | none | Liveness: status, version, `db_configured` (bool), active scan count |
| POST | `/api/scans` | token | Create a scan (backend re-validates scope; 400 if out of scope) |
| GET | `/api/scans` | token | List scans (newest first) |
| GET | `/api/scans/{id}` | token | Scan status (in-memory, DB fallback) |
| POST | `/api/scans/{id}/cancel` | token | Cancel a running scan |
| GET | `/api/overview?scan_id=` | token | Dashboard payload: session scan counts + per-scan assets/severity/tech/recent-events/jobs (latest scan by default) |
| GET | `/api/catalog` | token | Available modules (name/description/flags), modes, and profiles for the scan form |
| GET | `/api/assets?scan_id=` | token | Asset inventory: per-host IPs/ports/tech/HTTP services (+ live flag), DNS records, subdomain inventory, tech distribution (latest scan by default) |
| GET | `/api/vulns?scan_id=` | token | Vulnerability intelligence: persisted findings + vulnscan evidence (status/confidence/tier/detection/references/remediation), severity/status/confidence rollups, strongest-first |
| GET | `/api/diagnostics/runs` | token | List diagnostics runs under `results_dir` (domain, run_id, error counts by category/module, stream line counts), newest first |
| GET | `/api/diagnostics?run_id=&stream=&module=&limit=` | token | One run's summary + a stream's records (`events`/`errors`/`http`, newest-first, module-filterable) — records already redacted at write time; http carries no bodies |
| POST | `/api/diagnostics/proxy-check` | token | Standalone proxy-connectivity probe (`{url}` → `{ok,target,message}`); no target traffic, no scan |
| GET | `/api/config` | token | Read-only effective config + engine defaults for the Settings page — bind/loopback, DB configured + dialect (never the URL), proxy-env bool, CORS, results dir, token source (never the token), worker default/ceiling, modes, browser profiles |
| WS | `/ws/live?token=&scan_id=&since=` | token (query) | Live monitor stream: `event` (bus tap), `stats` (1 Hz limiter + live worker-pool), `lifecycle`. Replays buffered frames after `since` for reconnect. |

The live monitor (`api/ws.py`) is read-only w.r.t. the engine: a `LiveHub` ring-buffers
recent frames (monotonic `seq`) and fans them to clients; `start_live_monitor` subscribes a
bus observer + a 1 Hz sampler of `controller.rate_limiter.stats()` and the live worker-pool
(`controller.live_pool_stats`, a new read-only property backed by `HybridScheduler.pool_stats`).
A slow/disconnected client is dropped (bounded per-client queue) — scan execution is never affected.

New read methods on existing repositories (no model change): `ScanRepository.recent_all`,
`EventRepository.recent` / `count_by_type`. Overview assembly lives in `api/overview.py`
and degrades gracefully (no DB ⇒ session counts + empty aggregates). Asset-inventory
assembly lives in `api/assets.py`: per-host rows come from the aggregated `hosts` table,
DNS records + the full subdomain inventory from the persisted event stream (`get_by_type`);
a host is "live" when ≥1 HTTP service was observed on it. Same graceful-degrade + per-collection
cap (`_MAX_ROWS=5000`). Vulnerability-intelligence assembly lives in `api/vulns.py`: reads
`FindingRepository.list_for_scan` and surfaces the structured fields `vulnscan` folds into
`findings.evidence` (status/confidence/tier/detection/references/remediation), rolling the rest
up as `extra` — so findings from non-vulnscan modules (secret/takeover/CORS) render with their
own evidence shape and a null status. Rows are ordered strongest-first (severity, then confidence);
the deterministic-vs-LLM split holds — the GUI only displays what was persisted.
Diagnostics reads live in `api/diagnostics.py`: it globs `<results_dir>/*/run-*/diagnostics`
(so the `domain`/`run_id` query params only *filter* a glob confined to `results_dir` — a caller
can never read outside it), returns per-run summaries + one stream's records, and never leaks the
absolute `dir`. The records were already redacted by `net.redact` at write time and the http stream
carries metadata only (never bodies), so they're safe to return as-is. The proxy-check reuses the
same `ProxyConfig.probe()` the CLI's `--proxy-check` uses. The config view lives in
`api/sysinfo.py::build_config`: it reports only non-sensitive values — the DB is reduced to
`{configured, dialect}` (dialect parsed from the URL scheme, so no host/creds), the token to
`{token_set, token_source}` (never the token), and the proxy to an env-present bool — alongside
the engine defaults the scan form mirrors (worker default/ceiling from `WorkerPool`, modes,
browser profiles). Token management is purely client-side (localStorage via `lib/auth.ts`); the
backend stays the real gate.

`POST /api/scans` body is `ScanCreate` (`api/schemas.py`): `domain`, scope
(`in_scope`/`out_scope`/`max_distance`/`wildcard_apex`), `mode`, `modules`,
`rate_limit`/`max_concurrency`/`module_concurrency`, hybrid (`hybrid`/`workers`/
`targets`), `browser_profile`, `proxy`. The handler validates and **delegates** —
it never runs a module itself.

---

## 4. Security

- **Localhost bind** by default (`127.0.0.1:8787`); a non-loopback bind is an
  explicit operator choice.
- **Single bearer token** required on every sensitive route (and, later, the
  WebSocket). Generated and printed once to stderr if `RECON_AI_WEB_TOKEN` is
  unset; never exposed through any endpoint. Constant-time comparison.
- **Backend-authoritative scope:** `ScanManager.launch` re-runs `ScopeEngine` and
  fails closed before any task is created — the UI is never trusted for scope.
- **Strict CORS** (explicit allow-list, never `*`).
- **Redaction** via `net/redact.py` is already applied by the engine before data
  is persisted/logged, so responses inherit it.
- **No direct module execution from routes** — routes persist/delegate only.

---

## 5. Build status (per increment)

| # | Increment | Status |
|---|---|---|
| 1 | **API foundation** (app factory, auth, scan manager, scope re-validation, health + scan routes) | ✅ done — 6 backend tests, full suite 967 passing |
| 2 | **React shell** (Vite/TS/Tailwind, router, TanStack Query, dark SOC theme, token gate, nav, live health dot) | ✅ done — typecheck clean, 4 vitest tests, prod build served by FastAPI |
| 3 | **Overview dashboard** (KPI tiles, severity + technology charts, recent events/scans, job state; `/api/overview`) | ✅ done — 3 backend tests, full suite 970; frontend typecheck/build clean; route verified over HTTP w/ seeded DB |
| 4 | **Scan management** (create/configure form: scope/exclusions/mode/modules/workers/rate/concurrency/hybrid/proxy; scans table; start/cancel; `/api/catalog`) | ✅ done — 12 backend api tests, full suite 972; frontend typecheck/build clean |
| 5 | **Live monitor** (authenticated WebSocket, bus + stats + worker-pool tap, reconnect replay buffer) | ✅ done — 6 backend ws tests + 3 frontend reducer tests, full suite 977; **live-streamed a real hybrid scan** (97 events, live limiter + pool stats over WS) |
| 6 | **Asset explorer** (per-host IPs/ports/tech/services with live flag, DNS records, subdomain inventory; tabbed, searchable, live-only filter; `/api/assets`) | ✅ done — 3 backend tests, full suite 980; frontend typecheck/build clean |
| 7 | **Vulnerability intelligence** (findings + vulnscan evidence: verification status/confidence/tier/detection/references/remediation; severity+status+confidence rollups; severity/status/search filters; expandable evidence; `/api/vulns`) | ✅ done — 3 backend tests, full suite 983; frontend typecheck/build clean |
| 8 | **Diagnostics** (per-run JSONL reader — summary + events/errors/http streams, error rollups by category/module, module/text filters; proxy-connectivity probe; `/api/diagnostics*`) | ✅ done — 4 backend tests, full suite 987; frontend typecheck/build clean |
| 9 | **Settings** (read-only backend config + security posture via `/api/config`; client-side token management — replace/sign-out, reloads to re-gate) | ✅ done — 3 backend tests, full suite 990; frontend typecheck/build clean |
| 10 | **End-to-end GUI test** (real app→launch→bus→repositories→overview/assets/vulns readback→hub replay→cancel; out-of-scope rejected pre-launch) | ✅ done — 3 backend e2e tests, full suite 993; **live-reconfirmed** the real ScanController path through the API (osint scan of hackycorp.com: caps enforced, persisted, read back, WS lifecycle+stats+event frames) |

### Test commands + actual results
```bash
python -m pytest tests/unit/test_api_*.py -q             # 25 passed (foundation/overview/ws/assets/vulns/diagnostics/config/e2e)
python -m pytest -q                                      # 993 passed

cd frontend
npm install        # 292 packages
npm run typecheck  # tsc --noEmit — clean (exit 0)
npm test           # vitest — 4 passed (TokenGate + apiFetch)
npm run build      # vite build — dist/ (index.html + 236 kB js / 10.75 kB css)
```
Full-stack check: with `frontend/dist` present, `GET /` serves the SPA and
`GET /api/health` still routes (static mount is added after the API routers).

### Running it locally (dev)
```bash
pip install -e .[web]
recon-ai-web                      # backend on 127.0.0.1:8787 (prints the token once)
cd frontend && npm run dev        # Vite dev server on :5173, proxies /api + /ws to :8787
# or: npm run build, then recon-ai-web serves the built UI at http://127.0.0.1:8787/
```

### End-to-end validation (increment 10)
`tests/unit/test_api_e2e.py` drives the **production path** — `create_app` → real
`ScanManager.launch` (real scope re-validation, real background task, real live-monitor
attach) → real `EventBus` → real repositories → the real `/api/overview`, `/api/assets`,
`/api/vulns` readers → the real `LiveHub` (event/stats/lifecycle frames + `since=` reconnect
replay) → real cancel. Only the *scanner* is scripted (a controller injected via
`controller_factory`) so the automated test is offline and deterministic. The **real
`ScanController` engine** was reconfirmed live through the HTTP API (an osint scan of the
authorized hackycorp.com: `caps={PASSIVE_EXTERNAL}` enforced, assets persisted and read back
through the endpoints, WS carried started/complete lifecycle + stats + event frames) — see the
increment-5 live note for the richer hybrid-scan stream.

### Known limitations (current)
- Pause/resume not implemented (cancel-only) — see §1.
- **Scan-level timeout** is in the spec but not an engine parameter (only per-module
  timeouts exist in the scheduler). The form omits it rather than showing a control
  that does nothing; adding a real scan-wide timeout is a possible later engine change.
- **Gotcha recorded:** a FastAPI WebSocket endpoint must annotate its socket param
  (`websocket: WebSocket`) or dependency injection won't pass the socket and the
  handshake 403s. Fixed in `api/ws.py::live_ws`.
