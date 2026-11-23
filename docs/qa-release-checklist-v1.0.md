# Recon-AI v1.0 — QA & Reliability Acceptance Results

**Assessed:** 2026-11-03 · **Branch:** `feature/recon-intelligence-subsystems` ·
**Assessor:** automated code + test-suite verification (Claude Code)

**Result legend:** ✅ PASS · ❌ FAIL · ⛔ BLOCKED · ⬜ NOT TESTED · N/A

> **Method & honesty note.** Per the project rule *"Do not fabricate test
> results,"* every ✅ below is backed by code that was read and/or a test that
> actually ran. Items needing infrastructure not available in this assessment
> environment (Docker, multiple live proxies, 30-minute live scans, a real
> browser, disk-exhaustion) are marked ⬜ NOT TESTED with the reason — **not**
> passed. Features that do not exist are marked ❌ with "not implemented."

## Backbone evidence

- **Full test suite:** `python -m pytest -q` → **993 passed, 1 warning, exit 0**
  in 47.29s (run 2026-11-03, with `go/bin` on PATH). The lone warning is a
  3rd-party Starlette `DeprecationWarning`, not a failure.
- **Dedicated scope security suite:** `tests/security/test_scope_engine.py` — 41 tests.
- **API/GUI suite:** `tests/unit/test_api_{foundation,overview,assets,vulns,diagnostics,config,ws,e2e}.py`.
- **Scheduler suite:** `tests/unit/test_scheduler_{engine,integration,jobs,perf,pool,report}.py`.

---

## Executive summary

| # | Section | Verdict | Blocker? |
|---|---|---|---|
| 1 | Installation & startup | ✅ core / ❌ migrations, ⬜ fresh-clone | — |
| 2 | GUI & API integration | ✅ core / ❌ pause-resume | — |
| 3 | **Scope & authorisation** | ✅ with one gap (DNS-rebind) | **release blocker** |
| 4 | Scheduler & parallel execution | ✅ | — |
| 5 | **Rate limiting & proxy** | ✅ | **release blocker** |
| 6 | Scan modules & result accuracy | ✅ design / ⬜ reproducibility live | — |
| 7 | Database & data integrity | ✅ core / ❌ migrations, ⬜ backup | — |
| 8 | Live monitoring & WebSockets | ✅ / ⬜ 60s browser reconnect | — |
| 9 | Diagnostics & logging | ✅ / ❌ log rotation | — |
| 10 | **GUI security** | ✅ single-operator model / N/A multi-user | **release blocker** |
| 11 | Performance & resilience | ⬜ mostly (needs live long runs) | — |
| 12 | Packaging & release | ❌ Docker/CI/release process absent | — |

**Release-blocker verdict (§3, §5, §10):** the three security-critical sections
**pass** for the tool's actual threat model (a single-operator, localhost-bound
console that never scans outside a code-enforced scope and never bypasses
rate-limits). Two caveats a release owner must accept or fix first:
1. **No DNS-rebinding / connect-time IP pinning** (§3) — scope is enforced on
   hostnames and on discovered IPs at emit time, but a host that re-resolves to a
   new IP between validation and connection is not re-checked at the socket.
2. **Single shared token, no multi-user model** (§10) — fine for local use; **not**
   a multi-tenant/remote deployment posture. §12 ships no Docker/CI/HTTPS story.

---

## 1. Installation and startup

| Item | Result | Evidence |
|---|---|---|
| Fresh clone installs successfully | ⬜ NOT TESTED | Not re-cloned in this env; deps resolve in the working tree. `pip install -e .[web]` documented in CLAUDE.md. |
| Python dependencies install without conflicts | ✅ PASS | Working venv imports + 993 tests run clean; `pyproject.toml` pins are consistent (core + `ai`/`mcp`/`web`/`dev` extras). |
| Frontend dependencies install successfully | ✅ PASS | `frontend/node_modules` present; Vite dev + `npm run build` both ran this session. |
| Environment configuration is documented | ✅ PASS | CLAUDE.md "Running it" + `api/config.py` (`RECON_AI_WEB_*`, `RECON_AI_DB_URL`, `RECON_AI_RESULTS_DIR`, `RECON_AI_PROXY`); INSTALL.md for Burp. |
| Application starts using documented commands | ✅ PASS | `recon-ai-web` / `python -m api.app` verified running this session (`/api/health` 200). |
| Backend starts without unhandled exceptions | ✅ PASS | Backend served health + SPA + catalog (53 modules) cleanly. |
| Frontend builds without errors | ✅ PASS | `npm run build` produced `dist/` served by the backend. |
| Database connection works | ✅ PASS | `/api/health` → `db_configured:true`; assemblers read via repositories; `test_database.py`. |
| Database migrations run successfully | ❌ FAIL (not implemented) | `alembic/versions/` is **empty** — no migration revisions. Schema is created by SQLModel `init_db`/`create_all`, not Alembic. Alembic scaffolding (`env.py`) exists but is unused. |
| Application handles an unavailable database gracefully | ✅ PASS | Read assemblers degrade to empty payloads with no/failed DB (`test_api_*` "auth + no-DB" cases); `get_response_cache`/`get_limiter` fall back. |
| Health endpoint reports correct status | ✅ PASS | `api/routes/health.py` returns `status/version/db_configured/active_scans`; `db_url` never exposed. |
| Application shuts down cleanly | ✅ PASS | `api/app.py` lifespan cancels running scans via `ScanManager.shutdown()`; controller `finally` disposes engine + reaps subprocess trees (`recon/proc.py`). |
| Restarting does not corrupt existing scan records | ✅ PASS (design) | Scans persisted through repositories; restart reopens the same DB read-only for reads. No destructive startup step. (Live power-loss mid-write not exercised.) |

## 2. GUI and API integration

| Item | Result | Evidence |
|---|---|---|
| Create a scan through the GUI | ✅ PASS | `POST /api/scans` → `ScanCreated` (201); `test_api_e2e`. |
| Scan is saved in the database | ✅ PASS | `test_api_e2e` reads it back via overview/assets/vulns; `ScanRepository.create`. |
| Start a scan through the GUI | ✅ PASS | Create == launch; `ScanManager.launch` runs `controller.run` as a background task. |
| Existing Python engine executes it | ✅ PASS | `_default_controller_factory` builds the real `ScanController` (same as CLI/MCP); live osint run on authorized hackycorp.com confirmed separately. |
| Scan ID consistent across GUI/API/DB | ✅ PASS | `controller.scan_id` is the single id used in the entry, responses, DB rows, and WS frames; `test_api_e2e`. |
| Pause a running scan | ❌ FAIL (not implemented) | No pause in `ScanManager`/controller/scheduler. Lifecycle is create → cancel. |
| Resume a paused scan | ❌ FAIL (not implemented) | Same — no pause/resume state machine. |
| Cancel a running scan | ✅ PASS | `ScanManager.cancel` cancels the task; `test_api_e2e_cancel_stops_a_running_scan`. |
| Cancellation reaches all associated workers | ✅ PASS | Controller `finally` + `recon/proc.py` kills tool subprocess **trees**; hybrid `WorkerPool.shutdown(cancel=True)` marks in-flight + queued CANCELLED (`test_scheduler_pool`). |
| Invalid scan configurations are rejected | ✅ PASS | `ScanCreate` Pydantic constraints (`min_length`, `ge/le`, `gt`); out-of-scope seed → `ScopeRejected` → 400 (`test_api_e2e_out_of_scope_rejected_before_launch`). |
| API errors appear meaningfully in the GUI | ✅ PASS | Typed errors (`Message{detail}`, 400/401); frontend surfaces query/mutation errors (Diagnostics proxy-probe, Settings). |
| Repeated start requests do not create duplicate jobs | ⚠️ PARTIAL / by-design | Each `POST /api/scans` is a **distinct** scan by design (no "start existing"). The manager does not dedup identical concurrent requests → a double-submit creates two scans. Within the hybrid engine, per-job dedup by `dedup_key` prevents duplicate module execution. |
| CLI and GUI use same execution & security policies | ✅ PASS | GUI builds `ScanController` identically; scope engine, `CapabilityPolicy(mode)`, rate limiter are the same objects. |
| **Critical:** frontend disconnect ⇒ scan continues | ✅ PASS | Scan runs as an independent asyncio task; `LiveHub`/WS is a read-only observer; dropping a client never touches execution (`api/ws.py`, `test_api_e2e`). |

## 3. Scope and authorisation — RELEASE BLOCKER

| Item | Result | Evidence |
|---|---|---|
| Accept an explicitly authorised target | ✅ PASS | `ScopeEngine.evaluate` → IN; 41 scope tests. |
| Reject targets outside scope | ✅ PASS | Deny-first, default OUT; `test_scope_engine.py`. |
| Reject an unauthorised subdomain | ✅ PASS | Distance + ALLOW gating; scope suite. |
| Wildcard scope matching | ✅ PASS | `*.domain` rules; `wildcard_includes_apex` option; scope suite. |
| Exact hostname matching | ✅ PASS | Exact ALLOW/DENY rules; scope suite. |
| IP address scope validation | ✅ PASS | `RuleKind.CIDR` via `ipaddress`; scope suite. |
| IPv4 and IPv6 handling | ✅ PASS | `scope/engine.py` handles v4/v6 + cross-family mismatch (lines ~122–155). |
| Redirects to out-of-scope destinations | ✅ PASS (design) | `recon/fetch.py` uses `follow_redirects=False`; a `Location` to a new host re-enters only through the scope gate. |
| Redirects across sibling root domains | ✅ PASS (design) | Sibling root is OUT under deny-first default unless explicitly in-scope; not auto-followed. |
| DNS resolution changing between validation and connection | ❌ FAIL (gap) | **No DNS-rebinding defence / connect-time IP pinning.** Hostnames are scoped and discovered IPs gated at emit time, but the socket is not re-validated against the resolved IP. Documented gap for a localhost operator tool; must be noted for any SSRF-sensitive deployment. |
| Private/loopback/link-local restrictions | ⚠️ PARTIAL (by scope, not a separate guard) | Such IPs are OUT under any normal domain scope (deny-first default OUT); there is **no** independent "never touch RFC1918/127/169.254 even if in-scope" guard — an operator who explicitly adds them to `--in-scope` CIDR can reach them (intended for authorized internal ranges). |
| Every module uses the central scope validator | ✅ PASS | All emission funnels through `stamp_and_publish` → `ScopeEngine`; EventBus drops `scope_status != IN`. Core invariant. |
| Proxy routing cannot bypass scope | ✅ PASS | Proxy only changes transport; scope is evaluated before/at emission, independent of proxy; `test_proxy_integration`. |
| Manually supplied URLs cannot bypass scope | ✅ PASS | GUI/CLI seeds re-validated backend-side (`ScanManager.build_scope` fail-closed); discovered/injected URLs re-enter the gate. |
| Exclusions enforced across all modules | ✅ PASS | `out_scope` deny wins globally (incl. subtree exclusion); scope suite. |

## 4. Scheduler and parallel execution

| Item | Result | Evidence |
|---|---|---|
| One subdomain, one module | ✅ PASS | `test_scheduler_engine/integration`. |
| Multiple subdomains concurrently | ✅ PASS | `HybridScheduler._run_target` gather; integration tests. |
| Multiple modules concurrently | ✅ PASS | Per-target module DAG gather. |
| Both concurrency levels together | ✅ PASS | `test_scheduler_integration`. |
| Max workers = 1 / 5 / 10 | ✅ PASS | `WorkerPool._clamp_workers`; `test_scheduler_pool` covers sizing. |
| Active workers never exceed configured max | ✅ PASS | Fixed worker-task count; `SAFETY_CEILING=50`; pool tests. |
| Queued jobs eventually execute | ✅ PASS | Bounded `PriorityQueue` + drain; pool/perf tests. |
| Duplicate jobs deduplicated where intended | ✅ PASS | `submit()` dedup by `job.dedup_key`; pool tests. |
| Module dependencies respected | ✅ PASS | DAG `requires`; `_validate_dag` rejects cycles/unknowns; engine tests. |
| Failed module doesn't crash unrelated jobs | ✅ PASS | Per-job isolation → FAILED; target rolls up to PARTIAL; engine tests. |
| Worker exceptions captured | ✅ PASS | `_run_one` catches all → `_force_terminal(FAILED)`. |
| Workers recover after transient errors | ✅ PASS | Worker loop continues after a job's terminalization; pool tests. |
| Cancellation stops queued and running | ✅ PASS | `shutdown(cancel=True)` marks in-flight + queued CANCELLED. |
| Graceful shutdown handles active jobs | ✅ PASS | `shutdown()` drains via `queue.join()`. |
| No worker stuck indefinitely | ✅ PASS (design) | Per-job `timeout` → `asyncio.wait_for` → FAILED; `default_timeout`. |
| Partial results survive job failures | ✅ PASS | Target PARTIAL; already-emitted events persisted; live stop-safe writer. |
| **Stress: 20 subs × 5 modules, 10 workers** | ⬜ NOT TESTED (live) | Covered in spirit by `test_scheduler_perf.py` (synthetic load, bounded workers, no result loss); the exact 20×5×10 live run was not executed here. |

## 5. Rate limiting and proxy handling — RELEASE BLOCKER

| Item | Result | Evidence |
|---|---|---|
| Global req/s limit | ✅ PASS | `RateLimiter` rps spacing; CLI `-r`; `test_ratelimit`. |
| Per-host req/s limit | ✅ PASS | Per-bucket (host/tool) spacing; `test_ratelimit`. |
| Aggregate limiting across all workers | ✅ PASS | **One** `RateLimiter` per scan shared by every module/worker/wrapper via `guard()`; worker count ≠ request budget (core invariant). |
| Aggregate limiting across all modules | ✅ PASS | Same single chokepoint. |
| Separate proxy connections share one target budget | ✅ PASS | The limiter is keyed on target bucket, independent of transport/proxy; a proxy cannot create a parallel budget. |
| HTTP 429 triggers cooldown | ✅ PASS | `waf.detect` → backoff (×2/block, cap ×32); `test_ratelimit`. |
| Retry-After respected | ✅ PASS | Honored by backoff path (`observe_http`); `test_ratelimit`. |
| HTTP 403 classified correctly | ✅ PASS | 403 alone (CDN) is **not** a block; only with block-body/WAF-fingerprint; `test_ratelimit`/`waf`. |
| WAF challenges detected and reported | ✅ PASS | `waf.py` product DB (active=True) → backoff + `WAF_RESTRICTION_DETECTED` event. |
| Blocked target does NOT trigger proxy rotation | ✅ PASS | No proxy-rotation feature exists; block → shared-limiter cooldown only (`scheduler.note_waf`). (Rotating-proxy "WAF bypass" was explicitly refused earlier.) |
| Proxy failures distinguished from target errors | ✅ PASS | `net/errors.py` `classify_http_error` → ProxyConnection/ProxyAuth vs DNS/timeout/target; `test_net_diagnostics`. |
| Mandatory proxy never silently falls back to direct | ✅ PASS | `ProxyConfig.probe()` at start; unreachable → `ProxyConnectionError` **stops** the scan; `test_proxy_integration`. |
| Invalid proxy addresses rejected | ✅ PASS | Probe fails fast on bad URL; classified + raised. |
| Dead proxies marked unhealthy | N/A | Single-proxy model (Burp/one upstream); no proxy pool to health-check. A dead proxy stops the scan (above), by design. |
| Proxy failures don't cause infinite retries | ✅ PASS | Fail-closed stop, not a retry loop; `fetch` returns `FetchResult(ok=False)`. |
| TLS certificate validation remains enabled | ✅ PASS | `verify` defaults True; CA bundle is explicit opt-in; `verify=False` **warns** (takeover only); `test_proxy_integration`. |
| Proxy credentials never exposed in logs | ✅ PASS | `net/redact.py` scrubs URL userinfo + secret headers before any disk write; `test_net_diagnostics`. |
| **Important: 10 workers, 5 proxies, 2 req/s global** | ⬜ NOT TESTED (live) | Design guarantees aggregate ≤ 2 req/s (single shared limiter), but there is no 5-proxy pool feature and no live mock load was run here. |

## 6. Scan modules and result accuracy

| Item | Result | Evidence |
|---|---|---|
| Every module starts successfully | ✅ PASS | Registry auto-discovery; `test_modules.py` + per-module suites; missing-binary modules warn-and-skip. |
| Handles invalid input | ✅ PASS | Pure parsers unit-tested with malformed input (ffuf/katana/jsintel/retirejs/etc.). |
| Handles timeouts | ✅ PASS | `run_proc`/fetch timeouts; `recon/proc.py` tree-kill; `test_proc.py`. |
| Handles connection failures | ✅ PASS | `fetch` → `FetchResult(ok=False)`, never crashes siblings; `test_fetch_cache`. |
| Respects scope restrictions | ✅ PASS | All emit via scope gate (see §3). |
| Respects central rate limits | ✅ PASS | All I/O via `guard()`/`fetch` (see §5). |
| Results contain correct asset reference | ✅ PASS | Event `data` carries host/url; `test_events`, per-module tests. |
| Duplicate results handled consistently | ✅ PASS | Bus dedup by `dedup_key`; finding dedup `host:title:category`. |
| Evidence retained per finding | ✅ PASS | `FindingCandidateData.evidence` JSON; vulnscan folds structured evidence. |
| Results include timestamps | ✅ PASS | Event + DB `created_at`. |
| Results identify generating module | ✅ PASS | `source_tool`/`found_via` provenance. |
| Confirmed vs inferred distinguished | ✅ PASS | vulnscan status `OBSERVED/POTENTIAL/UNCONFIRMED/CONFIRMED`; `test_vulnscan`. |
| Tech fingerprinting records evidence + confidence | ✅ PASS | `TechnologyData.source`; `test_fingerprint_tools`; cloud noisy-OR confidence. |
| CVE correlation: potential vs validated | ✅ PASS | `vulnscan/cve.py` never CONFIRMED on a version string → POTENTIAL/UNCONFIRMED; `test_vulnscan`. |
| CVE results include version + references | ✅ PASS | CVE/CWE/refs in finding evidence (retirejs/known-cve). |
| Port/service discovery records observed details | ✅ PASS | naabu→nmap `-sV`; `test_naabu`/`test_nmap`/`test_rustscan`. |
| Missing results not shown as confirmed negatives | ✅ PASS | Assemblers show absence as empty, not "none found/confirmed clean." |
| **Accuracy: run twice, compare** | ⬜ NOT TESTED (live) | Determinism of pure parsers is unit-tested, but a full double-run diff against a live lab was not performed here. |

## 7. Database and data integrity

| Item | Result | Evidence |
|---|---|---|
| Scan records created correctly | ✅ PASS | `ScanRepository.create`; `test_database`, `test_api_e2e`. |
| Job records reference correct scan | ✅ PASS | Scheduler `save_job` with `scan_id`/`parent_id`; `test_scheduler_*`. |
| Module execution status transitions correct | ✅ PASS | `JobState` transitions validated; `test_scheduler_jobs`. |
| Assets associated with correct scan | ✅ PASS | `HostRepository` keyed by `scan_id`; `test_api_assets`. |
| Findings reference correct assets | ✅ PASS | `FindingRepository`; `test_api_vulns`. |
| Scan events persisted | ✅ PASS | `EventRepository.save`; `test_database`. |
| Diagnostic events persisted | ✅ PASS | `DiagnosticsLogger` JSONL + `summary.json`; `test_net_diagnostics`. |
| Duplicate asset records handled | ✅ PASS | `HostRepository.ensure`/add-* idempotent; KB `UniqueConstraint`. |
| Transactions roll back on failure | ✅ PASS (design) | Async sessions scoped per unit; failed writes don't commit. (Fault-injection not run.) |
| Interrupted scans retain partial results | ✅ PASS | Live stop-safe writer (commit `f2ec5f8`) + per-event persist. |
| Restart preserves scan history | ✅ PASS | Durable DB; `history`/`diff` CLI read prior scans. |
| Migrations from fresh install | ❌ FAIL (not implemented) | No Alembic revisions; schema via `create_all` (see §1). |
| Migrations from previous version | ❌ FAIL (not implemented) | No versioned migration path. |
| Backup and restore procedures | ⬜ NOT TESTED / undocumented | For sqlite it's a file copy; no documented/automated backup-restore procedure. |
| Sensitive values not stored unnecessarily | ✅ PASS | Secrets redacted before any event/log/DB write; cookie names only; no bodies in diagnostics. |

## 8. Live monitoring and WebSockets

| Item | Result | Evidence |
|---|---|---|
| Scan status updates | ✅ PASS | `lifecycle` frames (started/complete/failed/cancelled); `test_api_e2e`. |
| Worker utilisation updates | ✅ PASS | `stats` frame carries `pool` from `live_pool_stats` (hybrid). |
| Queue size updates | ✅ PASS | `pool.queued` in stats frame. |
| Module execution status updates | ✅ PASS | `MODULE_*` events via `on_event` → hub. |
| Subdomain job status updates | ✅ PASS | `TARGET_*` events. |
| Request statistics update | ✅ PASS | 1 Hz `rate_limiter.stats()` sample. |
| Rate-limit cooldowns displayed | ✅ PASS | `limiter.stats()` → `targets_in_cooldown`/`penalty`. |
| WAF events displayed | ✅ PASS | `waf_vendors`/`targets_backed_off` in stats; WAF events. |
| Errors appear in diagnostics UI | ✅ PASS | Diagnostics page reads `errors.jsonl`/summary; `test_api_diagnostics`. |
| WS disconnects don't interrupt scans | ✅ PASS | Read-only observer; bounded client queue; `test_api_e2e`. |
| Reconnect restores current state | ✅ PASS | `replay(since, scan_id)` tail replay; `test_api_e2e` since-cursor. |
| Missed events recoverable from persisted data | ✅ PASS | Ring-buffer replay + REST refetch (assemblers read the DB). |
| Duplicate events don't corrupt UI | ✅ PASS | Monotonic `seq`; client dedupes by seq. |
| Out-of-order events handled | ✅ PASS | Hub assigns seq at publish; ordering is server-authoritative. |
| WS access authorised per scan | ✅ PASS | `?token=` gate (`4401` on bad) + `?scan_id=` filter; `test_ws_rejects_bad_token`. |
| **Important: 60s disconnect then reconnect reconciles** | ⬜ NOT TESTED (live browser) | Replay logic is unit-tested; a real 60s browser drop/reconnect was not exercised. Note: buffer is 2000 frames — a very long/high-volume gap falls back to REST refetch. |

## 9. Diagnostics and logging

| Item | Result | Evidence |
|---|---|---|
| Logs have timestamps | ✅ PASS | JSONL records timestamped; `test_net_diagnostics`. |
| Logs have severity levels | ✅ PASS | events/errors streams split by level. |
| Logs include scan IDs | ✅ PASS | `run_id` = scan id on every record. |
| Logs include job IDs | ✅ PASS | Scheduler job records. |
| Logs include module names | ✅ PASS | per-record `module`; summary by module. |
| Correlation IDs where applicable | ✅ PASS | `contextvar` correlation_id per HTTP op. |
| Network timeouts classified | ✅ PASS | `classify_http_error` (ConnectTimeout/ReadTimeout). |
| DNS errors classified | ✅ PASS | DNS category. |
| Proxy errors classified | ✅ PASS | ProxyConnection/ProxyAuth categories. |
| Database errors classified | ⚠️ PARTIAL | HTTP/transport taxonomy is thorough; DB exceptions are caught and logged but not in a dedicated category taxonomy. |
| API errors classified | ✅ PASS | FastAPI structured errors (400/401) + `Message`. |
| Unexpected exceptions include stack traces | ✅ PASS | `log.error`/`exception` paths; scan failures capture `error`. |
| Credentials redacted | ✅ PASS | `net/redact.py`; `test_net_diagnostics`. |
| Cookies & authorization headers redacted | ✅ PASS | Secret-header list incl. authorization/cookie/api-key. |
| Sensitive request/response data not over-logged | ✅ PASS | `http.jsonl` is metadata only — **never bodies**. |
| Diagnostic exports work | ✅ PASS | `recon-ai diagnostics --export`; `GET /api/diagnostics`. |
| Log retention and rotation | ❌ FAIL (not implemented) | Per-run JSONL dirs accumulate; no rotation/retention policy. |

## 10. GUI security — RELEASE BLOCKER

| Item | Result | Evidence |
|---|---|---|
| Authentication required for remote access | ✅ PASS | Bearer token on all sensitive routes + WS; `require_token`; `test_api_*`. |
| Passwords not stored in plaintext | N/A | No password model — single bearer token, no user accounts. Token via env or generated-once (never persisted by the app, never returned by any endpoint). |
| Session expiry works | N/A | No sessions — stateless bearer token. |
| Logout invalidates session | N/A | No server session; "sign out" clears the browser-stored token (Settings). |
| Unauthenticated API requests rejected | ✅ PASS | 401 without a valid token; every `test_api_*` asserts the auth gate. |
| Unauthorised users can't access another user's scans | N/A / ⚠️ single-operator | No per-user isolation: any token holder sees all scans. Acceptable for a single-operator local tool; **not** a multi-tenant posture. |
| WebSocket authentication enforced | ✅ PASS | `websocket_token_ok`; closes `4401`; `test_ws_rejects_bad_token`. |
| CORS allows only intended origins | ✅ PASS | Strict allow-list, **never `*`** (`api/app.py`); default = Vite dev origin; `RECON_AI_WEB_CORS`. |
| CSRF protection where applicable | ✅ PASS (by design) | No cookie auth → no ambient-credential CSRF surface; token is an explicit `Authorization` header, methods restricted. |
| API input validation enforced | ✅ PASS | Pydantic `ScanCreate` constraints; mode `Literal`; `test_api_foundation`. |
| SQL injection protections tested | ✅ PASS (design) | SQLModel/SQLAlchemy parameterized queries throughout; no string-built SQL. (No raw SQL paths found.) |
| XSS protections tested | ✅ PASS (design) | React escapes by default; target strings control-char-stripped + length-capped at event construction (`_MAX_STR`). No `dangerouslySetInnerHTML` in the GUI. |
| SSRF protections tested | ⚠️ PARTIAL | Scope gate + no-follow-redirect confine outbound targets; **but** no DNS-rebinding/IP-pinning and no explicit RFC1918 block (see §3). |
| File export paths can't escape permitted dirs | ✅ PASS | Diagnostics reads are glob-confined to `results/`; `../../etc` traversal blocked (`test_api_diagnostics`). |
| Arbitrary command execution not exposed via GUI | ✅ PASS | No command input; routes only build a validated `ScanController`; tool args come from fixed wrappers with injection guards. |
| Secrets managed outside source code | ✅ PASS | Tokens/keys via env (`RECON_AI_WEB_TOKEN`, `ANTHROPIC_API_KEY`, `CENSYS_*`, `GITHUB_TOKEN`); none committed. |
| Production config doesn't enable debug mode | ✅ PASS | No debug/reload defaults; `--debug` is opt-in diagnostics only; FastAPI not in debug. |
| Remote deployment uses HTTPS | ❌ FAIL / out of scope | App serves plain HTTP on loopback by design; no built-in TLS. A remote deploy must front it with a TLS reverse proxy — not provided or documented. |

## 11. Performance and resilience

| Item | Result | Evidence |
|---|---|---|
| Run a scan for 30 minutes | ⬜ NOT TESTED | Needs a live long-running authorized target. |
| Multiple scans concurrently | ✅ PASS (design) / ⬜ live | `ScanManager` runs independent tasks; not load-tested here. |
| Monitor CPU / memory / DB growth / FE responsiveness | ⬜ NOT TESTED | Requires a live long run + profiling. |
| No unbounded queue growth | ✅ PASS | Bounded `PriorityQueue` with backpressure; LRU body cache (4096); hub ring buffer (2000); `test_scheduler_perf`. |
| No uncontrolled retry loops | ✅ PASS | Fail-closed proxy, `FetchResult(ok=False)` on error; no retry storms. |
| Request/connection timeouts work | ✅ PASS | httpx timeouts + per-job timeout; `test_proc`. |
| Slow DNS / slow HTTP / connection resets | ⚠️ PARTIAL | Classified + timed out (`net/errors.py`, `test_net_diagnostics`); not fault-injected live. |
| DB disconnection during a scan | ⬜ NOT TESTED | Reads degrade gracefully; mid-scan DB loss not fault-injected. |
| Backend restart during a scan | ✅ PASS (design) | In-flight scan is cancelled on shutdown; persisted partials survive; no corruption path. Live restart-mid-scan not exercised. |
| Frontend restart during a scan | ✅ PASS | Scan independent of client; reconnect replays (§8). |
| Disk space exhaustion (controlled) | ⬜ NOT TESTED | Needs a constrained FS; diagnostics degrade to no-op on unwritable dir (partial mitigation). |
| Graceful degradation under resource pressure | ⚠️ PARTIAL | Backpressure + bounded buffers + warn-and-skip give headroom; not stress-validated. |

## 12. Packaging and release

| Item | Result | Evidence |
|---|---|---|
| Docker build succeeds | ❌ FAIL (absent) | No `Dockerfile`. |
| Docker Compose startup | ❌ FAIL (absent) | No `docker-compose.yml`. |
| Works from a clean environment | ⬜ NOT TESTED | Not re-provisioned from scratch here. |
| Configuration documented | ✅ PASS | CLAUDE.md + INSTALL.md + `docs/`. |
| Default configuration is safe | ✅ PASS | Loopback bind, strict CORS, TLS-verify on, AI opt-in, intrusive tier off, token required. |
| Installation instructions accurate | ✅ PASS (spot-checked) | `pip install -e .[web]`, `recon-ai-web`, Vite commands all work. |
| Upgrade instructions accurate | ❌ FAIL (absent) | No upgrade/migration guide (ties to missing migrations). |
| Backup instructions documented | ❌ FAIL (absent) | None. |
| Restore instructions documented | ❌ FAIL (absent) | None. |
| API documentation available | ⚠️ PARTIAL | FastAPI auto-generates `/docs` (OpenAPI); hand-written API table in `docs/gui-architecture.md`. No standalone API reference. |
| CLI usage documented | ✅ PASS | CLAUDE.md "Running it"; `--help`. |
| GUI usage documented | ✅ PASS | `docs/gui-architecture.md`. |
| CI pipeline passes | ❌ FAIL (absent) | No `.github/workflows`. The test suite passes locally (993) but there is no CI. |
| Dependency vulnerabilities reviewed | ⬜ NOT TESTED | No `pip-audit`/`npm audit` run recorded. |
| Release notes prepared | ❌ FAIL (absent) | None. |
| GitHub release tagged | ❌ FAIL (absent) | No v1.0 tag. |
| Known limitations documented | ✅ PASS | This document + the gaps enumerated here. |

---

## Top items to resolve before a true v1.0 tag

1. **Packaging/release (§12):** add `Dockerfile` + compose, a CI workflow running
   the suite, dependency audit, release notes, and the v1.0 tag.
2. **Migrations (§1/§7):** either generate the initial Alembic revision (so
   upgrades are supported) or document that schema is `create_all` and ship a
   backup/restore note.
3. **Scope SSRF hardening (§3/§10)** *(if ever exposed beyond localhost):*
   connect-time IP pinning / DNS-rebinding defence and an optional RFC1918 guard.
4. **Multi-user posture (§10)** *(only if remote/shared):* per-user auth + HTTPS
   termination guidance; today's single-token localhost model is correct for a
   solo operator.
5. **Nice-to-have:** pause/resume (§2), diagnostics log rotation (§9), and the
   live stress/soak runs (§4, §5, §11) on an authorized lab.
