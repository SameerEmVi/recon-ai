# Hybrid Parallel Scanning Engine — Developer Reference

How recon-ai scans many authorized subdomains **concurrently** without weakening
any of its security properties. Grounded in the current code: the `scheduler/`
package, the `ratelimit/` extensions, and the controller/CLI wiring.

> TL;DR — `--hybrid` turns on a bounded **worker pool** that schedules one job per
> authorized subdomain (and, per target, a prerequisite-ordered module DAG). Each
> job is seeded into the **existing** event bus + module cascade through the
> **same** `ScopeEngine` chokepoint, and every outbound request still passes
> through the **one** shared `RateLimiter`. Worker count bounds *job* concurrency
> only — it never multiplies the request budget. The default scan path is
> unchanged when `--hybrid` is off.

This is an **orchestration layer**, not a rewrite. It adds no new scope logic, no
new rate limiter, no new HTTP client, and no new persistence schema concepts — it
composes the ones that already exist.

---

## 1. Where it sits

```
                 ┌──────────────────────── ScanController ────────────────────────┐
                 │                                                                 │
  authorized     │   HybridScheduler ── WorkerPool (≤ N workers, bounded queue)    │
  subdomains ───▶│        │                     │                                  │
  (--targets-    │        │ per target:         │ runs each job's runner:          │
   file / seed)  │        ▼                     ▼                                  │
                 │   scope.evaluate(host)   build_subdomain_runner(controller)     │
                 │        │  IN                 │                                  │
                 │        ▼                     ▼                                  │
                 │   module DAG gate  ──▶  stamp_and_publish(SUBDOMAIN)  ──────────┼──▶ EventBus
                 │                               (SAME scope chokepoint)           │     │
                 └───────────────────────────────────────────────────────────────┘     ▼
                                                                          existing module cascade
                                                                   (dnsx → httpx_probe → web/… )
                                                                                        │
   every outbound request from any module ───────────────────────────────────────────▶ RateLimiter.guard()
                                                                   (ONE shared limiter: rps + concurrency + WAF backoff)
```

The scheduler decides **which targets run and in what order**. It does **not**
touch what a module does once a target is seeded — that is the normal
event-driven pipeline, unchanged.

---

## 2. Files created / modified

### Created — `scheduler/` package

| File | Role |
|---|---|
| `scheduler/jobs.py` | `Job` dataclass, `JobKind` (TARGET/MODULE), `JobState` (9 states) + strict transition table, `InvalidTransition`. |
| `scheduler/pool.py` | `WorkerPool` — bounded asyncio worker pool over a `PriorityQueue`; dedup, backpressure, per-job timeout, failure isolation, graceful + hard shutdown, live counters. |
| `scheduler/engine.py` | `HybridScheduler` + `ModuleSpec` + `SchedulerReport`; subdomain-level scope gate, per-target module DAG (validated acyclic), roll-up, WAF/rate-limit notice hooks, cancel. |
| `scheduler/events.py` | §11 event taxonomy: 15 event-name constants + `build_event()` (UTC timestamp, **redacted** metadata). |
| `scheduler/report.py` | §12 unified report: `build_report_dict()` + `render_report_text()`. |
| `scheduler/integration.py` | Controller glue: `derive_module_specs()` (producer→watcher DAG, cycle-breaking), `build_subdomain_runner()`, `load_targets_file()`. |
| `scheduler/__init__.py` | Public exports. |

### Modified — composition points (no behavioural change when `--hybrid` is off)

| File | Change |
|---|---|
| `ratelimit/__init__.py` | `RateLimiter` gained `global_rate_per_sec` (aggregate token bucket w/ `burst`), `per_target_concurrency` (per-host semaphore), per-bucket backoff + `Retry-After` cooldown, `bucket=` on `observe_http`/`penalize`, and `stats()`. All opt-in — unset ⇒ prior behaviour. |
| `database/models.py` | Added `JobRecord` (table `jobs`, unique `(scan_job_id, dedup_key)`, `from_job()`). |
| `database/repository.py` | Added `JobRepository` (upsert / set_state / get / list_for_scan). |
| `database/persister.py` | Added `save_job()` (lock-serialized, never raises) + `list_jobs()`. |
| `controller/controller.py` | Constructor params `hybrid / workers / module_concurrency / hybrid_targets`; wires `per_target_concurrency` to the shared limiter (every scan); `_do_run_hybrid()`, `_on_scheduler_event()`, `scheduler_report` property. |
| `cli/main.py` | `--hybrid`, `--workers`, `--module-concurrency`, `--targets-file` + validation; `scan-status` command. |

### Tests (created / extended)

`tests/unit/test_scheduler_jobs.py` (12), `test_scheduler_pool.py` (10),
`test_scheduler_engine.py` (8), `test_scheduler_report.py` (6),
`test_scheduler_integration.py` (7), `test_scheduler_perf.py` (3, local mock
server), and `test_ratelimit.py` (+8 for the new limiter features).

---

## 3. Scheduler design

### Job lifecycle (`scheduler/jobs.py`)

```
QUEUED ──▶ VALIDATING ──▶ RUNNING ──▶ COMPLETED
   │            │            │    └──▶ PARTIAL   (target: some modules ok)
   │            │            │    └──▶ FAILED
   │            │            └──────▶ PAUSED ──▶ RUNNING
   │            └───────────────────▶ OUT_OF_SCOPE   (scope gate said not IN)
   └────────────────────────────────▶ CANCELLED      (never ran / shutdown)
```

Transitions are enforced by an allow-list (`_ALLOWED`); an illegal move raises
`InvalidTransition`. Same-state transitions are idempotent. `TERMINAL_STATES` =
{COMPLETED, PARTIAL, FAILED, CANCELLED, OUT_OF_SCOPE}. `dedup_key` is
`"{kind}:{target}[:{module}]"` with the target normalized (lower, no trailing
dot) — this is what prevents a subdomain (or a per-target module) being scheduled
twice.

### Worker pool (`scheduler/pool.py`)

* **Bounded** `PriorityQueue(maxsize = max(max_workers*100, 100))` → `submit()`
  blocks (backpressure) rather than growing without limit.
* **Priority with FIFO tie-break** (monotonic sequence) so equal-priority jobs are
  fair and none is starved.
* **Dedup** on `dedup_key` before a job is ever queued.
* **Per-job timeout** (`asyncio.wait_for`) and **failure isolation** — a runner
  raising marks *that* job FAILED and never touches its siblings.
* **Shutdown**: graceful (`join` then stop) or hard (`cancel=True` → in-flight and
  still-queued jobs become CANCELLED, marked + emitted from a non-cancelled
  context so the event is reliably published). `_finish` is idempotent.

### Two levels of concurrency (`scheduler/engine.py`)

* **Subdomain level** — every in-scope target runs as its own TARGET job,
  concurrently; an out-of-scope target becomes `OUT_OF_SCOPE` and never runs;
  targets dedup after normalization.
* **Module level** — per target, a `ModuleSpec` DAG: independent modules run
  concurrently, a module with `requires` waits on those futures first. A failed
  prerequisite → dependents `CANCELLED`; an independent module failing → the
  target rolls up to `PARTIAL`, not dead. The DAG is validated **acyclic at
  construction** (`_validate_dag`, fail-closed on unknown prereq or cycle).

> In the current controller wiring the per-target DAG is a single
> `ModuleSpec("pipeline")` job — because once a subdomain is seeded, the **event
> bus already owns module ordering** via watched/produced events. The DAG
> machinery (and `derive_module_specs`, which builds a real producer→watcher DAG
> with cycle-breaking) is in place and unit-tested for when finer-grained
> per-module scheduling is wired to the pool.

---

## 4. Configuration

| CLI flag | Controller param | Limiter / pool effect | Default |
|---|---|---|---|
| `--hybrid` | `hybrid` | Switch on the worker-pool pass. Off ⇒ unchanged scan. | off |
| `--workers N` | `workers` | `WorkerPool(max_workers=N)`, clamped `1..SAFETY_CEILING(50)`. **Job** concurrency only. | 10 |
| `--module-concurrency K` | `module_concurrency` | `RateLimiter(per_target_concurrency=K)` — max simultaneous requests to **one** host. Applies to **every** scan. | unlimited |
| `--targets-file PATH` | `hybrid_targets` | Authorized subdomain list (one host/line, `#` comments, deduped, normalized); each scope-validated. | seed domain |
| `-r / --rate-limit` | — | Per-bucket rps spacing (pre-existing). | unlimited |
| `-c / --max-concurrency` | — | Global in-flight op cap (pre-existing). | unlimited |

The aggregate `global_rate_per_sec` + `burst` token-bucket parameters exist on
`RateLimiter` for the engine to impose a scan-wide ceiling; they are the
mechanism that makes worker count independent of request budget (§6, §7) and are
exercised directly by the perf tests.

---

## 5. CLI examples

```bash
# Opt-in hybrid over an authorized subdomain list, 10 workers (default)
python -m cli.main scan example.com --hybrid --targets-file authorized_subs.txt

# More workers, but requests to any single host capped at 4 simultaneous
python -m cli.main scan example.com --hybrid --workers 20 \
    --targets-file authorized_subs.txt --module-concurrency 4

# Worker count bounded jobs, aggregate request rate still bounded by -r
python -m cli.main scan example.com --hybrid --workers 15 -r 5 -c 20 \
    --targets-file authorized_subs.txt

# Hybrid with DB persistence → inspect per-target/per-module job state afterward
python -m cli.main scan example.com --hybrid --targets-file subs.txt \
    --db-url "sqlite+aiosqlite:///recon.db"
python -m cli.main scan-status <scan_id> --db-url "sqlite+aiosqlite:///recon.db"
python -m cli.main scan-status <scan_id> --state FAILED --db-url ...   # filter
```

`--targets-file` without `--hybrid` prints a warning and is ignored (the flag only
has meaning for the hybrid pass). A missing or empty targets file exits non-zero
with a clear message.

---

## 6. Worker allocation

`--workers N` sizes the pool that runs **jobs** (one job ≈ one authorized
subdomain's scan). It is a *job-concurrency* knob:

* **Clamped** to `1..SAFETY_CEILING (50)` by `WorkerPool._clamp_workers` — a
  guardrail against accidentally launching a stampede; bad input falls back to the
  default 10.
* N workers means **at most N subdomains are being scanned at once**. The
  remaining targets wait in the bounded queue.
* N has **no effect on how fast requests go out** — that is the limiter's job
  (§7). Raising workers lets more *distinct hosts* make progress in parallel; it
  does not raise the total request rate.

---

## 7. Rate-limit enforcement (why workers ≠ request budget)

There is exactly **one** `RateLimiter` per scan (owned by the controller, shared
by every module, wrapper, and the engine). Every outbound request — regardless of
which worker/target it belongs to — passes through `RateLimiter.guard(bucket)`,
which applies, in order:

1. **Per-target semaphore** (`per_target_concurrency`, from `--module-concurrency`)
   — one slow/blocked host can't hold global slots and starve others.
2. **Global semaphore** (`max_concurrency`, from `-c`) — caps total in-flight ops.
3. **Aggregate token bucket** (`global_rate_per_sec` + `burst`) — a scan-wide
   req/s ceiling. It refills at the configured rate, spends one token per op, and
   **reserves future capacity** so concurrent callers can't all burst past the
   rate at once. This is the piece that decouples throughput from worker count.
4. **Per-bucket spacing** at the effective penalty (max of scan-wide and this
   target's own backoff) plus any **cooldown** (WAF / honoured `Retry-After`).

Because all four live in the single shared limiter, 10 workers and 3 workers hit
the *same* ceiling (measured in §9). WAF handling is per-target adaptive backoff +
cooldown — the engine **never** rotates proxies or raises concurrency to "get
around" a block; a block slows that target down. The engine's `note_waf` /
`note_rate_limited` hooks only *record evidence*; the slow-down is the limiter's.

---

## 8. Observability & persistence

* **Events** (`scheduler/events.py`): `scan_started`, `workers_started`,
  `target_discovered`, `subdomain_job_queued`, `target_out_of_scope`,
  `target_started`, `module_started/completed/failed`, `rate_limit_reached`,
  `waf_restriction_detected`, `target_paused`, `target_completed`,
  `scan_completed`, `scan_cancelled`. Each carries a UTC timestamp and
  **redacted** metadata (`net/redact.py`), and is fanned onto the per-run
  diagnostics stream via `controller._on_scheduler_event`.
* **Persistence**: every job lifecycle update is upserted to the `jobs` table
  through `Persister.save_job` (lock-serialized, never raises). `scan-status`
  reconstructs per-target/per-module state from those rows after the fact.
* **Unified report** (`scheduler/report.py`): printed at the end of a hybrid run —
  targets (completed/partial/failed/out-of-scope), modules + success rate, total
  requests + aggregate req/s, workers + jobs/worker, queue high-water, WAF
  vendors / backed-off / cooldown targets, proxy state, diagnostics dir.

---

## 9. Test commands + **actual** results

```bash
# whole scheduler surface + the limiter extensions
python -m pytest tests/unit/test_scheduler_jobs.py tests/unit/test_scheduler_pool.py \
    tests/unit/test_scheduler_engine.py tests/unit/test_scheduler_report.py \
    tests/unit/test_scheduler_integration.py tests/unit/test_scheduler_perf.py \
    tests/unit/test_ratelimit.py -q

# local mock-server performance tests only (no public network)
python -m pytest tests/unit/test_scheduler_perf.py -v

# full regression
python -m pytest -q
```

Actual results on this machine (Windows, Python 3.13.5, pytest 9.1.1):

```
tests/unit/test_scheduler_perf.py ...                         3 passed in 6.22s
python -m pytest -q                                         961 passed in 44.49s
```

`961` = the prior `958` plus the 3 new perf tests. No fabricated numbers — the
perf figures below are printed by the tests' own workload.

---

## 10. Performance measurements (local mock server, no network)

`tests/unit/test_scheduler_perf.py` stands up a localhost HTTP/1.1 server and
drives **real** guarded httpx GETs through the real `WorkerPool` + `RateLimiter`.
Measured:

| Scenario | Config | Result | Proves |
|---|---|---|---|
| Aggregate ceiling, few workers | 25 req/s ceiling, burst 1, 50 reqs / 5 buckets, **3 workers** | **2.03 s → 24.7 req/s** | limiter paces to the ceiling |
| Aggregate ceiling, many workers | same, **10 workers** | **2.00 s → 25.0 req/s** | **10 workers is NOT faster than 3** — worker count ≠ request budget |
| Per-target concurrency cap | `per_target_concurrency=2`, 10 workers, 24 reqs / 1 host | server saw **max 2** concurrent for that host | per-host cap holds under a big pool |
| Global concurrency cap | `max_concurrency=4`, 10 workers, 40 reqs / 8 hosts | server saw **max 4** concurrent overall | global cap holds under a big pool |

The headline invariant (§7) is demonstrated end-to-end: tripling-plus the worker
count (3 → 10) left wall-clock essentially unchanged (2.03 s → 2.00 s) because the
shared limiter — not the pool — governs throughput.

---

## 11. Known limitations

1. **No live binary/target validation in CI.** The perf and integration tests use
   a local mock server and stub runners; they do **not** run real recon binaries
   against a real target. End-to-end validation against an authorized target is an
   operator step, not an automated one.
2. **Per-target module DAG is not yet pool-scheduled in the controller.** The
   controller seeds one `ModuleSpec("pipeline")` job per target and lets the event
   bus order modules (the pre-existing, correct behaviour). The finer-grained DAG
   executor and `derive_module_specs` are implemented and unit-tested but not yet
   the controller's default wiring.
3. **`PAUSED` is modelled but not operator-triggered.** The state and transitions
   exist; there is no CLI to pause/resume a running target mid-scan yet. WAF
   handling uses the limiter's per-target cooldown instead of pausing the job.
4. **Aggregate `global_rate_per_sec` is not yet surfaced as its own CLI flag.** The
   token bucket is wired and tested; hybrid runs currently bound total rate via the
   existing per-bucket `-r` and the concurrency caps. Exposing a dedicated
   scan-wide `--global-rate` is a small follow-up.
5. **In-memory dedup/counters are per process.** A resumed or re-launched scan
   re-reads persisted jobs but the pool's in-memory dedup set starts empty; dedup
   across process restarts relies on the DB unique constraint, not the pool.
