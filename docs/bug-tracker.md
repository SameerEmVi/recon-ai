# Recon-AI — Bug Tracker

Living log of defects found outside the formal QA pass. Newest first.
Status legend: 🔴 OPEN · 🟡 IN PROGRESS · 🟢 FIXED (uncommitted) · ✅ FIXED & COMMITTED · ⚪ WONTFIX / BY-DESIGN

---

## BUG-001 — Hybrid scan path never backfilled `target_domain` to the DB

- **Status:** ✅ FIXED & COMMITTED (`61fcc22`, `feature/recon-intelligence-subsystems`)
- **Severity:** Medium (data integrity / UI)
- **Found:** 2026-11-22, live test on authorized `hackycorp.com` during Map/Plan feature verification.
- **Area:** `controller/controller.py` (scan lifecycle, hybrid path)
- **Symptom:** A `--hybrid` scan persisted its scan row with `target_domain=''`. The
  default (non-hybrid) path backfilled the seed domain after discovery; the hybrid
  path (`_do_run_hybrid`) did not. Downstream effect: blank domain header on
  Map/Plan/Assets/Vulnerabilities, and the **Asset Map lost its root `domain`
  anchor node** (graph built off `root_domain`).
- **Root cause:** `scan_start` creates the DB row with `domain=""` (seed not yet
  known); only `_do_run` patched it later. `_do_run_hybrid` had no equivalent patch.
- **Fix:** Factored a shared `async def _persist_scan_domain(self, seed_domain)`
  helper (UPDATE `ScanJob.target_domain`), called by **both** `_do_run` and
  `_do_run_hybrid` (hybrid: right after `_load_and_setup_modules()`).
- **Verification:** Re-ran hybrid on hackycorp — DB row became
  `target_domain='hackycorp.com'`; Map regained its domain anchor + `subdomain`
  edge to `assets.hackycorp.com`. 72 controller/scheduler/graph/plan tests green.

## BUG-002 — DB scan row stored legacy `mode:"A"/"B"` instead of the recon `--mode`

- **Status:** 🟢 FIXED (uncommitted — option (a), repurposed per design)
- **Severity:** Low (cosmetic, but muddied history/diff semantics)
- **Found:** 2026-11-22, inspecting the hackycorp scan row during the Map/Plan test.
- **Area:** `controller/controller.py` (scan_start persistence), `database/models.py`
- **Symptom:** The persisted scan row's `mode` field was `"A"` (no-AI) / `"B"` (AI),
  a legacy A/B-test code — **not** the recon execution mode
  (`osint/active/vuln/full`). The in-memory scan list (API) correctly reported the
  real mode (e.g. `"full"`), so the DB value and the live value disagreed. Every
  DB-reading assembler (overview/assets/vulns/graph/plan + CLI `history` + MCP)
  surfaced `"A"/"B"`.
- **Fix (option a — repurpose per design):** persist `self._mode` (the real recon
  mode) on the scan row. Mode is the capability ceiling; whether AI ran is an
  **orthogonal** axis, still recorded in the `AiAssessment` table — so no signal is
  lost. Verified no code branched on the `"A"/"B"` value (all readers only display
  it). Model default changed `"A"` → `"active"`; module docstring + startup log line
  updated to separate mode from the AI flag.
- **Note on existing rows:** old sqlite rows written before this fix keep their
  `"A"/"B"` value (no Alembic migration path — see QA checklist §7); new scans
  record the real mode. A backfill is only worth it if historical `mode` accuracy
  matters.

## BUG-003 — Plan board was target-level only (no per-module chips)

- **Status:** 🟢 FIXED (uncommitted — Phase 2.5, per-module progress for all scans)
- **Severity:** Low (observability gap, not a correctness defect)
- **Found:** 2026-11-22, Map/Plan live test.
- **Area:** `controller/controller.py`, `database/persister.py`, `api/plan.py`,
  `frontend/src/pages/Plan.tsx`.
- **Symptom:** The Plan board showed each target plus a single `pipeline` module
  chip. The hybrid engine runs `ModuleSpec("pipeline")` (one job per target; the
  EventBus owns real module order), so no per-module state was ever recorded.
- **Fix (without breaking the "bus owns module order" invariant):** record real
  per-(target, module) progress from the **single reactive-dispatch chokepoint**
  (`_handler`), not by re-modelling modules as scheduler jobs. A module is marked
  RUNNING on first dispatch for a host, FAILED if it raises, and flipped to
  COMPLETED at scan end (`_finalize_module_progress` — a reactive module is only
  "done" with a host once the cascade settles). Each transition emits a live
  `plan` frame (via the existing scheduler-listener fan-out) **and** upserts a
  `JobRecord(kind="module")` keyed `module:<target>:<module>` (new
  `Persister.record_module_job`), so progress survives reloads and shows on
  finished scans. `build_plan` drops the synthetic `pipeline` chip and rolls a
  target's state up from its modules when there's no TARGET job.
- **Bonus:** because the chokepoint is shared, **default (non-hybrid) scans now
  populate the Plan board too** — the original Phase 2.5 goal. No scope / rate-limit
  / planner behaviour changed (observe-only).
- **Tests:** pipeline-drop + derived target state, persister upsert (one evolving
  row), controller progress tracking + finalize. Full suite 1037 passed; frontend
  typecheck + build clean.
- **Not done (future):** live end-to-end verification of the stream on an
  authorized target (unit-covered; the WS→board wiring was verified live for the
  hybrid scheduler path on 2026-11-22).
