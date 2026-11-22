# Recon-AI — Bug Tracker

Living log of defects found outside the formal QA pass. Newest first.
Status legend: 🔴 OPEN · 🟡 IN PROGRESS · 🟢 FIXED (uncommitted) · ✅ FIXED & COMMITTED · ⚪ WONTFIX / BY-DESIGN

---

## BUG-001 — Hybrid scan path never backfilled `target_domain` to the DB

- **Status:** 🟢 FIXED (uncommitted — on `feature/recon-intelligence-subsystems`, part of the Map/Plan work)
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

## BUG-002 — DB scan row stores legacy `mode:"A"/"B"` instead of the recon `--mode`

- **Status:** 🔴 OPEN (pre-existing, unfixed — flagged for a decision)
- **Severity:** Low (cosmetic, but may muddy history/diff semantics)
- **Found:** 2026-11-22, inspecting the hackycorp scan row during the Map/Plan test.
- **Area:** `controller/controller.py` (~line 744, the A/B persistence code)
- **Symptom:** The persisted scan row's `mode` field is `"A"` (no-AI) / `"B"` (AI),
  a legacy A/B-test code — **not** the recon execution mode
  (`osint/active/vuln/full`). The in-memory scan list (API) correctly reports the
  real mode (e.g. `"full"`), so the DB value and the live value disagree.
- **Impact:** Every DB-reading assembler surfaces `"A"/"B"` for `mode`. No functional
  break observed, but anything keying history/diff on `mode` sees the wrong value.
- **Next action (needs user call):** decide whether to (a) repurpose the column to
  the real recon mode, (b) add a separate column, or (c) leave as-is and document.
  Not fixed autonomously — it touches persisted-row semantics (history/diff).

## BUG-003 — Plan board is target-level only under `--hybrid` (no per-module chips)

- **Status:** ⚪ BY-DESIGN (limitation, not a defect — candidate for Phase 2.5)
- **Severity:** N/A (expected behaviour; logged so it isn't re-investigated as a bug)
- **Found:** 2026-11-22, Map/Plan live test.
- **Area:** `scheduler/` integration (hybrid runs `ModuleSpec("pipeline")` — one
  "pipeline" job per target; the EventBus owns module ordering), surfaced in
  `api/plan.py` + `frontend/src/pages/Plan.tsx`.
- **Symptom:** The Plan board shows each target plus a single `pipeline` module chip,
  not one chip per recon module. This is correct for how the hybrid engine models
  jobs today.
- **Would-be fix (Phase 2.5):** model each module as its own scheduler job so the
  Plan board can show per-module lifecycle. Non-trivial — changes the hybrid job
  granularity. Deferred pending user direction.
