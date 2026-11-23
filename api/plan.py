"""
Plan/progress assembly for the Plan board.

A scan's execution is modelled as per-target / per-module job rows. The hybrid
engine adds a TARGET job per authorized subdomain (and one synthetic "pipeline"
MODULE job, dropped here); the controller records a real MODULE job per
(target, module) as the reactive cascade runs, so BOTH hybrid and default scans
populate the board. Their lifecycle states (QUEUED → RUNNING → COMPLETED/FAILED/…)
ARE the execution. This assembler projects the persisted `jobs` rows into a
per-target board: each target with its module jobs and their states, rolling the
target's own state up from its modules when there is no TARGET job (default scan).

Reads ONLY through `JobRepository` (no scan logic, no schema change). Jobs are
persisted live during a run, so a running scan shows partial progress and the live
WS `plan` frames advance it. Degrades gracefully: no DB, or a scan with no jobs
(e.g. one with no network modules), yields an empty board with `is_hybrid` False
so the UI can explain it.
"""

from __future__ import annotations

from uuid import UUID

# Order the UI renders target/module state chips in (most-active first).
STATE_ORDER = ["RUNNING", "VALIDATING", "QUEUED", "PAUSED", "COMPLETED",
               "PARTIAL", "FAILED", "CANCELLED", "OUT_OF_SCOPE"]
_MAX_TARGETS = 2000


def _empty() -> dict:
    return {"scan": None, "targets": [], "is_hybrid": False,
            "summary": {"targets": 0, "modules": 0, "by_state": {}}}


async def build_plan(manager, db_url: str | None, scan_id: str | None = None) -> dict:
    out = _empty()
    if not db_url:
        return out

    target_id = scan_id
    if not target_id:
        entries = manager.list()
        target_id = entries[0].scan_id if entries else None

    from database.repository import JobRepository, ScanRepository
    from database.session import make_engine, make_session_factory

    engine = make_engine(db_url)
    try:
        async with make_session_factory(engine)() as s:
            scan_repo = ScanRepository(s)
            scan = None
            if target_id:
                try:
                    scan = await scan_repo.get(UUID(target_id))
                except Exception:
                    scan = None
            if scan is None:
                recent = await scan_repo.recent_all(1)
                scan = recent[0] if recent else None
            if scan is None:
                return out

            out["scan"] = {"scan_id": str(scan.id), "domain": scan.target_domain,
                           "status": scan.status, "mode": scan.mode}

            jobs = await JobRepository(s).list_for_scan(scan.id)
            if not jobs:
                return out
            out["is_hybrid"] = True

            # Group by target: the TARGET job gives the target's own state; MODULE
            # jobs are its children. The hybrid scheduler emits a single synthetic
            # "pipeline" MODULE job per target (the bus owns real module order) —
            # drop it, since real per-module progress is now recorded separately.
            targets: dict[str, dict] = {}
            by_state: dict[str, int] = {}
            module_count = 0
            for j in jobs:
                if j.kind != "target" and (j.module or "") == "pipeline":
                    continue
                by_state[j.state] = by_state.get(j.state, 0) + 1
                t = targets.setdefault(j.target, {"target": j.target, "state": None,
                                                  "modules": []})
                if j.kind == "target":
                    t["state"] = j.state
                else:
                    module_count += 1
                    t["modules"].append({"module": j.module or "?", "state": j.state,
                                         "error": j.error})

            def _rank(state: str | None) -> int:
                try:
                    return STATE_ORDER.index(state or "QUEUED")
                except ValueError:
                    return len(STATE_ORDER)

            def _derive_target_state(mods: list[dict]) -> str | None:
                """Default (non-hybrid) scans have no TARGET job — roll the target
                state up from its module jobs so the board still shows progress."""
                states = {m["state"] for m in mods}
                if not states:
                    return None
                if states & {"RUNNING", "VALIDATING", "QUEUED", "PAUSED"}:
                    return "RUNNING"
                if "FAILED" in states:
                    return "PARTIAL" if states - {"FAILED"} else "FAILED"
                return "COMPLETED"

            for t in targets.values():
                t["modules"].sort(key=lambda m: (_rank(m["state"]), m["module"]))
                if t["state"] is None:
                    t["state"] = _derive_target_state(t["modules"])
            target_rows = sorted(
                targets.values(),
                key=lambda t: (_rank(t["state"]), -len(t["modules"]), t["target"]),
            )[:_MAX_TARGETS]

            out["targets"] = target_rows
            out["summary"] = {"targets": len(targets), "modules": module_count,
                              "by_state": by_state}
    except Exception:
        # A read failure must never break the board — return what we have.
        pass
    finally:
        await engine.dispose()

    return out
