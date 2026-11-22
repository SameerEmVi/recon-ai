"""
Plan/progress assembly for the Plan board.

The hybrid scanning engine models a scan as a DAG of jobs — one TARGET job per
authorized subdomain, and one MODULE job per (module, target). Those jobs ARE the
plan, and their lifecycle states (QUEUED → RUNNING → COMPLETED/FAILED/…) ARE the
execution. This assembler projects the persisted `jobs` rows into a per-target
board: each target with its module jobs and their states, plus a state summary.

Reads ONLY through `JobRepository` (no scan logic, no schema change). Jobs are
persisted live during a run, so a running hybrid scan shows partial progress and
the live WS `plan` frames advance it. Degrades gracefully: no DB, or a scan with
no jobs (a non-hybrid run records none), yields an empty board with `is_hybrid`
False so the UI can explain it.
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
            # jobs are its children.
            targets: dict[str, dict] = {}
            by_state: dict[str, int] = {}
            module_count = 0
            for j in jobs:
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

            for t in targets.values():
                t["modules"].sort(key=lambda m: (_rank(m["state"]), m["module"]))
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
