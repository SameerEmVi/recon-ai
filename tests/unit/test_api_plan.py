"""
Plan/progress board tests.

`build_plan` groups the persisted hybrid `jobs` rows into a per-target board
(target state + its module jobs + a state summary), + route auth / no-DB /
no-jobs (non-hybrid) degradation. Also covers the controller scheduler-listener
hook the live Plan stream relies on.
"""

from __future__ import annotations

import uuid

import httpx

from api.app import create_app
from api.config import Settings
from api.plan import build_plan
from api.scans import ScanManager

TOKEN = "t"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


async def _seed(url: str, *, with_jobs: bool = True) -> uuid.UUID:
    from database.models import JobRecord
    from database.repository import JobRepository, ScanRepository
    from database.session import init_db, make_engine, make_session_factory
    from scheduler.jobs import Job, JobKind, JobState

    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        await ScanRepository(s).create(sid, "ex.com", {}, "A")
        if with_jobs:
            jr = JobRepository(s)

            async def save(target, kind, state, module=None, error=None):
                job = Job(target=target, scan_id=sid, kind=kind, module=module)
                job.state = state
                job.error = error
                await jr.upsert(JobRecord.from_job(job, scan_job_id=sid))

            # Target A: running, two modules (one done, one running).
            await save("a.ex.com", JobKind.TARGET, JobState.RUNNING)
            await save("a.ex.com", JobKind.MODULE, JobState.COMPLETED, module="httpx_probe")
            await save("a.ex.com", JobKind.MODULE, JobState.RUNNING, module="ffuf")
            # Target B: a module failed.
            await save("b.ex.com", JobKind.TARGET, JobState.PARTIAL)
            await save("b.ex.com", JobKind.MODULE, JobState.FAILED, module="nuclei", error="timeout")
            # Target C: rejected by scope — never ran.
            await save("evil.com", JobKind.TARGET, JobState.OUT_OF_SCOPE)
    await engine.dispose()
    return sid


async def test_plan_groups_jobs_by_target(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'p.db').as_posix()}"
    sid = await _seed(url)

    out = await build_plan(ScanManager(), url, str(sid))
    assert out["scan"]["domain"] == "ex.com"
    assert out["is_hybrid"] is True
    assert out["summary"]["targets"] == 3 and out["summary"]["modules"] == 3
    assert out["summary"]["by_state"]["RUNNING"] == 2   # target A + ffuf module

    by_target = {t["target"]: t for t in out["targets"]}
    a = by_target["a.ex.com"]
    assert a["state"] == "RUNNING"
    mods = {m["module"]: m for m in a["modules"]}
    assert mods["ffuf"]["state"] == "RUNNING" and mods["httpx_probe"]["state"] == "COMPLETED"
    assert by_target["b.ex.com"]["modules"][0]["error"] == "timeout"
    assert by_target["evil.com"]["state"] == "OUT_OF_SCOPE"

    # A running target sorts ahead of a terminal one.
    assert out["targets"][0]["target"] == "a.ex.com"


async def test_plan_empty_without_jobs_is_not_hybrid(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'p2.db').as_posix()}"
    sid = await _seed(url, with_jobs=False)
    out = await build_plan(ScanManager(), url, str(sid))
    assert out["is_hybrid"] is False and out["targets"] == []


async def test_plan_route_auth_and_no_db():
    app = create_app(Settings(token=TOKEN, db_url=None), ScanManager())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/plan")).status_code == 401
        r = await c.get("/api/plan", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["scan"] is None and body["targets"] == [] and body["is_hybrid"] is False


async def test_plan_drops_pipeline_and_derives_target_state(tmp_path):
    # A default (non-hybrid) scan records only per-(target, module) MODULE jobs —
    # no TARGET job — plus the hybrid engine's synthetic "pipeline" job must be
    # dropped. The target's own state is rolled up from its real modules.
    import uuid as _uuid

    from database.models import JobRecord
    from database.repository import JobRepository, ScanRepository
    from database.session import init_db, make_engine, make_session_factory

    url = f"sqlite+aiosqlite:///{(tmp_path / 'p3.db').as_posix()}"
    engine = make_engine(url)
    await init_db(engine)
    sid = _uuid.uuid4()
    async with make_session_factory(engine)() as s:
        await ScanRepository(s).create(sid, "ex.com", {}, "full")
        jr = JobRepository(s)

        async def mod(target, module, state, kind="module"):
            await jr.upsert(JobRecord(
                scan_job_id=sid, kind=kind, target=target, module=module,
                state=state, dedup_key=f"{kind}:{target}:{module}"))

        # a.ex.com: real modules (one running) + a synthetic pipeline job to drop.
        await mod("a.ex.com", "httpx_probe", "COMPLETED")
        await mod("a.ex.com", "ffuf", "RUNNING")
        await mod("a.ex.com", "pipeline", "COMPLETED")
        # b.ex.com: a module failed alongside a completed one -> PARTIAL rollup.
        await mod("b.ex.com", "secretfinder", "COMPLETED")
        await mod("b.ex.com", "nuclei", "FAILED")
    await engine.dispose()

    out = await build_plan(ScanManager(), url, str(sid))
    assert out["is_hybrid"] is True
    by_target = {t["target"]: t for t in out["targets"]}
    a = by_target["a.ex.com"]
    assert {m["module"] for m in a["modules"]} == {"httpx_probe", "ffuf"}  # no pipeline
    assert a["state"] == "RUNNING"                     # derived from modules
    assert by_target["b.ex.com"]["state"] == "PARTIAL"  # completed + failed
    assert out["summary"]["modules"] == 4               # pipeline excluded from count


async def test_persister_record_module_job_upserts(tmp_path):
    # One evolving row per (target, module): RUNNING then COMPLETED, not two rows.
    import uuid as _uuid

    from database.persister import Persister
    from database.repository import JobRepository, ScanRepository
    from database.session import init_db, make_engine, make_session_factory

    url = f"sqlite+aiosqlite:///{(tmp_path / 'p4.db').as_posix()}"
    engine = make_engine(url)
    await init_db(engine)
    sid = _uuid.uuid4()
    async with make_session_factory(engine)() as s:
        await ScanRepository(s).create(sid, "ex.com", {}, "full")
        p = Persister(s)
        await p.record_module_job(sid, "a.ex.com", "ffuf", "RUNNING")
        await p.record_module_job(sid, "a.ex.com", "ffuf", "COMPLETED")
        await p.record_module_job(sid, "a.ex.com", "nuclei", "FAILED", error="boom")
        jobs = await JobRepository(s).list_for_scan(sid)
    await engine.dispose()

    rows = {(j.target, j.module): j for j in jobs}
    assert len(rows) == 2                               # ffuf upserted, not duplicated
    assert rows[("a.ex.com", "ffuf")].state == "COMPLETED"
    assert rows[("a.ex.com", "nuclei")].state == "FAILED"
    assert rows[("a.ex.com", "nuclei")].error == "boom"


async def test_controller_module_progress_tracks_and_finalizes():
    # The reactive-dispatch chokepoint records per-(target, module) progress and
    # streams it to observers; finalize flips survivors RUNNING -> COMPLETED.
    from scope.types import Scope
    from controller.controller import ScanController
    from events.types import Event, EventType, SubdomainData, UrlData

    c = ScanController(Scope.from_strings(in_scope=["ex.com"]), results_enabled=False)
    frames: list = []

    async def obs(name, payload):
        frames.append((name, payload.get("target"), payload.get("module"),
                       payload.get("status")))

    c.add_scheduler_listener(obs)

    sub = Event.create(EventType.SUBDOMAIN, SubdomainData(hostname="a.ex.com", source="t"),
                       scan_job_id=c.scan_id, source_tool="t")
    url = Event.create(EventType.URL, UrlData(url="https://a.ex.com/x"),
                       scan_job_id=c.scan_id, source_tool="t")

    await c._note_module_running("ffuf", sub)
    await c._note_module_running("ffuf", url)         # same (target, module) -> no 2nd frame
    await c._note_module_failed("nuclei", sub, RuntimeError("boom"))
    assert c._module_runs[("a.ex.com", "ffuf")] == "RUNNING"
    assert c._module_runs[("a.ex.com", "nuclei")] == "FAILED"

    await c._finalize_module_progress()
    assert c._module_runs[("a.ex.com", "ffuf")] == "COMPLETED"   # survivor flipped
    assert c._module_runs[("a.ex.com", "nuclei")] == "FAILED"    # failures kept

    assert ("module_started", "a.ex.com", "ffuf", "RUNNING") in frames
    assert ("module_failed", "a.ex.com", "nuclei", "FAILED") in frames
    assert ("module_completed", "a.ex.com", "ffuf", "COMPLETED") in frames
    assert sum(1 for f in frames if f[1:3] == ("a.ex.com", "ffuf")) == 2  # start + complete


async def test_controller_scheduler_listener_receives_events():
    # The live Plan stream relies on add_scheduler_listener fanning scheduler
    # lifecycle to observers, and on a raising observer never breaking the fan-out.
    from scope.types import Scope
    from controller.controller import ScanController

    c = ScanController(Scope.from_strings(in_scope=["ex.com"]), results_enabled=False)
    seen: list = []

    async def good(name, payload):
        seen.append((name, payload.get("target")))

    async def bad(name, payload):
        raise RuntimeError("observer boom")

    c.add_scheduler_listener(bad)      # must not break the fan-out
    c.add_scheduler_listener(good)
    await c._on_scheduler_event("module_started", {"target": "a.ex.com", "module": "ffuf"})
    assert seen == [("module_started", "a.ex.com")]
