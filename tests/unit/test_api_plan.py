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
