"""
Phase 3 tests — event-driven planner: deterministic apply, idempotency,
scope/tool/capability rejection, and a full round persisting a PlannerRound.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from database.exploration_models import Goal, Intent, PlannerRound
from database.models import ScanJob
from database.session import init_db, make_engine, make_session_factory
from exploration.planner import apply_decision, run_planner_round
from exploration.schemas import PlannerDecision
from exploration.store import ExplorationStore
from exploration.types import GoalState, IntentState

KNOWN = {"httpx_probe", "subfinder", "nuclei_info"}


@pytest.fixture
async def ctx(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'x.db'}")
    await init_db(engine)
    sf = make_session_factory(engine)
    async with sf() as s:
        sid = uuid.uuid4()
        s.add(ScanJob(id=sid, target_domain="example.com", mode="full", status="running"))
        store = ExplorationStore(s)
        run = await store.create_run(scan_job_id=sid, title="Assess", target="example.com")
        goal = await store.create_goal(exploration_id=run.id, title="Identify services",
                                       success_criteria="live service recorded", state=GoalState.ACTIVE.value)
        yield {"s": s, "store": store, "run": run, "goal": goal}
    await engine.dispose()


def _in_scope(target: str) -> bool:
    return target.endswith("example.com")


async def test_apply_creates_goal_and_intent(ctx):
    store, run, goal, s = ctx["store"], ctx["run"], ctx["goal"], ctx["s"]
    dec = PlannerDecision(operations=[
        {"op": "create_goal", "title": "Fingerprint technologies", "success_criteria": "tech linked"},
        {"op": "create_intent", "goal_id": str(goal.id), "title": "probe api",
         "tool_name": "httpx_probe", "target": "api.example.com"},
    ])
    res = await apply_decision(store, run, dec, scope_ok=_in_scope, capability_ok=lambda t: True, known_tools=KNOWN)
    assert res.created_goals == 1 and res.created_intents == 1
    it = (await s.execute(select(Intent).where(Intent.exploration_id == run.id))).scalars().all()
    assert len(it) == 1 and it[0].state == IntentState.QUEUED.value


async def test_intent_idempotent(ctx):
    store, run, goal = ctx["store"], ctx["run"], ctx["goal"]
    op = {"op": "create_intent", "goal_id": str(goal.id), "title": "probe",
          "tool_name": "httpx_probe", "target": "api.example.com"}
    await apply_decision(store, run, PlannerDecision(operations=[op]), scope_ok=_in_scope, capability_ok=lambda t: True, known_tools=KNOWN)
    res2 = await apply_decision(store, run, PlannerDecision(operations=[op]), scope_ok=_in_scope, capability_ok=lambda t: True, known_tools=KNOWN)
    assert res2.created_intents == 0   # deduped — not created twice
    n = (await ctx["s"].execute(select(func.count()).select_from(Intent))).scalar_one()
    assert n == 1


async def test_goal_idempotent(ctx):
    store, run = ctx["store"], ctx["run"]
    op = {"op": "create_goal", "title": "Identify Services", "success_criteria": "x"}  # dup of seeded (case-insensitive)
    res = await apply_decision(store, run, PlannerDecision(operations=[op]), scope_ok=_in_scope, capability_ok=lambda t: True, known_tools=KNOWN)
    assert res.created_goals == 0


async def test_out_of_scope_intent_rejected(ctx):
    store, run, goal, s = ctx["store"], ctx["run"], ctx["goal"], ctx["s"]
    dec = PlannerDecision(operations=[{"op": "create_intent", "goal_id": str(goal.id),
                                       "title": "probe evil", "tool_name": "httpx_probe", "target": "evil.com"}])
    res = await apply_decision(store, run, dec, scope_ok=_in_scope, capability_ok=lambda t: True, known_tools=KNOWN)
    assert res.created_intents == 0 and any("out of scope" in r for r in res.rejected)
    assert (await s.execute(select(func.count()).select_from(Intent))).scalar_one() == 0


async def test_unknown_tool_and_capability_rejected(ctx):
    store, run, goal = ctx["store"], ctx["run"], ctx["goal"]
    unknown = PlannerDecision(operations=[{"op": "create_intent", "goal_id": str(goal.id),
                                           "title": "x", "tool_name": "metasploit", "target": "api.example.com"}])
    r1 = await apply_decision(store, run, unknown, scope_ok=_in_scope, capability_ok=lambda t: True, known_tools=KNOWN)
    assert r1.created_intents == 0 and any("not a registered tool" in r for r in r1.rejected)

    forbidden = PlannerDecision(operations=[{"op": "create_intent", "goal_id": str(goal.id),
                                             "title": "x", "tool_name": "nuclei_info", "target": "api.example.com"}])
    r2 = await apply_decision(store, run, forbidden, scope_ok=_in_scope, capability_ok=lambda t: False, known_tools=KNOWN)
    assert r2.created_intents == 0 and any("capability not permitted" in r for r in r2.rejected)


async def test_block_and_stop(ctx):
    store, run, goal, s = ctx["store"], ctx["run"], ctx["goal"], ctx["s"]
    dec = PlannerDecision(operations=[
        {"op": "block_goal", "goal_id": str(goal.id), "reason": "no reachable services"},
        {"op": "stop", "reason": "nothing more to do"},
    ])
    res = await apply_decision(store, run, dec, scope_ok=_in_scope, capability_ok=lambda t: True, known_tools=KNOWN)
    assert res.blocked == 1 and res.stop and res.stop_reason == "nothing more to do"
    g = (await s.execute(select(Goal).where(Goal.id == goal.id))).scalar_one()
    assert g.state == GoalState.BLOCKED.value


async def test_run_planner_round_records_round(ctx):
    s, run, goal = ctx["s"], ctx["run"], ctx["goal"]

    async def propose(_p, _t):
        return {"reasoning": "probe the service",
                "operations": [{"op": "create_intent", "goal_id": str(goal.id), "title": "probe",
                                "tool_name": "httpx_probe", "target": "api.example.com"}]}

    rnd, res = await run_planner_round(s, run, propose, scope_ok=_in_scope,
                                       capability_ok=lambda t: True, known_tools=KNOWN, trigger="test")
    assert rnd.status == "completed" and rnd.round_no == 1 and res.created_intents == 1
    n = (await s.execute(select(func.count()).select_from(PlannerRound))).scalar_one()
    assert n == 1
