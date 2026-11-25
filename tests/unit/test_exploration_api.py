"""
Phase 6 tests — exploration engine views + operator actions + event contract.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from database.exploration_models import Goal, Intent
from database.models import ScanJob
from database.session import init_db, make_engine, make_session_factory
from exploration import actions, views
from exploration.events import FACT_CREATED, build_event
from exploration.store import ExplorationStore
from exploration.types import ApprovalState, ExplorationStatus, GoalState, IntentState


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
                                       success_criteria={"kind": "min_facts", "count": 1},
                                       state=GoalState.ACTIVE.value)
        intent = await store.create_intent(exploration_id=run.id, goal_id=goal.id, title="probe",
                                           tool_name="httpx_probe", target="api.example.com",
                                           state=IntentState.QUEUED.value,
                                           approval_state=ApprovalState.PENDING.value)
        await store.record_fact(exploration_id=run.id, goal_id=goal.id, intent_id=intent.id,
                                fact_type="http_service", title="200 /", asset="api.example.com")
        yield {"s": s, "store": store, "run": run, "goal": goal, "intent": intent, "sid": str(sid)}
    await engine.dispose()


# ── views ─────────────────────────────────────────────────────────────────────

async def test_resolve_and_lists(ctx):
    s, run, sid = ctx["s"], ctx["run"], ctx["sid"]
    assert (await views.resolve_run(s, scan_id=sid)).id == run.id
    assert len(await views.list_goals(s, run)) == 1
    assert len(await views.list_intents(s, run)) == 1
    facts = await views.list_facts(s, run)
    assert facts["total"] == 1 and len(facts["facts"]) == 1


async def test_engine_graph(ctx):
    s, store, run, goal, intent = ctx["s"], ctx["store"], ctx["run"], ctx["goal"], ctx["intent"]
    # Wire edges so the graph has structure.
    await store.add_edge(exploration_id=run.id, src_id=run.id, src_kind="objective",
                         dst_id=goal.id, dst_kind="goal", rel="spawns")
    await store.add_edge(exploration_id=run.id, src_id=goal.id, src_kind="goal",
                         dst_id=intent.id, dst_kind="intent", rel="plans")
    g = await views.build_engine_graph(s, run)
    kinds = {n["kind"] for n in g["nodes"]}
    assert {"objective", "goal", "intent", "fact"} <= kinds
    assert g["summary"]["goals"] == 1 and len(g["edges"]) == 2


async def test_get_node(ctx):
    s, run, goal = ctx["s"], ctx["run"], ctx["goal"]
    n = await views.get_node(s, run, str(goal.id))
    assert n and n["kind"] == "goal" and len(n["facts"]) == 1
    assert await views.get_node(s, run, str(uuid.uuid4())) is None


# ── actions ─────────────────────────────────────────────────────────────────────

async def test_pause_resume_stop(ctx):
    s, run = ctx["s"], ctx["run"]
    assert (await actions.pause(s, run))["status"] == ExplorationStatus.PAUSED.value
    assert (await actions.resume(s, run))["status"] == ExplorationStatus.RUNNING.value
    r = await actions.stop(s, run, "done")
    assert r["status"] == ExplorationStatus.STOPPED.value and run.stop_reason == "done"


async def test_intent_approval_actions(ctx):
    s, run, intent = ctx["s"], ctx["run"], ctx["intent"]
    r = await actions.approve_intent(s, run, str(intent.id))
    assert r["approval_state"] == ApprovalState.APPROVED.value
    it = (await s.execute(select(Intent).where(Intent.id == intent.id))).scalar_one()
    assert it.approval_state == ApprovalState.APPROVED.value

    r2 = await actions.reject_intent(s, run, str(intent.id), "no")
    assert r2["state"] == IntentState.REJECTED.value


async def test_goal_actions(ctx):
    s, run, goal = ctx["s"], ctx["run"], ctx["goal"]
    assert (await actions.prioritize_goal(s, run, str(goal.id), 1))["priority"] == 1
    r = await actions.block_goal(s, run, str(goal.id), "blocked by operator")
    assert r["state"] == GoalState.BLOCKED.value
    g = (await s.execute(select(Goal).where(Goal.id == goal.id))).scalar_one()
    assert g.state == GoalState.BLOCKED.value


async def test_action_unknown_id(ctx):
    s, run = ctx["s"], ctx["run"]
    assert (await actions.approve_intent(s, run, str(uuid.uuid4())))["ok"] is False
    assert (await actions.block_goal(s, run, str(uuid.uuid4())))["ok"] is False


# ── event contract ───────────────────────────────────────────────────────────────

def test_build_event():
    ev = build_event(FACT_CREATED, exploration_id="e1", scan_id="s1", node_id="n1", payload={"x": 1})
    assert ev["kind"] == "exploration" and ev["event"] == "fact.created" and ev["payload"]["x"] == 1
    with pytest.raises(ValueError):
        build_event("bogus.event", exploration_id="e1")
