"""
Phase 5 tests — deterministic goal completion: structured criteria, manual
criteria never auto-satisfy, parent-respects-children, reopen on lost evidence.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from database.exploration_models import Activity, Goal
from database.models import ScanJob
from database.session import init_db, make_engine, make_session_factory
from exploration.completion import evaluate_all, evaluate_goal
from exploration.store import ExplorationStore
from exploration.types import GoalState


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
        yield {"s": s, "store": store, "run": run}
    await engine.dispose()


async def test_min_facts_criteria(ctx):
    s, store, run = ctx["s"], ctx["store"], ctx["run"]
    goal = await store.create_goal(exploration_id=run.id, title="Identify services",
                                   success_criteria={"kind": "min_facts", "fact_type": "http_service", "count": 1},
                                   state=GoalState.ACTIVE.value)
    assert (await evaluate_goal(s, goal)).state == GoalState.ACTIVE.value   # no facts yet
    await store.record_fact(exploration_id=run.id, goal_id=goal.id, fact_type="http_service",
                            title="200 /", asset="api.example.com")
    assert (await evaluate_goal(s, goal)).state == GoalState.SATISFIED.value


async def test_manual_criteria_never_auto_satisfied(ctx):
    s, store, run = ctx["s"], ctx["store"], ctx["run"]
    goal = await store.create_goal(exploration_id=run.id, title="Assess weaknesses",
                                   success_criteria={"text": "operator confirms assessment"},
                                   state=GoalState.ACTIVE.value)
    await store.record_fact(exploration_id=run.id, goal_id=goal.id, fact_type="x", title="y")
    ev = await evaluate_goal(s, goal)
    assert ev.state == GoalState.PARTIAL.value   # has evidence but NOT auto-satisfied


async def test_parent_respects_children(ctx):
    s, store, run = ctx["s"], ctx["store"], ctx["run"]
    parent = await store.create_goal(exploration_id=run.id, title="Tech identified",
                                     success_criteria={"kind": "children"}, state=GoalState.ACTIVE.value)
    child = await store.create_goal(exploration_id=run.id, title="Collect headers",
                                    success_criteria={"kind": "fact_exists", "fact_type": "header"},
                                    parent_goal_id=parent.id, state=GoalState.ACTIVE.value)
    # Child not satisfied → parent not satisfied.
    res = await evaluate_all(s, run)
    p = (await s.execute(select(Goal).where(Goal.id == parent.id))).scalar_one()
    assert p.state != GoalState.SATISFIED.value
    # Satisfy the child's criterion → parent becomes satisfied.
    await store.record_fact(exploration_id=run.id, goal_id=child.id, fact_type="header", title="server: nginx")
    await evaluate_all(s, run)
    p = (await s.execute(select(Goal).where(Goal.id == parent.id))).scalar_one()
    c = (await s.execute(select(Goal).where(Goal.id == child.id))).scalar_one()
    assert c.state == GoalState.SATISFIED.value and p.state == GoalState.SATISFIED.value


async def test_reopen_on_lost_evidence(ctx):
    s, store, run = ctx["s"], ctx["store"], ctx["run"]
    # Goal needs 2 facts but was marked satisfied with only 1 → re-eval reopens it.
    goal = await store.create_goal(exploration_id=run.id, title="g",
                                   success_criteria={"kind": "min_facts", "fact_type": "url", "count": 2},
                                   state=GoalState.SATISFIED.value)
    await store.record_fact(exploration_id=run.id, goal_id=goal.id, fact_type="url", title="/a")
    res = await evaluate_all(s, run)
    assert res["reopened"] == 1
    g = (await s.execute(select(Goal).where(Goal.id == goal.id))).scalar_one()
    assert g.state != GoalState.SATISFIED.value
    acts = (await s.execute(select(Activity).where(Activity.activity_type == "goal_reopened"))).scalars().all()
    assert len(acts) == 1


async def test_blocked_goal_not_overridden(ctx):
    s, store, run = ctx["s"], ctx["store"], ctx["run"]
    goal = await store.create_goal(exploration_id=run.id, title="g",
                                   success_criteria={"kind": "fact_exists", "fact_type": "x"},
                                   state=GoalState.BLOCKED.value)
    await store.record_fact(exploration_id=run.id, goal_id=goal.id, fact_type="x", title="y")
    await evaluate_all(s, run)
    g = (await s.execute(select(Goal).where(Goal.id == goal.id))).scalar_one()
    assert g.state == GoalState.BLOCKED.value   # operator-terminal, not auto-satisfied
