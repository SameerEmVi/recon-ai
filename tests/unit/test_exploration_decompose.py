"""
Phase 2 tests — typed store (dedup/provenance/edges) + goal decomposition.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from database.exploration_models import Activity, ExplorationEdge, Goal
from database.models import ScanJob
from database.session import init_db, make_engine, make_session_factory
from exploration.decompose import DECOMPOSE_TOOL, decompose, persist_decomposition
from exploration.store import ExplorationStore
from exploration.types import EdgeRel, NodeKind


@pytest.fixture
async def ctx(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'x.db'}")
    await init_db(engine)
    sf = make_session_factory(engine)
    async with sf() as s:
        sid = uuid.uuid4()
        s.add(ScanJob(id=sid, target_domain="example.com", mode="full", status="running"))
        store = ExplorationStore(s)
        run = await store.create_run(scan_job_id=sid, title="Assess example.com",
                                     target="example.com", constraints={"in_scope": ["*.example.com"]})
        yield {"s": s, "store": store, "run": run}
    await engine.dispose()


# ── store: dedup + edges ────────────────────────────────────────────────────────

async def test_fact_dedup_returns_existing(ctx):
    store, run = ctx["store"], ctx["run"]
    f1, c1 = await store.record_fact(exploration_id=run.id, fact_type="subdomain",
                                     title="api.example.com", asset="api.example.com", source="subfinder")
    f2, c2 = await store.record_fact(exploration_id=run.id, fact_type="subdomain",
                                     title="api.example.com", asset="api.example.com", source="subfinder")
    assert c1 is True and c2 is False
    assert f1.id == f2.id


async def test_edge_dedup(ctx):
    store, run, s = ctx["store"], ctx["run"], ctx["s"]
    a, b = uuid.uuid4(), uuid.uuid4()
    e1 = await store.add_edge(exploration_id=run.id, src_id=a, src_kind="goal", dst_id=b, dst_kind="intent", rel="plans")
    e2 = await store.add_edge(exploration_id=run.id, src_id=a, src_kind="goal", dst_id=b, dst_kind="intent", rel="plans")
    assert e1 is not None and e2 is None
    n = (await s.execute(select(func.count()).select_from(ExplorationEdge))).scalar_one()
    assert n == 1


async def test_intent_dedup_key_and_lookup(ctx):
    store, run = ctx["store"], ctx["run"]
    goal = await store.create_goal(exploration_id=run.id, title="g", success_criteria="c")
    it = await store.create_intent(exploration_id=run.id, goal_id=goal.id, title="probe",
                                   tool_name="httpx_probe", target="https://API.example.com/")
    assert it.dedup_key == "httpx_probe:https://api.example.com"
    found = await store.find_open_intent(run.id, "httpx_probe", "https://api.example.com/")
    assert found is not None and found.id == it.id


# ── decomposition ───────────────────────────────────────────────────────────────

def _fake(result: dict):
    async def propose(_prompt, _tool): return result
    return propose


async def test_decompose_validates_and_persists(ctx):
    store, run, s = ctx["store"], ctx["run"], ctx["s"]
    proposer = _fake({
        "objective": "Assess the authorized attack surface of example.com.",
        "goals": [
            {"title": "Discover in-scope subdomains", "success_criteria": "≥1 subdomain recorded", "priority": 2},
            {"title": "Identify technologies on discovered services",
             "success_criteria": "technology linked to a service",
             "subgoals": [{"title": "Collect response headers", "success_criteria": "headers recorded"}]},
        ],
    })
    decomp = await decompose("Assess example.com", "example.com", {"in_scope": ["*.example.com"]}, proposer)
    created = await persist_decomposition(store, run, decomp)

    assert len(created) == 3                              # 2 goals + 1 subgoal
    assert all(g.created_by == "decomposer" for g in created)
    assert all(g.success_criteria for g in created)

    # Objective→goal edges (2) + goal→subgoal edge (1) = 3; one is SPAWNS from the run id.
    edges = (await s.execute(select(ExplorationEdge).where(ExplorationEdge.exploration_id == run.id))).scalars().all()
    assert len(edges) == 3
    obj_edges = [e for e in edges if e.src_id == run.id and e.src_kind == NodeKind.OBJECTIVE.value]
    assert len(obj_edges) == 2 and all(e.rel == EdgeRel.SPAWNS.value for e in obj_edges)

    # A goal_created activity per goal.
    acts = (await s.execute(select(Activity).where(Activity.activity_type == "goal_created"))).scalars().all()
    assert len(acts) == 3

    # The subgoal links to its parent.
    sub = next(g for g in created if g.title == "Collect response headers")
    parent = next(g for g in created if g.title.startswith("Identify technologies"))
    assert sub.parent_goal_id == parent.id


async def test_decompose_rejects_goal_without_criteria(ctx):
    store, run = ctx["store"], ctx["run"]
    proposer = _fake({"objective": "x", "goals": [{"title": "Run nmap"}]})   # no success_criteria
    with pytest.raises(ValidationError):
        await decompose("x", "example.com", {}, proposer)


async def test_decompose_tool_schema_shape():
    assert DECOMPOSE_TOOL["name"] == "decompose_goals"
    assert "objective" in DECOMPOSE_TOOL["input_schema"]["properties"]
