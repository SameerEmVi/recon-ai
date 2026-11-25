"""
Phase 1 tests — exploration domain model + typed planner schemas.

Covers: tables create & persist via init_db, provenance/dedup constraints,
one-claim-per-intent, and the planner/decomposition schema guarantees (success
criteria required, discriminated operations, UUID validation, length caps).
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from database.exploration_models import (
    ExecutionClaim, ExplorationEdge, ExplorationRun, Fact, Goal, Intent,
)
from database.models import ScanJob
from database.session import init_db, make_engine, make_session_factory
from exploration.schemas import (
    CreateGoalOp, GoalDecomposition, PlannerDecision,
)
from exploration.types import EdgeRel, GoalState, IntentState, NodeKind


@pytest.fixture
async def session_factory(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'x.db'}")
    await init_db(engine)
    yield make_session_factory(engine)
    await engine.dispose()


async def _seed_run(s) -> ExplorationRun:
    sid = uuid.uuid4()
    s.add(ScanJob(id=sid, target_domain="example.com", mode="full", status="running"))
    run = ExplorationRun(scan_job_id=sid, title="Assess example.com", target="example.com",
                         constraints={"in_scope": ["*.example.com"], "mode": "full"})
    s.add(run)
    await s.commit()
    await s.refresh(run)
    return run


# ── model / persistence ─────────────────────────────────────────────────────────

async def test_full_graph_persists(session_factory):
    async with session_factory() as s:
        run = await _seed_run(s)
        goal = Goal(exploration_id=run.id, title="Discover in-scope subdomains",
                    success_criteria={"min_subdomains": 1}, state=GoalState.ACTIVE.value,
                    created_by="decomposer")
        s.add(goal); await s.commit(); await s.refresh(goal)

        intent = Intent(exploration_id=run.id, goal_id=goal.id, title="Enumerate subdomains",
                        tool_name="subfinder", target="example.com", dedup_key="subfinder:example.com",
                        state=IntentState.QUEUED.value)
        s.add(intent); await s.commit(); await s.refresh(intent)

        fact = Fact(exploration_id=run.id, goal_id=goal.id, intent_id=intent.id,
                    asset="api.example.com", fact_type="subdomain", title="api.example.com",
                    source="subfinder", dedup_key="subdomain:api.example.com")
        s.add(fact)
        s.add(ExplorationEdge(exploration_id=run.id, src_id=goal.id, src_kind=NodeKind.GOAL.value,
                              dst_id=intent.id, dst_kind=NodeKind.INTENT.value, rel=EdgeRel.PLANS.value))
        await s.commit()

        assert run.id and goal.exploration_id == run.id and intent.goal_id == goal.id
        assert fact.source_event_id is None  # provenance optional but column exists


async def test_fact_dedup_unique(session_factory):
    async with session_factory() as s:
        run = await _seed_run(s)
        s.add(Fact(exploration_id=run.id, fact_type="t", title="a", dedup_key="k"))
        await s.commit()
        s.add(Fact(exploration_id=run.id, fact_type="t", title="dup", dedup_key="k"))
        with pytest.raises(Exception):   # UniqueConstraint(exploration_id, dedup_key)
            await s.commit()


async def test_one_claim_per_intent(session_factory):
    async with session_factory() as s:
        run = await _seed_run(s)
        goal = Goal(exploration_id=run.id, title="g", success_criteria={})
        s.add(goal); await s.commit(); await s.refresh(goal)
        intent = Intent(exploration_id=run.id, goal_id=goal.id, title="i", tool_name="dnsx")
        s.add(intent); await s.commit(); await s.refresh(intent)

        s.add(ExecutionClaim(intent_id=intent.id, exploration_id=run.id, worker="w1", claim_token="t1"))
        await s.commit()
        s.add(ExecutionClaim(intent_id=intent.id, exploration_id=run.id, worker="w2", claim_token="t2"))
        with pytest.raises(Exception):   # UniqueConstraint(intent_id)
            await s.commit()


# ── decomposition schema ────────────────────────────────────────────────────────

def test_decomposition_requires_goals_and_criteria():
    d = GoalDecomposition(objective="Assess example.com", goals=[
        {"title": "Discover subdomains", "success_criteria": "≥1 in-scope subdomain recorded"},
    ])
    assert d.goals[0].success_criteria

    with pytest.raises(ValidationError):   # no goals
        GoalDecomposition(objective="x", goals=[])
    with pytest.raises(ValidationError):   # goal missing success_criteria
        GoalDecomposition(objective="x", goals=[{"title": "Run nmap"}])


def test_decomposition_nests_subgoals():
    d = GoalDecomposition(objective="o", goals=[{
        "title": "Identify technologies", "success_criteria": "tech linked to a service",
        "subgoals": [{"title": "Collect headers", "success_criteria": "headers recorded"}],
    }])
    assert d.goals[0].subgoals[0].title == "Collect headers"


# ── planner-operation schema ─────────────────────────────────────────────────────

def test_planner_decision_discriminates_operations():
    gid = str(uuid.uuid4())
    iid = str(uuid.uuid4())
    dec = PlannerDecision(reasoning="probe the new service", operations=[
        {"op": "create_goal", "title": "Fingerprint app", "success_criteria": "tech recorded"},
        {"op": "create_intent", "goal_id": gid, "title": "httpx probe", "tool_name": "httpx_probe", "target": "api.example.com"},
        {"op": "cancel_intent", "intent_id": iid},
        {"op": "continue"},
        {"op": "stop", "reason": "goals satisfied"},
    ])
    kinds = [type(o).__name__ for o in dec.operations]
    assert kinds[:2] == ["CreateGoalOp", "CreateIntentOp"]


def test_create_goal_requires_success_criteria():
    with pytest.raises(ValidationError):
        CreateGoalOp(title="Identify services")   # no success_criteria


def test_bad_uuid_rejected():
    with pytest.raises(ValidationError):
        PlannerDecision(operations=[{"op": "block_goal", "goal_id": "not-a-uuid", "reason": "x"}])


def test_string_caps_enforced():
    with pytest.raises(ValidationError):
        CreateGoalOp(title="x" * 5000, success_criteria="ok")
