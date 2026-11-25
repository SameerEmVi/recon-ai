"""
Phase 4 tests — intent execution: atomic claims, double-execution prevention,
expiry recovery, execution-time scope/capability/approval gates, fact provenance.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from database.exploration_models import ExecutionClaim, Fact, Intent
from database.models import ScanJob
from database.session import init_db, make_engine, make_session_factory
from exploration.execution import (
    ExecutionOutcome, FactOut, claim_next, execute_intent, recover_expired,
)
from exploration.store import ExplorationStore
from exploration.types import ApprovalState, IntentState


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
        goal = await store.create_goal(exploration_id=run.id, title="g", success_criteria="c")
        yield {"s": s, "store": store, "run": run, "goal": goal, "engine": engine, "sf": sf}
    await engine.dispose()


async def _queued(store, run, goal, tool="httpx_probe", target="api.example.com", **kw):
    it = await store.create_intent(exploration_id=run.id, goal_id=goal.id, title="t",
                                   tool_name=tool, target=target, state=IntentState.QUEUED.value, **kw)
    return it


def _ok_tool(facts):
    async def run_tool(_intent):
        return ExecutionOutcome(ok=True, summary="done", facts=facts)
    return run_tool


# ── claims ──────────────────────────────────────────────────────────────────────

async def test_claim_sets_running_and_creates_claim(ctx):
    s, store, run, goal = ctx["s"], ctx["store"], ctx["run"], ctx["goal"]
    await _queued(store, run, goal)
    claimed = await claim_next(s, run.id, "w1")
    assert claimed is not None
    it, claim = claimed
    assert it.state == IntentState.RUNNING.value and claim.worker == "w1"
    assert (await s.execute(select(func.count()).select_from(ExecutionClaim))).scalar_one() == 1


async def test_single_intent_claimed_once(ctx):
    # Two queued intents, two workers → each gets a distinct one; never the same twice.
    s, store, run, goal = ctx["s"], ctx["store"], ctx["run"], ctx["goal"]
    await _queued(store, run, goal, target="a.example.com")
    await _queued(store, run, goal, target="b.example.com")
    c1 = await claim_next(s, run.id, "w1")
    c2 = await claim_next(s, run.id, "w2")
    assert c1 and c2 and c1[0].id != c2[0].id
    c3 = await claim_next(s, run.id, "w3")
    assert c3 is None   # nothing left to claim


async def test_approval_pending_not_claimed(ctx):
    s, store, run, goal = ctx["s"], ctx["store"], ctx["run"], ctx["goal"]
    await _queued(store, run, goal, approval_state=ApprovalState.PENDING.value)
    assert await claim_next(s, run.id, "w1") is None


# ── execution ───────────────────────────────────────────────────────────────────

async def test_execute_records_facts_and_completes(ctx):
    s, store, run, goal = ctx["s"], ctx["store"], ctx["run"], ctx["goal"]
    await _queued(store, run, goal)
    it, _ = await claim_next(s, run.id, "w1")
    facts = [FactOut(fact_type="http_service", title="200 /", asset="api.example.com", content={"status": 200})]
    outcome = await execute_intent(s, run, it, run_tool=_ok_tool(facts),
                                   scope_ok=lambda t: True, capability_ok=lambda t: True)
    assert outcome.ok
    it2 = (await s.execute(select(Intent).where(Intent.id == it.id))).scalar_one()
    assert it2.state == IntentState.COMPLETED.value
    f = (await s.execute(select(Fact).where(Fact.exploration_id == run.id))).scalars().all()
    assert len(f) == 1 and f[0].intent_id == it.id and f[0].source == "httpx_probe"
    # claim released
    assert (await s.execute(select(func.count()).select_from(ExecutionClaim))).scalar_one() == 0


async def test_execution_rechecks_scope(ctx):
    s, store, run, goal = ctx["s"], ctx["store"], ctx["run"], ctx["goal"]
    await _queued(store, run, goal, target="api.example.com")
    it, _ = await claim_next(s, run.id, "w1")
    # Scope flips to deny at execution → rejected, no facts, claim released.
    outcome = await execute_intent(s, run, it, run_tool=_ok_tool([FactOut(fact_type="x", title="y")]),
                                   scope_ok=lambda t: False, capability_ok=lambda t: True)
    assert not outcome.ok
    it2 = (await s.execute(select(Intent).where(Intent.id == it.id))).scalar_one()
    assert it2.state == IntentState.REJECTED.value
    assert (await s.execute(select(func.count()).select_from(Fact))).scalar_one() == 0
    assert (await s.execute(select(func.count()).select_from(ExecutionClaim))).scalar_one() == 0


async def test_tool_error_fails_intent(ctx):
    s, store, run, goal = ctx["s"], ctx["store"], ctx["run"], ctx["goal"]
    await _queued(store, run, goal)
    it, _ = await claim_next(s, run.id, "w1")

    async def boom(_i): raise RuntimeError("tool crashed")
    outcome = await execute_intent(s, run, it, run_tool=boom, scope_ok=lambda t: True, capability_ok=lambda t: True)
    assert not outcome.ok
    it2 = (await s.execute(select(Intent).where(Intent.id == it.id))).scalar_one()
    assert it2.state == IntentState.FAILED.value and "tool crashed" in (it2.error or "")


# ── recovery ─────────────────────────────────────────────────────────────────────

async def test_recover_expired_requeues(ctx):
    s, store, run, goal = ctx["s"], ctx["store"], ctx["run"], ctx["goal"]
    await _queued(store, run, goal)
    it, claim = await claim_next(s, run.id, "w1")
    # Simulate a dead worker: expire the claim in the past.
    claim.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await s.commit()
    n = await recover_expired(s, run.id)
    assert n == 1
    it2 = (await s.execute(select(Intent).where(Intent.id == it.id))).scalar_one()
    assert it2.state == IntentState.QUEUED.value   # requeued for another worker
    assert (await s.execute(select(func.count()).select_from(ExecutionClaim))).scalar_one() == 0
    # And it can be claimed again.
    assert await claim_next(s, run.id, "w2") is not None
