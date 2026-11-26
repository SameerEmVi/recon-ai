"""
Live-wiring tests — build a goal-driven exploration from a finished scan's real
data (deterministic, idempotent, graceful on an empty scan).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from database.exploration_models import ExplorationRun, Fact, Goal, Intent
from database.models import Finding, Host, ScanJob
from database.session import init_db, make_engine, make_session_factory
from exploration.bridge import build_from_scan
from exploration.types import GoalState


@pytest.fixture
async def sf(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'b.db'}")
    await init_db(engine)
    yield make_session_factory(engine)
    await engine.dispose()


async def _scan_with_data(s) -> uuid.UUID:
    sid = uuid.uuid4()
    s.add(ScanJob(id=sid, target_domain="example.com", mode="full", status="complete"))
    s.add(Host(scan_job_id=sid, hostname="api.example.com", ip_addresses=["1.2.3.4"],
               open_ports=[443], technologies=["nginx", "react"],
               services=[{"url": "https://api.example.com/", "status_code": 200, "title": "API"}]))
    s.add(Host(scan_job_id=sid, hostname="www.example.com", technologies=["nginx"],
               services=[{"url": "https://www.example.com/", "status_code": 200}]))
    s.add(Finding(scan_job_id=sid, host="api.example.com", title="CORS misconfiguration",
                  description="", category="cors", severity_hint="high"))
    await s.commit()
    return sid


async def test_build_from_scan_populates_and_evaluates(sf):
    async with sf() as s:
        sid = await _scan_with_data(s)
        run = await build_from_scan(s, scan_job_id=sid, target="example.com", mode="full")
        assert run is not None and run.target == "example.com"

        goals = (await s.execute(select(Goal).where(Goal.exploration_id == run.id))).scalars().all()
        assert len(goals) == 5
        facts = (await s.execute(select(Fact).where(Fact.exploration_id == run.id))).scalars().all()
        ftypes = {f.fact_type for f in facts}
        assert {"subdomain", "http_service", "technology", "finding"} <= ftypes

        # Evidence-backed goals satisfied by real facts.
        by_title = {g.title: g for g in goals}
        assert by_title["Discover in-scope subdomains"].state == GoalState.SATISFIED.value
        assert by_title["Identify live HTTP services"].state == GoalState.SATISFIED.value
        assert by_title["Identify technologies on discovered services"].state == GoalState.SATISFIED.value
        # Facts carry provenance (linked to an intent + goal).
        assert all(f.intent_id is not None and f.goal_id is not None for f in facts)


async def test_build_from_scan_is_idempotent(sf):
    async with sf() as s:
        sid = await _scan_with_data(s)
        assert await build_from_scan(s, scan_job_id=sid, target="example.com") is not None
        assert await build_from_scan(s, scan_job_id=sid, target="example.com") is None   # no-op
        # Exactly one exploration + one set of goals.
        assert (await s.execute(select(func.count()).select_from(ExplorationRun))).scalar_one() == 1
        assert (await s.execute(select(func.count()).select_from(Goal))).scalar_one() == 5


async def test_build_from_empty_scan(sf):
    async with sf() as s:
        sid = uuid.uuid4()
        s.add(ScanJob(id=sid, target_domain="blank.com", mode="osint", status="complete"))
        await s.commit()
        run = await build_from_scan(s, scan_job_id=sid, target="blank.com")
        assert run is not None
        # Goals exist but nothing is satisfied (no evidence), no intents/facts, no crash.
        goals = (await s.execute(select(Goal).where(Goal.exploration_id == run.id))).scalars().all()
        assert len(goals) == 5
        assert all(g.state != GoalState.SATISFIED.value for g in goals)
        assert (await s.execute(select(func.count()).select_from(Fact))).scalar_one() == 0
        assert (await s.execute(select(func.count()).select_from(Intent))).scalar_one() == 0
