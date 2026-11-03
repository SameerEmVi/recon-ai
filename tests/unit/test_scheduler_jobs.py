"""
Tests for the hybrid scanning engine's job model + lifecycle (scheduler.jobs)
and its DB persistence (database.models.JobRecord + JobRepository).

DB tests use in-memory SQLite via aiosqlite — no PostgreSQL required.
"""

from __future__ import annotations

import uuid

import pytest

from database.models import JobRecord
from database.repository import JobRepository
from database.session import drop_db, init_db, make_engine, make_session_factory
from scheduler.jobs import InvalidTransition, Job, JobKind, JobState

DB_URL = "sqlite+aiosqlite://"


@pytest.fixture
async def session():
    engine = make_engine(DB_URL)
    await init_db(engine)
    factory = make_session_factory(engine)
    async with factory() as s:
        yield s
    await drop_db(engine)
    await engine.dispose()


# ── pure job model ─────────────────────────────────────────────────────────────

def test_target_job_defaults_and_dedup_key():
    j = Job(target="API.Example.com.", scan_id=uuid.uuid4())
    assert j.kind is JobKind.TARGET
    assert j.target == "api.example.com"              # normalized (lower, trailing dot)
    assert j.state is JobState.QUEUED
    assert j.dedup_key == "target:api.example.com"
    assert not j.is_terminal


def test_module_job_dedup_key_includes_module():
    j = Job(target="a.com", scan_id=uuid.uuid4(), kind=JobKind.MODULE, module="ffuf")
    assert j.dedup_key == "module:a.com:ffuf"


def test_module_job_requires_module_name():
    with pytest.raises(ValueError):
        Job(target="a.com", scan_id=uuid.uuid4(), kind=JobKind.MODULE)


def test_valid_lifecycle_transitions():
    j = Job(target="a.com", scan_id=uuid.uuid4())
    j.transition(JobState.VALIDATING)
    j.transition(JobState.RUNNING)
    j.transition(JobState.COMPLETED, result={"urls": 3})
    assert j.state is JobState.COMPLETED and j.is_terminal
    assert j.result == {"urls": 3}


def test_invalid_transition_raises():
    j = Job(target="a.com", scan_id=uuid.uuid4())
    with pytest.raises(InvalidTransition):
        j.transition(JobState.COMPLETED)             # QUEUED -> COMPLETED not allowed


def test_terminal_state_cannot_transition():
    j = Job(target="a.com", scan_id=uuid.uuid4())
    j.transition(JobState.OUT_OF_SCOPE)
    assert j.is_terminal
    with pytest.raises(InvalidTransition):
        j.transition(JobState.RUNNING)               # cannot resurrect an out-of-scope job


def test_same_state_is_idempotent_noop():
    j = Job(target="a.com", scan_id=uuid.uuid4())
    j.transition(JobState.RUNNING)
    before = j.updated_at
    j.transition(JobState.RUNNING, error="still going")   # no-op transition, fields may update
    assert j.state is JobState.RUNNING
    assert j.error == "still going"
    assert j.updated_at == before                    # state didn't change → timestamp unchanged


def test_pause_resume_cycle():
    j = Job(target="a.com", scan_id=uuid.uuid4())
    j.transition(JobState.RUNNING)
    j.transition(JobState.PAUSED)                    # e.g. target entered WAF cooldown
    j.transition(JobState.RUNNING)                   # resumed
    assert j.state is JobState.RUNNING


# ── DB persistence ───────────────────────────────────────────────────────────

async def test_jobrecord_roundtrip(session):
    scan = uuid.uuid4()
    repo = JobRepository(session)
    j = Job(target="a.com", scan_id=scan, priority=10)
    rec = await repo.upsert(JobRecord.from_job(j))
    assert rec.state == "QUEUED" and rec.dedup_key == "target:a.com"

    got = await repo.get(scan, "target:a.com")
    assert got is not None and got.priority == 10 and got.target == "a.com"


async def test_upsert_updates_existing_row_not_duplicate(session):
    scan = uuid.uuid4()
    repo = JobRepository(session)
    j = Job(target="a.com", scan_id=scan)
    await repo.upsert(JobRecord.from_job(j))
    j.transition(JobState.VALIDATING)
    j.transition(JobState.RUNNING)
    await repo.upsert(JobRecord.from_job(j))          # same (scan, dedup_key)

    rows = await repo.list_for_scan(scan)
    assert len(rows) == 1                             # one evolving row, not two
    assert rows[0].state == "RUNNING"


async def test_set_state_and_list_filter(session):
    scan = uuid.uuid4()
    repo = JobRepository(session)
    await repo.upsert(JobRecord.from_job(Job(target="a.com", scan_id=scan)))
    await repo.upsert(JobRecord.from_job(Job(target="b.com", scan_id=scan)))
    await repo.set_state(scan, "target:a.com", JobState.COMPLETED.value)

    completed = await repo.list_for_scan(scan, state="COMPLETED")
    queued = await repo.list_for_scan(scan, state="QUEUED")
    assert {r.target for r in completed} == {"a.com"}
    assert {r.target for r in queued} == {"b.com"}


async def test_persister_save_and_list_jobs(session):
    from database.persister import Persister
    scan = uuid.uuid4()
    p = Persister(session)
    job = Job(target="a.com", scan_id=scan, kind=JobKind.MODULE, module="httpx_probe")
    await p.save_job(job)
    jobs = await p.list_jobs(scan)
    assert len(jobs) == 1 and jobs[0].module == "httpx_probe"
