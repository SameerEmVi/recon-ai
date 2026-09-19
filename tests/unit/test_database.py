"""
Database model, repository, and diff tests.

Uses SQLite in-memory via aiosqlite — no PostgreSQL required.
JSONB is not used here (SQLite uses JSON text), but the logic is identical.
"""

from __future__ import annotations

import uuid

import pytest

from database.diff import ScanDiff, TypeDiff, compute_diff
from database.models import EventRecord, Finding, Host, ScanJob
from database.repository import (
    EventRepository,
    FindingRepository,
    HostRepository,
    ScanRepository,
)
from database.session import drop_db, init_db, make_engine, make_session_factory
from events.types import (
    Event,
    EventType,
    FindingCandidateData,
    HttpServiceData,
    IpData,
    SubdomainData,
)
from scope.types import ScopeStatus

DB_URL = "sqlite+aiosqlite://"   # in-memory, per test


@pytest.fixture
async def session():
    engine = make_engine(DB_URL)
    await init_db(engine)
    factory = make_session_factory(engine)
    async with factory() as s:
        yield s
    await drop_db(engine)
    await engine.dispose()


def _in_scope_subdomain(hostname: str, scan_id: uuid.UUID) -> Event:
    e = Event.create(
        EventType.SUBDOMAIN,
        SubdomainData(hostname=hostname, source="test"),
        scan_job_id=scan_id,
        source_tool="test",
    )
    e.scope_status = ScopeStatus.IN
    e.distance = 1
    return e


# ── ScanRepository ────────────────────────────────────────────────────────────

async def test_scan_create_and_retrieve(session):
    repo = ScanRepository(session)
    scan_id = uuid.uuid4()
    job = await repo.create(scan_id, "example.com", {"in_scope": ["*.example.com"]}, "A")
    assert job.id == scan_id
    assert job.status == "running"

    fetched = await repo.get(scan_id)
    assert fetched is not None
    assert fetched.target_domain == "example.com"


async def test_scan_complete(session):
    repo = ScanRepository(session)
    scan_id = uuid.uuid4()
    await repo.create(scan_id, "example.com", {}, "A")
    await repo.complete(scan_id, event_count=42)
    job = await repo.get(scan_id)
    assert job.status == "complete"
    assert job.event_count == 42
    assert job.completed_at is not None


async def test_scan_recent_ordered(session):
    repo = ScanRepository(session)
    for _ in range(3):
        sid = uuid.uuid4()
        await repo.create(sid, "example.com", {}, "A")
        await repo.complete(sid, 0)
    scans = await repo.recent("example.com", limit=10)
    assert len(scans) == 3


# ── EventRepository ───────────────────────────────────────────────────────────

async def test_event_save_and_dedup_keys(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "A")
    repo = EventRepository(session)

    e = _in_scope_subdomain("api.example.com", scan_id)
    assert await repo.save(e) is True

    keys = await repo.dedup_keys(scan_id, EventType.SUBDOMAIN)
    assert e.dedup_key in keys


async def test_event_save_duplicate_returns_false(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "A")
    repo = EventRepository(session)

    e1 = _in_scope_subdomain("api.example.com", scan_id)
    e2 = _in_scope_subdomain("api.example.com", scan_id)
    assert e1.dedup_key == e2.dedup_key

    assert await repo.save(e1) is True
    assert await repo.save(e2) is False   # duplicate


async def test_event_same_dedup_key_different_scans_both_saved(session):
    """Same subdomain in two different scans must both be saved."""
    scan_a = uuid.uuid4()
    scan_b = uuid.uuid4()
    await ScanRepository(session).create(scan_a, "example.com", {}, "A")
    await ScanRepository(session).create(scan_b, "example.com", {}, "A")
    repo = EventRepository(session)

    e_a = _in_scope_subdomain("api.example.com", scan_a)
    e_b = _in_scope_subdomain("api.example.com", scan_b)

    assert await repo.save(e_a) is True
    assert await repo.save(e_b) is True


# ── HostRepository ────────────────────────────────────────────────────────────

async def test_host_ensure_creates_once(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "A")
    repo = HostRepository(session)

    h1 = await repo.ensure(scan_id, "api.example.com")
    h2 = await repo.ensure(scan_id, "api.example.com")
    assert h1.id == h2.id


async def test_host_add_ip(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "A")
    repo = HostRepository(session)
    await repo.add_ip(scan_id, "api.example.com", "93.184.216.34")
    host = await repo.ensure(scan_id, "api.example.com")
    assert "93.184.216.34" in (host.ip_addresses or [])


async def test_host_add_port(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "A")
    repo = HostRepository(session)
    await repo.add_port(scan_id, "api.example.com", 443)
    host = await repo.ensure(scan_id, "api.example.com")
    assert 443 in (host.open_ports or [])


async def test_host_add_technology(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "A")
    repo = HostRepository(session)
    await repo.add_technology(scan_id, "api.example.com", "nginx/1.24")
    host = await repo.ensure(scan_id, "api.example.com")
    assert "nginx/1.24" in (host.technologies or [])


async def test_host_list_for_scan(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "A")
    repo = HostRepository(session)
    await repo.ensure(scan_id, "api.example.com")
    await repo.ensure(scan_id, "www.example.com")
    hosts = await repo.list_for_scan(scan_id)
    assert len(hosts) == 2


# ── FindingRepository ─────────────────────────────────────────────────────────

async def test_finding_from_event(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "A")
    repo = FindingRepository(session)

    e = Event.create(
        EventType.FINDING_CANDIDATE,
        FindingCandidateData(
            host="api.example.com",
            title="Reflected XSS",
            description="param q reflects unsanitized",
            category="xss",
            evidence={"param": "q", "payload": "<script>alert(1)</script>"},
        ),
        scan_job_id=scan_id,
        source_tool="test",
    )
    e.scope_status = ScopeStatus.IN

    finding = await repo.from_event(e)
    assert finding is not None
    assert finding.title == "Reflected XSS"
    assert finding.category == "xss"

    all_findings = await repo.list_for_scan(scan_id)
    assert len(all_findings) == 1


# ── ScanDiff ──────────────────────────────────────────────────────────────────

async def test_compute_diff_detects_new_subdomain(session):
    scan_a = uuid.uuid4()
    scan_b = uuid.uuid4()
    await ScanRepository(session).create(scan_a, "example.com", {}, "A")
    await ScanRepository(session).create(scan_b, "example.com", {}, "A")
    repo = EventRepository(session)

    await repo.save(_in_scope_subdomain("api.example.com", scan_a))
    await repo.save(_in_scope_subdomain("api.example.com", scan_b))
    await repo.save(_in_scope_subdomain("new.example.com", scan_b))

    diff = await compute_diff(repo, scan_a, scan_b, types=[EventType.SUBDOMAIN])
    td = diff.for_type(EventType.SUBDOMAIN)
    assert td is not None
    assert any("new.example.com" in k for k in td.new_keys)
    assert not td.gone_keys


async def test_compute_diff_detects_gone_subdomain(session):
    scan_a = uuid.uuid4()
    scan_b = uuid.uuid4()
    await ScanRepository(session).create(scan_a, "example.com", {}, "A")
    await ScanRepository(session).create(scan_b, "example.com", {}, "A")
    repo = EventRepository(session)

    await repo.save(_in_scope_subdomain("api.example.com", scan_a))
    await repo.save(_in_scope_subdomain("gone.example.com", scan_a))
    await repo.save(_in_scope_subdomain("api.example.com", scan_b))

    diff = await compute_diff(repo, scan_a, scan_b, types=[EventType.SUBDOMAIN])
    td = diff.for_type(EventType.SUBDOMAIN)
    assert any("gone.example.com" in k for k in td.gone_keys)


async def test_compute_diff_no_changes(session):
    scan_a = uuid.uuid4()
    scan_b = uuid.uuid4()
    await ScanRepository(session).create(scan_a, "example.com", {}, "A")
    await ScanRepository(session).create(scan_b, "example.com", {}, "A")
    repo = EventRepository(session)

    for sid in (scan_a, scan_b):
        await repo.save(_in_scope_subdomain("api.example.com", sid))

    diff = await compute_diff(repo, scan_a, scan_b, types=[EventType.SUBDOMAIN])
    assert not diff.has_changes


async def test_scan_diff_summary_format(session):
    scan_a = uuid.uuid4()
    scan_b = uuid.uuid4()
    await ScanRepository(session).create(scan_a, "example.com", {}, "A")
    await ScanRepository(session).create(scan_b, "example.com", {}, "A")
    repo = EventRepository(session)
    await repo.save(_in_scope_subdomain("new.example.com", scan_b))

    diff = await compute_diff(repo, scan_a, scan_b, types=[EventType.SUBDOMAIN])
    summary = diff.summary()
    assert "SUBDOMAIN" in summary
    assert "+1" in summary
