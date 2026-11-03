"""
Increment 3 — dashboard overview tests.

Route auth + no-DB session stats, plus DB aggregation from a seeded temp sqlite
(which also exercises the new ScanRepository.recent_all / EventRepository.recent /
count_by_type read methods).
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from api.app import create_app
from api.config import Settings
from api.overview import build_overview
from api.scans import ScanEntry, ScanManager

TOKEN = "t"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


async def test_overview_requires_token_and_runs_without_db():
    app = create_app(Settings(token=TOKEN, db_url=None), ScanManager())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/overview")).status_code == 401
        r = await c.get("/api/overview", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["scans"]["total"] == 0
    assert body["assets"]["findings"] == 0 and body["scan"] is None


async def test_overview_counts_session_scans():
    mgr = ScanManager()
    mgr._entries["a"] = ScanEntry(scan_id="a", domain="x.com", mode="active", status="running")
    mgr._entries["b"] = ScanEntry(scan_id="b", domain="y.com", mode="osint", status="complete")
    mgr._entries["c"] = ScanEntry(scan_id="c", domain="z.com", mode="full", status="failed")
    out = await build_overview(mgr, None)
    assert out["scans"] == {"running": 1, "complete": 1, "failed": 1, "cancelled": 0, "total": 3}
    assert len(out["recent_scans"]) == 3


async def _seed(url: str) -> uuid.UUID:
    from database.models import Finding
    from database.repository import (
        EventRepository, FindingRepository, HostRepository, ScanRepository,
    )
    from database.session import init_db, make_engine, make_session_factory
    from events.types import Event, EventType, SubdomainData
    from scope.types import ScopeStatus

    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        await ScanRepository(s).create(sid, "ex.com", {}, "A")
        hr = HostRepository(s)
        await hr.ensure(sid, "ex.com")
        await hr.add_port(sid, "ex.com", 443)
        await hr.add_technology(sid, "ex.com", "nginx")
        await FindingRepository(s).save(Finding(
            scan_job_id=sid, host="ex.com", title="t", description="d",
            category="vuln:x", severity_hint="high",
        ))
        e = Event.create(EventType.SUBDOMAIN, SubdomainData(hostname="a.ex.com", source="t"),
                         scan_job_id=sid, source_tool="t")
        e.scope_status = ScopeStatus.IN
        await EventRepository(s).save(e)
    await engine.dispose()
    return sid


async def test_overview_aggregates_from_db(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'ov.db').as_posix()}"
    sid = await _seed(url)

    # Explicit scan_id.
    out = await build_overview(ScanManager(), url, str(sid))
    assert out["scan"]["domain"] == "ex.com"
    assert out["assets"]["open_ports"] == 1
    assert out["assets"]["subdomains"] == 1
    assert out["assets"]["findings"] == 1
    assert out["severity"] == {"high": 1}
    assert any(t["name"] == "nginx" for t in out["technologies"])
    assert any(e["type"] == "SUBDOMAIN" for e in out["recent_events"])

    # No scan_id → falls back to the latest DB scan (exercises recent_all).
    latest = await build_overview(ScanManager(), url)
    assert latest["scan"]["scan_id"] == str(sid)
