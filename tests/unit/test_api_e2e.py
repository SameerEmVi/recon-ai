"""
Increment 10 — end-to-end GUI-stack test.

Drives the REAL stack: create_app → ScanManager.launch (real scope re-validation,
real background task, real live-monitor attach) → a scan that emits real Events
on a real EventBus and persists through the real repositories to a real (temp
sqlite) DB → the overview/assets/vulns readers read it back → the LiveHub carries
the event/stats/lifecycle frames a WebSocket client would receive, and a
reconnect (`since=`) replays only the tail → cancel stops a running scan.

Only the *scanner* is scripted (a controller injected via `controller_factory`)
so the test is offline and deterministic; every other component — routing, auth,
scope gate, scan manager, event bus, live monitor/hub, repositories and the three
read endpoints — is the production code path. The real ScanController engine was
live-validated separately (see docs/gui-architecture.md increment 5).
"""

from __future__ import annotations

import asyncio
import uuid

import httpx
import pytest

from api.app import create_app
from api.config import Settings
from api.scans import ScanManager

TOKEN = "e2e"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _Limiter:
    def stats(self) -> dict:
        return {"requests": 5, "penalty": 1.0, "waf_vendors": [],
                "targets_backed_off": [], "targets_in_cooldown": []}


async def _persist_and_emit(controller, db_url: str) -> None:
    """Write a small, realistic asset graph through the real repositories AND
    publish the matching events on the real bus (so the live monitor taps them)."""
    from database.repository import (
        EventRepository, FindingRepository, HostRepository, ScanRepository,
    )
    from database.models import Finding
    from database.session import init_db, make_engine, make_session_factory
    from events.types import (
        DnsRecordData, Event, EventType, FindingCandidateData, HttpServiceData,
        SubdomainData,
    )
    from scope.types import ScopeStatus

    sid = controller.scan_id

    def mk(etype, data):
        ev = Event.create(etype, data, scan_job_id=sid, source_tool="e2e")
        ev.scope_status = ScopeStatus.IN
        return ev

    events = [
        mk(EventType.SUBDOMAIN, SubdomainData(hostname="www.hackycorp.com", source="e2e")),
        mk(EventType.DNS_RECORD, DnsRecordData(hostname="www.hackycorp.com",
                                               record_type="A", value="203.0.113.10")),
        mk(EventType.HTTP_SERVICE, HttpServiceData(url="https://www.hackycorp.com",
                                                   status_code=200, title="Home")),
        mk(EventType.FINDING_CANDIDATE, FindingCandidateData(
            host="www.hackycorp.com", title="Security header missing: www.hackycorp.com",
            description="CSP absent.", category="vuln:security-headers", severity_hint="high",
            evidence={"status": "OBSERVED"})),
    ]

    engine = make_engine(db_url)
    await init_db(engine)
    async with make_session_factory(engine)() as s:
        await ScanRepository(s).create(sid, "hackycorp.com", {}, "osint")
        # Persist the events exactly as the real DB persister would (events table).
        er = EventRepository(s)
        for ev in events:
            await er.save(ev)
        hr = HostRepository(s)
        await hr.ensure(sid, "www.hackycorp.com")
        await hr.add_ip(sid, "www.hackycorp.com", "203.0.113.10")
        await hr.add_port(sid, "www.hackycorp.com", 443)
        await hr.add_technology(sid, "www.hackycorp.com", "nginx")
        await hr.add_service(sid, "www.hackycorp.com",
                             {"url": "https://www.hackycorp.com", "status_code": 200, "title": "Home"})
        await FindingRepository(s).save(Finding(
            scan_job_id=sid, host="www.hackycorp.com",
            title="Security header missing: www.hackycorp.com",
            description="[OBSERVED] CSP absent.", category="vuln:security-headers",
            severity_hint="high",
            evidence={"check_id": "security-headers", "status": "OBSERVED",
                      "confidence": 0.95, "confidence_label": "high",
                      "detection_method": "header-probe", "tier": "active"},
        ))
        await ScanRepository(s).complete(sid, len(events))
    await engine.dispose()

    # Publish the same discoveries on the bus for the live monitor (WS) tap.
    for ev in events:
        await controller.bus.publish(ev)
    await controller.bus.drain()


def _make_controller(kind: str, db_url: str):
    """A scripted controller exposing exactly the surface the manager/monitor use."""
    from events.bus import EventBus

    class _Controller:
        def __init__(self) -> None:
            self.scan_id = uuid.uuid4()
            self.bus = EventBus()
            self.rate_limiter = _Limiter()

        @property
        def live_pool_stats(self):
            return {"max_workers": 4, "running": 1, "queued": 0,
                    "terminal": {"COMPLETED": 1}}

        async def run(self, domain: str) -> None:
            if kind == "happy":
                await _persist_and_emit(self, db_url)
                await asyncio.sleep(0.08)        # let the 1 Hz stats sampler emit ≥1 frame
            else:                                 # "hang" — stays running until cancelled
                await asyncio.sleep(30)

    return _Controller()


def _app_with(kind: str, db_url: str):
    app = create_app(Settings(token=TOKEN, db_url=db_url))
    hub = app.state.hub
    app.state.scan_manager = ScanManager(
        db_url=db_url, hub=hub,
        controller_factory=lambda cfg, scope: _make_controller(kind, db_url),
    )
    return app


async def _wait_status(mgr, scan_id: str, target: str, timeout: float = 5.0) -> str:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        e = mgr.get(scan_id)
        if e and e.status == target:
            return e.status
        await asyncio.sleep(0.02)
    return mgr.get(scan_id).status if mgr.get(scan_id) else "missing"


async def test_e2e_scan_persists_streams_and_reads_back(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'e2e.db').as_posix()}"
    app = _app_with("happy", url)
    mgr = app.state.scan_manager
    hub = app.state.hub

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        # 1. Create the scan (real scope re-validation + real launch).
        r = await c.post("/api/scans", headers=AUTH, json={"domain": "hackycorp.com", "mode": "osint"})
        assert r.status_code in (200, 201), r.text
        scan_id = r.json()["scan_id"]

        # 2. It runs to completion.
        assert await _wait_status(mgr, scan_id, "complete") == "complete"

        # 3. Persistence reads back through every read endpoint.
        ov = (await c.get(f"/api/overview?scan_id={scan_id}", headers=AUTH)).json()
        assert ov["scan"]["domain"] == "hackycorp.com"
        assert ov["assets"]["subdomains"] >= 1 and ov["assets"]["findings"] == 1

        assets = (await c.get(f"/api/assets?scan_id={scan_id}", headers=AUTH)).json()
        host = next(h for h in assets["hosts"] if h["hostname"] == "www.hackycorp.com")
        assert host["live"] is True and host["ports"] == [443] and "nginx" in host["technologies"]
        assert "www.hackycorp.com" in assets["subdomains"]
        assert assets["dns_records"][0]["value"] == "203.0.113.10"

        vulns = (await c.get(f"/api/vulns?scan_id={scan_id}", headers=AUTH)).json()
        assert vulns["summary"]["by_severity"] == {"high": 1}
        assert vulns["findings"][0]["status"] == "OBSERVED"

    # 4. The LiveHub holds exactly what a WebSocket client would have received.
    frames = hub.replay(0, scan_id)
    kinds = {f["kind"] for f in frames}
    assert {"lifecycle", "event", "stats"} <= kinds
    lifecycles = [f["event"] for f in frames if f["kind"] == "lifecycle"]
    assert "scan_started" in lifecycles and "scan_complete" in lifecycles
    types = {f["type"] for f in frames if f["kind"] == "event"}
    assert {"SUBDOMAIN", "DNS_RECORD", "HTTP_SERVICE", "FINDING_CANDIDATE"} <= types

    # 5. Reconnect replay: since=<a mid seq> returns only newer frames, in order.
    mid = frames[len(frames) // 2]["seq"]
    tail = hub.replay(mid, scan_id)
    assert tail and all(f["seq"] > mid for f in tail)
    assert [f["seq"] for f in tail] == sorted(f["seq"] for f in tail)


async def test_e2e_cancel_stops_a_running_scan(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'e2e2.db').as_posix()}"
    app = _app_with("hang", url)
    mgr = app.state.scan_manager

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/scans", headers=AUTH, json={"domain": "hackycorp.com", "mode": "osint"})
        scan_id = r.json()["scan_id"]
        # Give the task a turn to actually start.
        for _ in range(20):
            if mgr.get(scan_id).status == "running":
                break
            await asyncio.sleep(0.02)
        assert mgr.get(scan_id).status == "running"

        cancel = await c.post(f"/api/scans/{scan_id}/cancel", headers=AUTH)
        assert cancel.status_code == 200
        assert await _wait_status(mgr, scan_id, "cancelled") == "cancelled"
        assert mgr.get(scan_id).task.done()


async def test_e2e_out_of_scope_rejected_before_launch(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'e2e3.db').as_posix()}"
    app = _app_with("happy", url)
    mgr = app.state.scan_manager

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        # in_scope restricted to a different domain → the seed is out of scope.
        r = await c.post("/api/scans", headers=AUTH, json={
            "domain": "evil.example", "mode": "osint", "in_scope": ["*.hackycorp.com", "hackycorp.com"]})
        assert r.status_code == 400
    # No task/entry was created.
    assert mgr.active_count == 0 and mgr.list() == []
