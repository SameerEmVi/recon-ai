"""
Increment 6 — Asset Explorer tests.

Route auth + no-DB empty inventory, plus asset aggregation from a seeded temp
sqlite: per-host IPs/ports/tech/services (with the live flag), DNS records and
the subdomain inventory from the event stream.
"""

from __future__ import annotations

import uuid

import httpx

from api.app import create_app
from api.assets import build_assets
from api.config import Settings
from api.scans import ScanManager

TOKEN = "t"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


async def test_assets_requires_token_and_runs_without_db():
    app = create_app(Settings(token=TOKEN, db_url=None), ScanManager())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/assets")).status_code == 401
        r = await c.get("/api/assets", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["scan"] is None
    assert body["summary"]["hosts"] == 0
    assert body["hosts"] == [] and body["subdomains"] == [] and body["dns_records"] == []


async def _seed(url: str) -> uuid.UUID:
    from database.repository import EventRepository, HostRepository, ScanRepository
    from database.session import init_db, make_engine, make_session_factory
    from events.types import DnsRecordData, Event, EventType, SubdomainData
    from scope.types import ScopeStatus

    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        await ScanRepository(s).create(sid, "ex.com", {}, "A")
        hr = HostRepository(s)
        # A live host (has a service) ...
        await hr.ensure(sid, "www.ex.com")
        await hr.add_ip(sid, "www.ex.com", "1.2.3.4")
        await hr.add_port(sid, "www.ex.com", 443)
        await hr.add_technology(sid, "www.ex.com", "nginx")
        await hr.add_service(sid, "www.ex.com",
                             {"url": "https://www.ex.com", "status_code": 200, "title": "Home"})
        # ... and a dark host (resolved, no HTTP service).
        await hr.ensure(sid, "dark.ex.com")
        await hr.add_ip(sid, "dark.ex.com", "1.2.3.5")

        er = EventRepository(s)
        for hn in ("www.ex.com", "dark.ex.com", "api.ex.com"):
            e = Event.create(EventType.SUBDOMAIN, SubdomainData(hostname=hn, source="t"),
                             scan_job_id=sid, source_tool="subfinder")
            e.scope_status = ScopeStatus.IN
            await er.save(e)
        d = Event.create(EventType.DNS_RECORD,
                         DnsRecordData(hostname="www.ex.com", record_type="A", value="1.2.3.4"),
                         scan_job_id=sid, source_tool="dnsx")
        d.scope_status = ScopeStatus.IN
        await er.save(d)
    await engine.dispose()
    return sid


async def test_assets_aggregate_from_db(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'as.db').as_posix()}"
    sid = await _seed(url)

    out = await build_assets(ScanManager(), url, str(sid))
    assert out["scan"]["domain"] == "ex.com"

    sm = out["summary"]
    assert sm["hosts"] == 2 and sm["live_hosts"] == 1
    assert sm["ips"] == 2 and sm["open_ports"] == 1
    assert sm["subdomains"] == 3 and sm["dns_records"] == 1

    by_name = {h["hostname"]: h for h in out["hosts"]}
    assert by_name["www.ex.com"]["live"] is True
    assert by_name["www.ex.com"]["ports"] == [443]
    assert by_name["www.ex.com"]["services"][0]["status_code"] == 200
    assert by_name["dark.ex.com"]["live"] is False

    assert out["subdomains"] == ["api.ex.com", "dark.ex.com", "www.ex.com"]  # sorted
    assert out["dns_records"][0] == {"hostname": "www.ex.com", "record_type": "A", "value": "1.2.3.4"}
    assert any(t["name"] == "nginx" for t in out["technologies"])


async def test_assets_fall_back_to_latest_scan(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'as2.db').as_posix()}"
    sid = await _seed(url)
    # No scan_id → newest DB scan (exercises recent_all).
    out = await build_assets(ScanManager(), url)
    assert out["scan"]["scan_id"] == str(sid)
