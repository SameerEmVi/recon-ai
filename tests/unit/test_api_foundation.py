"""
Increment 1 — web API foundation tests.

Drive the real FastAPI app in-process (httpx ASGITransport) with a FAKE
controller factory so no real scan runs. Covers: health, token auth required,
backend scope re-validation (out-of-scope seed rejected before any task),
create delegates to the engine, status, and cancel.
"""

from __future__ import annotations

import asyncio
import types
import uuid

import httpx
import pytest

from api.app import create_app
from api.config import Settings
from api.scans import ScanManager

TOKEN = "test-token-123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class FakeController:
    """Stands in for ScanController: never touches the network; run() blocks
    until released or cancelled so we can observe 'running' state."""
    def __init__(self) -> None:
        self.scan_id = uuid.uuid4()
        self.bus = types.SimpleNamespace(seen_count=7)
        self._release = asyncio.Event()
        self.ran = False

    async def run(self, domain: str) -> None:
        self.ran = True
        await self._release.wait()


def _make():
    created: list[FakeController] = []

    def factory(cfg, scope):
        c = FakeController()
        created.append(c)
        return c

    settings = Settings(token=TOKEN, db_url=None)
    mgr = ScanManager(db_url=None, controller_factory=factory)
    app = create_app(settings, mgr)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    return client, mgr, created


# ── health (unauthenticated) ────────────────────────────────────────────────────

async def test_health_ok_without_auth():
    client, mgr, _ = _make()
    async with client:
        r = await client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["db_configured"] is False


# ── auth ──────────────────────────────────────────────────────────────────────

async def test_scans_require_token():
    client, mgr, _ = _make()
    async with client:
        assert (await client.get("/api/scans")).status_code == 401           # no token
        assert (await client.get("/api/scans", headers={"Authorization": "Bearer nope"})
                ).status_code == 401                                          # wrong token
        assert (await client.get("/api/scans", headers=AUTH)).status_code == 200


# ── backend scope re-validation (fail-closed) ───────────────────────────────────

async def test_out_of_scope_seed_rejected_before_any_task():
    client, mgr, created = _make()
    async with client:
        r = await client.post("/api/scans", headers=AUTH, json={
            "domain": "example.com", "in_scope": ["*.other.com", "other.com"],
        })
    assert r.status_code == 400
    assert "not in scope" in r.json()["detail"]
    assert created == []                      # factory never called → no scan started


# ── create delegates + status + cancel ───────────────────────────────────────────

async def test_create_delegates_then_status_running():
    client, mgr, created = _make()
    async with client:
        r = await client.post("/api/scans", headers=AUTH, json={"domain": "example.com"})
        assert r.status_code == 201
        sid = r.json()["scan_id"]
        assert r.json()["status"] == "running"
        assert len(created) == 1                                   # delegated to the engine factory

        for _ in range(10):                                        # let the bg task reach run()
            if created[0].ran:
                break
            await asyncio.sleep(0)
        assert created[0].ran is True                              # the real engine object was run

        s = await client.get(f"/api/scans/{sid}", headers=AUTH)
        assert s.status_code == 200 and s.json()["status"] == "running"

        await mgr.shutdown()                                       # release/cancel the fake run


async def test_create_accepts_full_config():
    client, mgr, created = _make()
    async with client:
        r = await client.post("/api/scans", headers=AUTH, json={
            "domain": "example.com",
            "in_scope": ["*.example.com", "example.com"],
            "out_scope": ["admin.example.com"],
            "mode": "active",
            "modules": ["subfinder", "dnsx", "httpx_probe"],
            "rate_limit": 5, "max_concurrency": 20, "module_concurrency": 4,
            "hybrid": True, "workers": 15, "targets": ["www.example.com", "api.example.com"],
            "browser_profile": "chrome-windows", "proxy": None,
        })
    assert r.status_code == 201 and len(created) == 1
    await mgr.shutdown()


async def test_cancel_marks_cancelled():
    client, mgr, created = _make()
    async with client:
        sid = (await client.post("/api/scans", headers=AUTH, json={"domain": "example.com"})
               ).json()["scan_id"]
        r = await client.post(f"/api/scans/{sid}/cancel", headers=AUTH)
    assert r.status_code == 200 and r.json()["status"] == "cancelled"


async def test_status_404_for_unknown_scan():
    client, mgr, _ = _make()
    async with client:
        r = await client.get(f"/api/scans/{uuid.uuid4()}", headers=AUTH)
    assert r.status_code == 404


async def test_catalog_lists_modules_modes_profiles():
    client, mgr, _ = _make()
    async with client:
        assert (await client.get("/api/catalog")).status_code == 401      # token required
        r = await client.get("/api/catalog", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert set(body["modes"]) >= {"osint", "vuln", "active", "full"}
    assert len(body["modules"]) > 0 and "name" in body["modules"][0]
    assert any(p["name"] == "full" for p in body["profiles"])
