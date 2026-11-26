"""Evidence read API (api/evidence.py + route) — display view, key gating, auth."""

from __future__ import annotations

import uuid

import httpx
import pytest

from api.app import create_app
from api.config import Settings
from api.evidence import build_evidence, evidence_summary
from api.scans import ScanManager
from database.models import Finding, ScanJob
from database.repository import FindingRepository, HttpExchangeRepository
from database.session import init_db, make_engine, make_session_factory
from evidence import CapturedExchange, EvidenceCipher, build_exchange

KEY = EvidenceCipher.generate_key()
TOKEN = "test-token-123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
async def db(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'ev.db'}"
    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        s.add(ScanJob(id=sid, target_domain="example.com", mode="pentest", status="complete"))
        await s.commit()
        finding = await FindingRepository(s).save(Finding(
            scan_job_id=sid, host="api.example.com", title="Missing security headers",
            description="", category="vuln:security-headers", severity_hint="low"))
        repo = HttpExchangeRepository(s)
        linked = await repo.save(build_exchange(
            CapturedExchange(host="api.example.com", method="GET",
                             url="https://api.example.com/", status_code=200,
                             response_body="<html>proof</html>"),
            EvidenceCipher(KEY), scan_id=sid))
        await repo.link_to_finding(linked.id, finding.id)
        await repo.save(build_exchange(
            CapturedExchange(host="api.example.com", method="GET",
                             url="https://api.example.com/robots.txt", status_code=404),
            EvidenceCipher(KEY), scan_id=sid))
    await engine.dispose()
    return {"url": url, "scan_id": str(sid), "finding_id": str(finding.id)}


async def test_build_evidence_decrypts_when_server_has_key(db, monkeypatch):
    monkeypatch.setenv("RECON_AI_EVIDENCE_KEY", KEY)
    data = await build_evidence(db["url"], scan_id=db["scan_id"])
    assert data["count"] == 2 and data["key_available"] is True
    proof = next(e for e in data["exchanges"] if e["url"].endswith("/"))
    assert proof["response_body"] == "<html>proof</html>"       # decrypted for the operator
    assert proof["bodies_available"] is True
    assert proof["finding_id"] == db["finding_id"]              # bound to its finding


async def test_build_evidence_hides_bodies_without_key(db, monkeypatch):
    monkeypatch.delenv("RECON_AI_EVIDENCE_KEY", raising=False)
    data = await build_evidence(db["url"], scan_id=db["scan_id"])
    assert data["key_available"] is False
    for e in data["exchanges"]:
        assert e["response_body"] is None and e["bodies_available"] is False
        assert "proof" not in str(e)                            # never leaks the body


async def test_evidence_by_finding_and_summary(db, monkeypatch):
    monkeypatch.setenv("RECON_AI_EVIDENCE_KEY", KEY)
    one = await build_evidence(db["url"], finding_id=db["finding_id"])
    assert one["count"] == 1 and one["exchanges"][0]["finding_id"] == db["finding_id"]
    summary = await evidence_summary(db["url"], scan_id=db["scan_id"])
    assert summary == {"exchanges": 2, "linked_to_findings": 1, "key_available": True}


async def test_build_evidence_degrades_without_db():
    out = await build_evidence(None, scan_id="x")
    assert out == {"exchanges": [], "count": 0, "key_available": out["key_available"]}


async def test_evidence_route_requires_token(db):
    settings = Settings(token=TOKEN, db_url=db["url"])
    app = create_app(settings, ScanManager(db_url=db["url"]))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/api/evidence")).status_code == 401
        r = await client.get(f"/api/evidence?scan_id={db['scan_id']}", headers=AUTH)
        assert r.status_code == 200 and r.json()["count"] == 2
