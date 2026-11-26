"""Evidence-aware report (vulnscan/report.render_markdown + api/report) — §5."""

from __future__ import annotations

import uuid

import httpx
import pytest

from api.app import create_app
from api.config import Settings
from api.report import build_scan_report, render_report
from api.scans import ScanManager
from database.models import Finding, ScanJob
from database.repository import FindingRepository, HttpExchangeRepository
from database.session import init_db, make_engine, make_session_factory
from evidence import CapturedExchange, EvidenceCipher, build_exchange
from vulnscan.report import build_report, render_markdown

KEY = EvidenceCipher.generate_key()
TOKEN = "test-token-123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


# ── render_markdown shows the bound evidence ──────────────────────────────────────

def _result(**kw):
    from vulnscan.schema import VulnResult
    base = dict(asset="api.example.com", check_id="security-headers",
                check_name="Missing security headers", category="security-headers",
                status="OBSERVED", severity="low", confidence=0.9,
                detection_method="header-probe", evidence={"missing": "csp"},
                url="https://api.example.com/")
    base.update(kw)
    return VulnResult(**base)


def test_markdown_includes_per_finding_evidence():
    r = _result()
    ev = {r.dedup_key: [{
        "method": "GET", "status_code": 200, "url": "https://api.example.com/",
        "source_tool": "assess_url", "response_body": "<html>proof-of-bug</html>",
        "bodies_dropped": None,
    }]}
    report = build_report("example.com", [r], evidence=ev)
    md = render_markdown(report)
    assert "# Vulnerability Assessment — example.com" in md
    assert "Missing security headers" in md and "`LOW`" in md
    assert "**Evidence** (1 captured exchange(s))" in md
    assert "GET 200 https://api.example.com/" in md
    assert "proof-of-bug" in md                      # the captured body is quoted


def test_markdown_notes_when_body_unavailable():
    r = _result()
    ev = {r.dedup_key: [{
        "method": "GET", "status_code": 200, "url": "https://api.example.com/",
        "source_tool": "assess_url", "response_body": None,
        "bodies_dropped": "evidence key not configured",
    }]}
    md = render_markdown(build_report("example.com", [r], evidence=ev))
    assert "evidence key not configured" in md
    assert "Response body:" not in md                # no body fence when unavailable


def test_markdown_without_evidence_still_renders():
    md = render_markdown(build_report("example.com", [_result()]))
    assert "Missing security headers" in md
    assert "**Evidence**" not in md                  # falls back to structured evidence line


def test_html_report_escapes_captured_body():
    from vulnscan.report import render_html
    r = _result()
    # A captured body containing HTML must be escaped, never injected into the page.
    ev = {r.dedup_key: [{
        "method": "GET", "status_code": 200, "url": "https://api.example.com/",
        "source_tool": "assess_url",
        "response_body": "<script>alert('xss')</script><b>page</b>",
        "bodies_dropped": None,
    }]}
    h = render_html(build_report("example.com", [r], evidence=ev))
    assert h.startswith("<!doctype html>") and "Vulnerability Assessment" in h
    assert "Missing security headers" in h
    assert "<pre>" in h                               # evidence body block present
    assert "&lt;script&gt;alert(" in h                # escaped
    assert "<script>alert(" not in h                  # NOT injected


# ── DB round-trip: build_scan_report attaches real evidence ───────────────────────

@pytest.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setenv("RECON_AI_EVIDENCE_KEY", KEY)
    url = f"sqlite+aiosqlite:///{tmp_path / 'r.db'}"
    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        s.add(ScanJob(id=sid, target_domain="example.com", mode="pentest", status="complete"))
        await s.commit()
        finding = await FindingRepository(s).save(Finding(
            scan_job_id=sid, host="api.example.com",
            title="Missing security headers: https://api.example.com/",
            description="",
            category="vuln:security-headers", severity_hint="low",
            evidence={"check_id": "security-headers", "status": "OBSERVED",
                      "confidence": 0.9, "url": "https://api.example.com/"}))
        ex = await HttpExchangeRepository(s).save(build_exchange(
            CapturedExchange(host="api.example.com", method="GET",
                             url="https://api.example.com/", status_code=200,
                             response_body="<html>bound-proof</html>"),
            EvidenceCipher(KEY), scan_id=sid))
        await HttpExchangeRepository(s).link_to_finding(ex.id, finding.id)
    await engine.dispose()
    return {"url": url, "scan_id": str(sid)}


async def test_build_scan_report_attaches_evidence(db):
    report, scan = await build_scan_report(db["url"], db["scan_id"])
    assert report is not None and report["summary"]["total"] == 1
    md = render_report(report, "md")
    assert "bound-proof" in md and "GET 200 https://api.example.com/" in md


async def test_build_scan_report_missing_scan():
    report, scan = await build_scan_report("sqlite+aiosqlite://", str(uuid.uuid4()))
    assert report is None and scan is None


async def test_report_route_formats_and_auth(db):
    settings = Settings(token=TOKEN, db_url=db["url"])
    app = create_app(settings, ScanManager(db_url=db["url"]))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get(f"/api/report?scan_id={db['scan_id']}")).status_code == 401
        md = await client.get(f"/api/report?scan_id={db['scan_id']}&format=md", headers=AUTH)
        assert md.status_code == 200 and "bound-proof" in md.text
        assert md.headers["content-type"].startswith("text/markdown")
        bad = await client.get(f"/api/report?scan_id={db['scan_id']}&format=pdf", headers=AUTH)
        assert bad.status_code == 400
