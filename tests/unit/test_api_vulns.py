"""
Increment 7 — vulnerability-intelligence tests.

Route auth + no-DB empty payload, plus aggregation from a seeded temp sqlite:
severity/status/confidence rollups, strongest-first ordering, surfacing the
vulnscan evidence fields, and graceful handling of a non-vulnscan finding (no
status/confidence) alongside a structured one.
"""

from __future__ import annotations

import uuid

import httpx

from api.app import create_app
from api.config import Settings
from api.scans import ScanManager
from api.vulns import build_vulns

TOKEN = "t"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


async def test_vulns_requires_token_and_runs_without_db():
    app = create_app(Settings(token=TOKEN, db_url=None), ScanManager())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/vulns")).status_code == 401
        r = await c.get("/api/vulns", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["scan"] is None and body["summary"]["total"] == 0 and body["findings"] == []


async def _seed(url: str) -> uuid.UUID:
    from database.models import Finding
    from database.repository import FindingRepository, ScanRepository
    from database.session import init_db, make_engine, make_session_factory

    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        await ScanRepository(s).create(sid, "ex.com", {}, "A")
        fr = FindingRepository(s)
        # A structured vulnscan finding (medium, POTENTIAL) ...
        await fr.save(Finding(
            scan_job_id=sid, host="www.ex.com", title="jQuery known CVE: www.ex.com",
            description="[POTENTIAL] vulnerable library.", category="vuln:known-cve",
            severity_hint="medium",
            evidence={"check_id": "known-cve", "status": "POTENTIAL", "confidence": 0.6,
                      "confidence_label": "medium", "detection_method": "version-correlation",
                      "tier": "passive", "references": "CVE-2020-11022",
                      "remediation": "Upgrade jQuery.", "ev_version": "3.4.1"},
        ))
        # ... a high-severity one ...
        await fr.save(Finding(
            scan_job_id=sid, host="www.ex.com", title="Security header missing: www.ex.com",
            description="[OBSERVED] CSP absent.", category="vuln:security-headers",
            severity_hint="high",
            evidence={"check_id": "security-headers", "status": "OBSERVED", "confidence": 0.95,
                      "confidence_label": "high", "detection_method": "header-probe", "tier": "active"},
        ))
        # ... and a non-vulnscan finding with its own evidence shape (no status/confidence).
        await fr.save(Finding(
            scan_job_id=sid, host="api.ex.com", title="Exposed secret: api.ex.com",
            description="Redacted key.", category="exposed-secret", severity_hint="low",
            evidence={"redacted": "AKIA…", "http_status": 200},
        ))
    await engine.dispose()
    return sid


async def test_vulns_aggregate_and_order(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'v.db').as_posix()}"
    sid = await _seed(url)

    out = await build_vulns(ScanManager(), url, str(sid))
    assert out["scan"]["domain"] == "ex.com"

    sm = out["summary"]
    assert sm["total"] == 3
    assert sm["by_severity"] == {"high": 1, "medium": 1, "low": 1}
    assert sm["by_status"] == {"OBSERVED": 1, "POTENTIAL": 1}       # the secret has no status
    assert sm["by_confidence"] == {"high": 1, "medium": 1}

    rows = out["findings"]
    assert [r["severity"] for r in rows] == ["high", "medium", "low"]  # strongest first
    cve = next(r for r in rows if r["category"] == "vuln:known-cve")
    assert cve["status"] == "POTENTIAL" and cve["references"] == "CVE-2020-11022"
    assert cve["remediation"] == "Upgrade jQuery." and cve["extra"]["ev_version"] == "3.4.1"
    secret = next(r for r in rows if r["category"] == "exposed-secret")
    assert secret["status"] is None and secret["confidence"] is None
    assert secret["extra"]["redacted"] == "AKIA…"


async def test_vulns_fall_back_to_latest_scan(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'v2.db').as_posix()}"
    sid = await _seed(url)
    out = await build_vulns(ScanManager(), url)
    assert out["scan"]["scan_id"] == str(sid)
