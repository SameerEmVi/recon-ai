"""Unit tests for the cross-task Findings assembler + triage store (api/findings.py)."""

from __future__ import annotations

import uuid

import pytest

from api.findings import build_findings, export_findings_csv, set_triage
from database.models import Finding, ScanJob
from database.session import init_db, make_engine, make_session_factory


@pytest.fixture
async def db(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'f.db'}"
    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    f1, f2 = uuid.uuid4(), uuid.uuid4()
    async with make_session_factory(engine)() as s:
        s.add(ScanJob(id=sid, target_domain="example.com", mode="full", status="complete"))
        s.add(Finding(id=f1, scan_job_id=sid, host="a.example.com",
                      title="Exposed secret: Google API Key", description="d",
                      category="exposed-secret", severity_hint="high",
                      evidence={"status": "POTENTIAL", "confidence": 0.8}))
        s.add(Finding(id=f2, scan_job_id=sid, host="b.example.com",
                      title="Security headers missing", description="d",
                      category="vuln:security-headers", severity_hint="low",
                      evidence={"status": "OBSERVED", "confidence": 0.5}))
        await s.commit()
    await engine.dispose()
    return {"url": url, "scan_id": str(sid), "f1": str(f1), "f2": str(f2)}


async def test_build_lists_all_and_tiles(db):
    out = await build_findings(db["url"])
    assert out["total"] == 2
    assert out["summary"]["by_severity"] == {"high": 1, "low": 1}
    assert out["summary"]["by_stage"] == {"pending": 2}       # default stage
    assert "exposed-secret" in out["facets"]["categories"]
    assert out["facets"]["tasks"][0]["domain"] == "example.com"


async def test_filters(db):
    assert (await build_findings(db["url"], severity="high"))["total"] == 1
    assert (await build_findings(db["url"], category="exposed-secret"))["total"] == 1
    assert (await build_findings(db["url"], status="POTENTIAL"))["total"] == 1
    assert (await build_findings(db["url"], host="b.example"))["total"] == 1
    assert (await build_findings(db["url"], q="header"))["total"] == 1
    assert (await build_findings(db["url"], scan_id=db["scan_id"]))["total"] == 2


async def test_triage_roundtrip_and_tile(db):
    r = await set_triage(db["url"], db["f1"], report_stage="submitted", note="sent")
    assert r["ok"] and r["report_stage"] == "submitted"
    out = await build_findings(db["url"], report_stage="submitted")
    assert out["total"] == 1
    assert out["findings"][0]["report_stage"] == "submitted"
    assert out["findings"][0]["note"] == "sent"
    # Tiles track the (unfiltered) stage distribution.
    full = await build_findings(db["url"])
    assert full["summary"]["by_stage"].get("submitted") == 1
    assert full["summary"]["by_stage"].get("pending") == 1


async def test_verification_override(db):
    await set_triage(db["url"], db["f2"], verification_override="CONFIRMED")
    out = await build_findings(db["url"], status="CONFIRMED")
    assert out["total"] == 1
    assert out["findings"][0]["verification_override"] == "CONFIRMED"
    assert out["findings"][0]["detected_status"] == "OBSERVED"   # engine value untouched


async def test_triage_rejects_bad_stage_and_ghost(db):
    assert (await set_triage(db["url"], db["f1"], report_stage="nonsense"))["ok"] is False
    assert (await set_triage(db["url"], str(uuid.uuid4()), report_stage="submitted"))["ok"] is False


async def test_export_csv(db):
    await set_triage(db["url"], db["f1"], report_stage="accepted")
    csv_text = await export_findings_csv(db["url"])
    assert "severity,title,host" in csv_text
    assert "Exposed secret: Google API Key" in csv_text
    assert "accepted" in csv_text
    assert len(csv_text.strip().splitlines()) == 3            # header + 2 rows


async def test_no_db_degrades():
    out = await build_findings(None)
    assert out["total"] == 0 and out["findings"] == []
    assert (await set_triage(None, str(uuid.uuid4())))["ok"] is False
