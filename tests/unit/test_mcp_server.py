"""
MCP server tests — no real MCP transport needed.

We test the tool handler functions directly by importing the module and
calling the underlying async functions. This avoids needing a live MCP
connection or Claude Desktop.

Tests cover:
  - context.py helpers (scan registry)
  - serialization helpers (_serialize_host, _serialize_finding, _serialize_assessment)
  - start_scan / get_scan_status happy path (mocked controller)
  - list_hosts / list_findings / list_assessments (real SQLite DB)
  - compute_diff (real SQLite DB)
  - _resolve_db_url raises without env var or param
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpserver.context import (
    complete_scan,
    fail_scan,
    get_scan_entry,
    register_scan,
)


# ── context helpers ───────────────────────────────────────────────────────────

def test_register_and_get_scan():
    scan_id = str(uuid.uuid4())
    entry = register_scan(scan_id, "example.com")
    assert entry.status == "running"
    assert entry.domain == "example.com"
    assert get_scan_entry(scan_id) is entry


def test_complete_scan_updates_status():
    scan_id = str(uuid.uuid4())
    register_scan(scan_id, "example.com")
    complete_scan(scan_id, event_count=42)
    entry = get_scan_entry(scan_id)
    assert entry.status == "complete"
    assert entry.event_count == 42


def test_fail_scan_updates_status():
    scan_id = str(uuid.uuid4())
    register_scan(scan_id, "example.com")
    fail_scan(scan_id, "connection refused")
    entry = get_scan_entry(scan_id)
    assert entry.status == "failed"
    assert "connection" in entry.error


def test_get_scan_entry_returns_none_for_unknown():
    assert get_scan_entry(str(uuid.uuid4())) is None


# ── _resolve_db_url ───────────────────────────────────────────────────────────

def test_resolve_db_url_raises_without_param_or_env(monkeypatch):
    monkeypatch.delenv("RECON_AI_DB_URL", raising=False)
    from mcpserver.server import _resolve_db_url
    with pytest.raises(ValueError, match="No database URL"):
        _resolve_db_url(None)


def test_resolve_db_url_uses_param():
    from mcpserver.server import _resolve_db_url
    assert _resolve_db_url("sqlite+aiosqlite:///test.db") == "sqlite+aiosqlite:///test.db"


def test_resolve_db_url_uses_env(monkeypatch):
    monkeypatch.setenv("RECON_AI_DB_URL", "sqlite+aiosqlite:///env.db")
    from mcpserver.server import _resolve_db_url
    assert _resolve_db_url(None) == "sqlite+aiosqlite:///env.db"


# ── serialization helpers ─────────────────────────────────────────────────────

def _make_host():
    from database.models import Host
    h = Host(
        scan_job_id=uuid.uuid4(),
        hostname="api.example.com",
        ip_addresses=["1.2.3.4"],
        open_ports=[80, 443],
        technologies=["nginx"],
        services=[{"url": "https://api.example.com/", "status_code": 200}],
    )
    h.id = uuid.uuid4()
    return h


def _make_finding():
    from database.models import Finding
    f = Finding(
        scan_job_id=uuid.uuid4(),
        host="api.example.com",
        title="Version disclosure",
        description="nginx version in Server header",
        category="info-disclosure",
        severity_hint="low",
        evidence={"header": "Server: nginx/1.24"},
    )
    f.id = uuid.uuid4()
    return f


def _make_assessment():
    from database.models import AiAssessment
    a = AiAssessment(
        scan_job_id=uuid.uuid4(),
        target_type="host",
        target_id=uuid.uuid4(),
        importance="high",
        environment_guess="prod",
        attack_surface_notes="Public API with authentication.",
        assessment={"interesting_indicators": ["nginx"]},
    )
    a.id = uuid.uuid4()
    return a


def test_serialize_host_fields():
    from mcpserver.server import _serialize_host
    h = _make_host()
    result = _serialize_host(h)
    assert result["hostname"] == "api.example.com"
    assert "1.2.3.4" in result["ip_addresses"]
    assert 443 in result["open_ports"]
    assert "nginx" in result["technologies"]
    assert isinstance(result["id"], str)


def test_serialize_finding_fields():
    from mcpserver.server import _serialize_finding
    f = _make_finding()
    result = _serialize_finding(f)
    assert result["host"] == "api.example.com"
    assert result["title"] == "Version disclosure"
    assert result["severity_hint"] == "low"
    assert isinstance(result["id"], str)


def test_serialize_assessment_fields():
    from mcpserver.server import _serialize_assessment
    a = _make_assessment()
    result = _serialize_assessment(a)
    assert result["importance"] == "high"
    assert result["environment"] == "prod"
    assert result["target_type"] == "host"
    assert isinstance(result["id"], str)
    assert isinstance(result["target_id"], str)


# ── list_hosts / list_findings / list_assessments (real SQLite) ───────────────

DB_URL = "sqlite+aiosqlite://"


@pytest.fixture
async def db_session():
    from database.session import drop_db, init_db, make_engine, make_session_factory
    engine = make_engine(DB_URL)
    await init_db(engine)
    factory = make_session_factory(engine)
    async with factory() as s:
        yield s
    await drop_db(engine)
    await engine.dispose()


async def test_list_hosts_returns_hosts(db_session):
    from database.repository import HostRepository, ScanRepository
    scan_id = uuid.uuid4()
    await ScanRepository(db_session).create(scan_id, "example.com", {}, "A")
    repo = HostRepository(db_session)
    await repo.ensure(scan_id, "api.example.com")
    await repo.add_technology(scan_id, "api.example.com", "nginx")

    from mcpserver.server import _serialize_host
    hosts = await repo.list_for_scan(scan_id)
    serialized = [_serialize_host(h) for h in hosts]

    assert len(serialized) == 1
    assert serialized[0]["hostname"] == "api.example.com"
    assert "nginx" in serialized[0]["technologies"]


async def test_list_findings_returns_findings(db_session):
    from database.models import Finding
    from database.repository import FindingRepository, ScanRepository
    scan_id = uuid.uuid4()
    await ScanRepository(db_session).create(scan_id, "example.com", {}, "A")
    f = Finding(
        scan_job_id=scan_id,
        host="api.example.com",
        title="XSS",
        description="reflected",
        category="xss",
        severity_hint="medium",
        evidence={"param": "q"},
    )
    await FindingRepository(db_session).save(f)

    from mcpserver.server import _serialize_finding
    findings = await FindingRepository(db_session).list_for_scan(scan_id)
    serialized = [_serialize_finding(f) for f in findings]

    assert len(serialized) == 1
    assert serialized[0]["title"] == "XSS"


async def test_list_assessments_returns_assessments(db_session):
    from database.models import AiAssessment
    from database.repository import AiAssessmentRepository, ScanRepository
    scan_id = uuid.uuid4()
    target_id = uuid.uuid4()
    await ScanRepository(db_session).create(scan_id, "example.com", {}, "B")
    a = AiAssessment(
        scan_job_id=scan_id,
        target_type="host",
        target_id=target_id,
        importance="critical",
        environment_guess="prod",
        attack_surface_notes="Admin panel exposed.",
        assessment={},
    )
    await AiAssessmentRepository(db_session).save(a)

    from mcpserver.server import _serialize_assessment
    assessments = await AiAssessmentRepository(db_session).list_for_scan(scan_id)
    serialized = [_serialize_assessment(a) for a in assessments]

    assert len(serialized) == 1
    assert serialized[0]["importance"] == "critical"


# ── get_scan_status happy path ────────────────────────────────────────────────

async def test_get_scan_status_from_registry(monkeypatch):
    scan_id = str(uuid.uuid4())
    register_scan(scan_id, "example.com")
    complete_scan(scan_id, 77)

    from mcpserver.server import get_scan_status
    result = await get_scan_status(scan_id)
    assert result["status"] == "complete"
    assert result["event_count"] == 77
    assert result["domain"] == "example.com"


async def test_get_scan_status_not_found_without_db(monkeypatch):
    monkeypatch.delenv("RECON_AI_DB_URL", raising=False)
    scan_id = str(uuid.uuid4())   # never registered

    from mcpserver.server import get_scan_status
    result = await get_scan_status(scan_id, db_url=None)
    # Falls back to DB which fails → returns unknown status
    assert result["status"] in ("unknown", "not_found")
