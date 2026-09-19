"""
Triage tests — mock-based so no Anthropic API key is required.

Tests cover:
  - Prompt builders (pure functions, no I/O)
  - Assessor (mocked AsyncAnthropic client)
  - Triage.assess_scan (mocked Assessor, real DB via SQLite)
"""

from __future__ import annotations

import types
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai.assessor import Assessor
from ai.prompts.host import build_host_list_prompt, HOST_ASSESSMENT_TOOL
from ai.prompts.finding import build_finding_prompt, FINDING_ASSESSMENT_TOOL
from ai.triage import Triage, TriageReport
from database.models import AiAssessment, Finding, Host
from database.repository import (
    AiAssessmentRepository,
    FindingRepository,
    HostRepository,
    ScanRepository,
)
from database.session import drop_db, init_db, make_engine, make_session_factory

DB_URL = "sqlite+aiosqlite://"


@pytest.fixture
async def session():
    engine = make_engine(DB_URL)
    await init_db(engine)
    factory = make_session_factory(engine)
    async with factory() as s:
        yield s
    await drop_db(engine)
    await engine.dispose()


# ── prompt builders ───────────────────────────────────────────────────────────

def _make_host(hostname: str) -> Host:
    h = Host(
        scan_job_id=uuid.uuid4(),
        hostname=hostname,
        ip_addresses=["93.184.216.34"],
        open_ports=[80, 443],
        technologies=["nginx/1.24", "PHP/8.1"],
        services=[{"url": f"https://{hostname}/", "status_code": 200, "title": "Home"}],
    )
    h.id = uuid.uuid4()
    return h


def _make_finding(host: str) -> Finding:
    f = Finding(
        scan_job_id=uuid.uuid4(),
        host=host,
        title="Reflected XSS",
        description="param q reflects without encoding",
        category="xss",
        severity_hint="medium",
        evidence={"param": "q", "payload": "<script>"},
    )
    f.id = uuid.uuid4()
    return f


def test_build_host_list_prompt_includes_hostname():
    host = _make_host("api.example.com")
    prompt = build_host_list_prompt("example.com", [host])
    assert "api.example.com" in prompt
    assert "nginx/1.24" in prompt
    assert "443" in prompt


def test_build_host_list_prompt_caps_at_8_services():
    host = _make_host("api.example.com")
    host.services = [{"url": f"https://x.com/{i}", "status_code": 200} for i in range(20)]
    prompt = build_host_list_prompt("example.com", [host])
    # Should not include all 20 services in the prompt
    assert prompt.count("https://x.com/") <= 8


def test_build_finding_prompt_includes_fields():
    finding = _make_finding("api.example.com")
    prompt = build_finding_prompt(finding)
    assert "api.example.com" in prompt
    assert "Reflected XSS" in prompt
    assert "xss" in prompt
    assert "param" in prompt


def test_build_finding_prompt_caps_description():
    finding = _make_finding("api.example.com")
    finding.description = "A" * 600
    prompt = build_finding_prompt(finding)
    # Cap is 512 chars for description in the prompt builder
    assert "A" * 513 not in prompt


# ── Assessor (mocked client) ──────────────────────────────────────────────────

def _mock_tool_response(tool_name: str, input_dict: dict):
    """Build a fake anthropic.types.Message with a tool_use block."""
    block = MagicMock()
    block.type = "tool_use"
    block.name = tool_name
    block.input = input_dict

    response = MagicMock()
    response.content = [block]
    return response


async def test_assessor_returns_tool_input():
    client = MagicMock()
    client.messages.create = AsyncMock(return_value=_mock_tool_response(
        "record_host_assessments",
        {"assessments": [{"hostname": "api.example.com", "importance": "high"}]},
    ))
    assessor = Assessor(client, model="test-model")
    result = await assessor.call("some prompt", HOST_ASSESSMENT_TOOL)
    assert result["assessments"][0]["importance"] == "high"


async def test_assessor_returns_empty_on_api_error():
    import anthropic
    client = MagicMock()
    client.messages.create = AsyncMock(
        side_effect=anthropic.APIError("fail", request=MagicMock(), body=None)
    )
    assessor = Assessor(client, model="test-model")
    result = await assessor.call("some prompt", HOST_ASSESSMENT_TOOL)
    assert result == {}


async def test_assessor_returns_empty_when_no_tool_use_block():
    block = MagicMock()
    block.type = "text"   # not tool_use
    response = MagicMock()
    response.content = [block]
    client = MagicMock()
    client.messages.create = AsyncMock(return_value=response)
    assessor = Assessor(client, model="test-model")
    result = await assessor.call("prompt", HOST_ASSESSMENT_TOOL)
    assert result == {}


# ── Triage.assess_scan (mocked assessor, real SQLite DB) ──────────────────────

def _make_triage_with_mock(session, host_response: dict, finding_response: dict) -> Triage:
    """Build a Triage instance whose Assessor is mocked."""
    triage = Triage.__new__(Triage)
    triage._model = "test-model"
    triage._host_repo = HostRepository(session)
    triage._finding_repo = FindingRepository(session)
    triage._assessment_repo = AiAssessmentRepository(session)

    mock_assessor = MagicMock()
    async def fake_call(prompt, tool):
        if tool["name"] == HOST_ASSESSMENT_TOOL["name"]:
            return host_response
        return finding_response
    mock_assessor.call = fake_call
    triage._assessor = mock_assessor
    return triage


async def test_triage_assess_scan_saves_host_assessment(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "B")

    # Insert a host record
    host_repo = HostRepository(session)
    host = await host_repo.ensure(scan_id, "api.example.com")
    await host_repo.add_technology(scan_id, "api.example.com", "nginx/1.24")

    host_resp = {
        "assessments": [{
            "hostname": "api.example.com",
            "importance": "high",
            "environment": "prod",
            "attack_surface_notes": "Public API with admin redirect.",
            "interesting_indicators": ["admin panel", "nginx"]
        }]
    }
    triage = _make_triage_with_mock(session, host_resp, {})
    report = await triage.assess_scan(scan_id, "example.com")

    assert len(report.host_assessments) == 1
    ha = report.host_assessments[0]
    assert ha.importance == "high"
    assert ha.environment == "prod"
    assert ha.db_record is not None

    # Verify persisted to DB
    assessments = await AiAssessmentRepository(session).list_for_scan(scan_id)
    assert len(assessments) == 1
    assert assessments[0].target_type == "host"
    assert assessments[0].importance == "high"


async def test_triage_assess_scan_saves_finding_assessment(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "B")

    finding = Finding(
        scan_job_id=scan_id,
        host="api.example.com",
        title="Reflected XSS",
        description="param q reflects without encoding",
        category="xss",
        evidence={"param": "q"},
    )
    finding = await FindingRepository(session).save(finding)

    finding_resp = {
        "confirmed_interesting": True,
        "severity": "medium",
        "reasoning": "Reflected XSS in search could enable CSRF-based attacks.",
        "investigation_notes": "Check CSP headers, test in authenticated context.",
    }
    triage = _make_triage_with_mock(session, {"assessments": []}, finding_resp)
    report = await triage.assess_scan(scan_id, "example.com")

    assert len(report.finding_assessments) == 1
    fa = report.finding_assessments[0]
    assert fa.confirmed_interesting is True
    assert fa.severity == "medium"
    assert fa.db_record is not None


async def test_triage_host_not_in_llm_response_gets_default(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "B")
    await HostRepository(session).ensure(scan_id, "unknown.example.com")

    # LLM returns empty assessments list (didn't mention the host)
    triage = _make_triage_with_mock(session, {"assessments": []}, {})
    report = await triage.assess_scan(scan_id, "example.com")

    assert len(report.host_assessments) == 1
    assert report.host_assessments[0].importance == "low"
    assert "Not assessed" in report.host_assessments[0].attack_surface_notes


async def test_triage_sorted_by_importance(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "B")
    await HostRepository(session).ensure(scan_id, "low.example.com")
    await HostRepository(session).ensure(scan_id, "critical.example.com")

    host_resp = {
        "assessments": [
            {"hostname": "low.example.com", "importance": "low",
             "environment": "dev", "attack_surface_notes": "Dev env.", "interesting_indicators": []},
            {"hostname": "critical.example.com", "importance": "critical",
             "environment": "prod", "attack_surface_notes": "Admin panel.", "interesting_indicators": ["admin"]},
        ]
    }
    triage = _make_triage_with_mock(session, host_resp, {})
    report = await triage.assess_scan(scan_id, "example.com")

    assert report.host_assessments[0].importance == "critical"
    assert report.host_assessments[1].importance == "low"


async def test_triage_report_print_summary_contains_key_info(session):
    scan_id = uuid.uuid4()
    await ScanRepository(session).create(scan_id, "example.com", {}, "B")
    await HostRepository(session).ensure(scan_id, "api.example.com")

    host_resp = {
        "assessments": [{
            "hostname": "api.example.com",
            "importance": "high",
            "environment": "prod",
            "attack_surface_notes": "Interesting.",
            "interesting_indicators": ["phpinfo exposed"],
        }]
    }
    triage = _make_triage_with_mock(session, host_resp, {})
    report = await triage.assess_scan(scan_id, "example.com")
    summary = report.print_summary()

    assert "api.example.com" in summary
    assert "HIGH" in summary
    assert "prod" in summary
    assert "phpinfo exposed" in summary
