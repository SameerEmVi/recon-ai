"""Unit tests for the exploration-graph assembler (api/exploration.py)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from api.exploration import _build, build_exploration
from database.models import EventRecord, Finding, ScanJob
from database.session import init_db, make_engine, make_session_factory


class _Mgr:
    def list(self):
        return []


# ── pure _build (provenance → typed graph) ──────────────────────────────────────

def _ev(etype, tool, host, *, parent=None):
    return SimpleNamespace(
        id=uuid.uuid4(), type=etype, source_tool=tool,
        source_event_id=parent, data={"hostname": host})


def test_build_shapes_start_goal_intents_facts():
    e1 = _ev("SUBDOMAIN", "subfinder", "a.example.com")              # seed (no parent)
    e2 = _ev("DNS_RECORD", "dnsx", "a.example.com", parent=e1.id)    # child of subfinder
    e3 = _ev("HTTP_SERVICE", "httpx", "a.example.com", parent=e2.id) # child of dnsx
    out = _build("example.com", "full", "running", [e1, e2, e3], [], [])

    kinds = [n["kind"] for n in out["nodes"]]
    assert kinds.count("start") == 1
    assert kinds.count("goal") == 1
    assert kinds.count("intent") == 3            # subfinder, dnsx, httpx
    assert kinds.count("fact") == 3              # one event-type fact per tool
    assert out["summary"]["intents"] == 3
    assert out["summary"]["events"] == 3

    # Every edge connects existing nodes.
    ids = {n["id"] for n in out["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in out["edges"])


def test_build_intent_chain_from_lineage():
    e1 = _ev("SUBDOMAIN", "subfinder", "a.example.com")
    e2 = _ev("DNS_RECORD", "dnsx", "a.example.com", parent=e1.id)
    e3 = _ev("HTTP_SERVICE", "httpx", "a.example.com", parent=e2.id)
    out = _build("example.com", "full", "running", [e1, e2, e3], [], [])

    chains = {(e["source"], e["target"]) for e in out["edges"] if e["rel"] == "intent-chain"}
    assert ("intent:subfinder", "intent:dnsx") in chains
    assert ("intent:dnsx", "intent:httpx") in chains

    # The seed tool is spawned by the objective; reactive tools are not (reached
    # via the dataflow instead), so there is exactly one 'spawns' into an intent.
    spawns_into_intent = [e for e in out["edges"]
                          if e["rel"] == "spawns" and e["target"].startswith("intent:")]
    assert len(spawns_into_intent) == 1
    assert spawns_into_intent[0]["target"] == "intent:subfinder"


def test_build_vulnerability_attributed_to_proving_intent():
    e1 = _ev("HTTP_SERVICE", "httpx", "a.example.com")
    e2 = _ev("URL", "secretfinder", "a.example.com", parent=e1.id)
    finding = SimpleNamespace(
        id=uuid.uuid4(), title="Exposed API key", category="exposed-secret",
        severity_hint="high", host="a.example.com", source_event_id=e2.id)
    out = _build("example.com", "full", "complete", [e1, e2], [finding], [])

    vulns = [n for n in out["nodes"] if n["kind"] == "vulnerability"]
    assert len(vulns) == 1
    assert vulns[0]["label"] == "Exposed API key"
    assert vulns[0]["severity"] == "high"
    # 'proves' edge comes from the intent that produced the finding's source event.
    proves = [e for e in out["edges"] if e["rel"] == "proves"]
    assert proves and proves[0]["source"] == "intent:secretfinder"
    assert proves[0]["target"] == vulns[0]["id"]


def test_build_finding_candidate_events_are_not_facts():
    e1 = _ev("FINDING_CANDIDATE", "vulnassess", "a.example.com")
    out = _build("example.com", "vuln", "complete", [e1], [], [])
    facts = [n for n in out["nodes"] if n["kind"] == "fact"]
    assert facts == []          # finding_candidate is a vuln axis, never a fact node


# ── DB round-trip ───────────────────────────────────────────────────────────────

@pytest.fixture
async def db(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'e.db'}"
    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    e1 = uuid.uuid4()
    e2 = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        s.add(ScanJob(id=sid, target_domain="example.com", mode="full", status="running"))
        s.add(EventRecord(id=e1, scan_job_id=sid, type="SUBDOMAIN",
                          data={"hostname": "a.example.com"}, scope_status="IN", distance=1,
                          dedup_key=f"s:{e1}", source_tool="subfinder", source_event_id=None))
        s.add(EventRecord(id=e2, scan_job_id=sid, type="HTTP_SERVICE",
                          data={"url": "https://a.example.com/"}, scope_status="IN", distance=1,
                          dedup_key=f"h:{e2}", source_tool="httpx", source_event_id=e1))
        s.add(Finding(scan_job_id=sid, host="a.example.com", title="Missing HSTS",
                      description="", category="security-headers", severity_hint="low",
                      source_event_id=e2))
        await s.commit()
    await engine.dispose()
    return {"url": url, "scan_id": str(sid)}


async def test_exploration_db_roundtrip(db):
    out = await build_exploration(_Mgr(), db["url"], db["scan_id"])
    assert out["scan"]["domain"] == "example.com"
    assert out["summary"]["intents"] == 2
    assert out["summary"]["vulnerabilities"] == 1
    chains = {(e["source"], e["target"]) for e in out["edges"] if e["rel"] == "intent-chain"}
    assert ("intent:subfinder", "intent:httpx") in chains
    ids = {n["id"] for n in out["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in out["edges"])


async def test_exploration_no_db():
    out = await build_exploration(_Mgr(), None)
    assert out["scan"] is None and out["nodes"] == []
