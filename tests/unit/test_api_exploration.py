"""Unit tests for the exploration-graph assembler (api/exploration.py)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from api.exploration import GOALS, _build, build_exploration, tier_of
from database.models import EventRecord, Finding, ScanJob
from database.session import init_db, make_engine, make_session_factory
from policy.policy import (
    CAP_FUZZING, CAP_INTRUSIVE_TEST, CAP_PASSIVE_EXTERNAL, CAP_TARGET_HTTP_REQUEST,
    CAP_VULNERABILITY_CHECK,
)


class _Mgr:
    def list(self):
        return []

    def get(self, scan_id):
        return None


NOW = datetime(2026, 1, 1, 12, 0, 0)


def _ev(etype, tool, host, *, parent=None, at=None, data=None):
    return SimpleNamespace(
        id=uuid.uuid4(), type=etype, source_tool=tool, source_event_id=parent,
        data=data or {"hostname": host}, created_at=at)


def _job(module, state="RUNNING", at=None):
    return SimpleNamespace(kind="module", module=module, state=state,
                           created_at=at, updated_at=at)


def _by_id(out):
    return {n["id"]: n for n in out["nodes"]}


# ── tiers: goals come from the central capability policy ───────────────────────

def test_tier_of_follows_capabilities():
    assert tier_of(frozenset({CAP_PASSIVE_EXTERNAL})) == "osint"
    assert tier_of(frozenset({CAP_FUZZING, CAP_TARGET_HTTP_REQUEST})) == "recon"
    assert tier_of(frozenset({CAP_VULNERABILITY_CHECK, CAP_TARGET_HTTP_REQUEST})) == "pentest"
    assert tier_of(frozenset({CAP_INTRUSIVE_TEST})) == "pentest"
    assert tier_of(None) == "recon"          # unclassified → discovery bucket


def test_build_shapes_start_goals_intents_facts():
    e1 = _ev("SUBDOMAIN", "subfinder", "a.example.com")              # seed (no parent)
    e2 = _ev("DNS_RECORD", "dnsx", "a.example.com", parent=e1.id)    # child of subfinder
    e3 = _ev("HTTP_SERVICE", "httpx", "a.example.com", parent=e2.id) # child of dnsx
    out = _build("example.com", "full", "running", [e1, e2, e3], [], [], now=NOW)

    kinds = [n["kind"] for n in out["nodes"]]
    assert kinds.count("start") == 1
    assert kinds.count("goal") == len(GOALS) == 3
    assert kinds.count("intent") == 3            # subfinder, dnsx, httpx_probe
    assert kinds.count("fact") == 3              # one event-type fact per tool
    assert out["summary"]["intents"] == 3
    assert out["summary"]["events"] == 3

    # The httpx wrapper's binary name is folded into its module.
    assert "intent:httpx_probe" in _by_id(out)
    # Every edge connects existing nodes.
    ids = set(_by_id(out))
    assert all(e["source"] in ids and e["target"] in ids for e in out["edges"])


def test_intents_sit_under_their_tier_goal():
    e1 = _ev("SUBDOMAIN", "subfinder", "a.example.com")
    e2 = _ev("HTTP_SERVICE", "httpx", "a.example.com", parent=e1.id)
    e3 = _ev("URL", "ffuf", "a.example.com", parent=e2.id)
    e4 = _ev("TECHNOLOGY", "nuclei", "a.example.com", parent=e2.id)
    out = _build("example.com", "full", "running", [e1, e2, e3, e4], [], [], now=NOW)

    spawns = {(e["source"], e["target"]) for e in out["edges"] if e["rel"] == "spawns"}
    assert ("goal:osint", "intent:subfinder") in spawns
    assert ("goal:recon", "intent:httpx_probe") in spawns
    assert ("goal:recon", "intent:ffuf") in spawns
    assert ("goal:pentest", "intent:nuclei") in spawns
    # Goals are processed in order, chained by `next`.
    nxt = [(e["source"], e["target"]) for e in out["edges"] if e["rel"] == "next"]
    assert nxt == [("goal:osint", "goal:recon"), ("goal:recon", "goal:pentest")]
    nodes = _by_id(out)
    assert [nodes[f"goal:{t}"]["priority"] for t in ("osint", "recon", "pentest")] == [9, 8, 7]


def test_build_intent_chain_from_lineage():
    e1 = _ev("SUBDOMAIN", "subfinder", "a.example.com")
    e2 = _ev("DNS_RECORD", "dnsx", "a.example.com", parent=e1.id)
    e3 = _ev("HTTP_SERVICE", "httpx", "a.example.com", parent=e2.id)
    out = _build("example.com", "full", "running", [e1, e2, e3], [], [], now=NOW)

    chains = {(e["source"], e["target"]) for e in out["edges"] if e["rel"] == "intent-chain"}
    assert ("intent:subfinder", "intent:dnsx") in chains
    assert ("intent:dnsx", "intent:httpx_probe") in chains
    nodes = _by_id(out)
    assert nodes["intent:dnsx"]["fed_by"] == ["subfinder"]
    assert nodes["intent:dnsx"]["feeds"] == ["httpx_probe"]


def test_osint_mode_locks_active_goals():
    e1 = _ev("SUBDOMAIN", "crt_sh", "a.example.com", at=NOW)
    out = _build("example.com", "osint", "running", [e1], [], [], now=NOW)
    nodes = _by_id(out)
    assert nodes["goal:osint"]["state"] == "running"
    assert nodes["goal:recon"]["state"] == "locked"
    assert nodes["goal:pentest"]["state"] == "locked"
    assert "osint" in nodes["goal:recon"]["reason"]


def test_intent_states_reflect_activity_and_completion():
    recent = _ev("SUBDOMAIN", "subfinder", "a.example.com", at=NOW - timedelta(seconds=10))
    stale = _ev("URL", "wayback", "a.example.com", at=NOW - timedelta(minutes=10))
    jobs = [_job("ffuf", "FAILED", at=NOW - timedelta(minutes=5))]
    running = _by_id(_build("example.com", "full", "running", [recent, stale], [], jobs,
                            planned=["katana"], now=NOW))
    assert running["intent:subfinder"]["state"] == "running"     # output in the last 90 s
    assert running["intent:wayback"]["state"] == "waiting"       # ran, then went quiet
    assert running["intent:ffuf"]["state"] == "failed"
    assert running["intent:katana"]["state"] == "pending"        # loaded, not yet fired
    assert running["goal:osint"]["state"] == "running"

    done = _by_id(_build("example.com", "full", "complete", [recent, stale], [], [], now=NOW))
    assert done["intent:subfinder"]["state"] == "done"
    assert done["goal:osint"]["state"] == "achieved"


def test_fact_cards_carry_samples_but_never_emails():
    evs = [_ev("SUBDOMAIN", "subfinder", h) for h in ("a.ex.com", "b.ex.com", "c.ex.com", "d.ex.com")]
    evs.append(_ev("EMAIL", "js_intel", "ex.com", data={"address": "ceo@ex.com"}))
    nodes = _by_id(_build("ex.com", "full", "running", evs, [], [], now=NOW))
    fact = nodes["fact:subfinder:SUBDOMAIN"]
    assert fact["label"] == "4 subdomains"
    assert fact["samples"] == ["a.ex.com", "b.ex.com", "c.ex.com"]
    email = nodes["fact:js_intel:EMAIL"]
    assert email["label"] == "1 email address"
    assert "samples" not in email and "ceo@ex.com" not in str(email)


def test_scope_node_constrains_allowed_goals_only():
    scope = {"in_scope": ["example.com", "*.example.com"], "out_scope": [], "max_distance": 5}
    out = _build("example.com", "osint", "running", [], [], [], scope=scope, now=NOW)
    nodes = _by_id(out)
    assert "*.example.com" in nodes["scope"]["summary"]
    constrains = {e["target"] for e in out["edges"] if e["rel"] == "constrains"}
    assert constrains == {"goal:osint"}


def test_build_vulnerability_attributed_to_proving_intent():
    e1 = _ev("HTTP_SERVICE", "httpx", "a.example.com")
    e2 = _ev("URL", "secretfinder", "a.example.com", parent=e1.id)
    finding = SimpleNamespace(
        id=uuid.uuid4(), title="Exposed API key", category="exposed-secret",
        severity_hint="high", host="a.example.com", source_event_id=e2.id,
        evidence={"status": "POTENTIAL", "confidence": 0.7})
    out = _build("example.com", "full", "complete", [e1, e2], [finding], [], now=NOW)

    vulns = [n for n in out["nodes"] if n["kind"] == "vulnerability"]
    assert len(vulns) == 1
    assert vulns[0]["label"] == "Exposed API key"
    assert vulns[0]["severity"] == "high"
    assert vulns[0]["verification"] == "POTENTIAL"
    proves = [e for e in out["edges"] if e["rel"] == "proves"]
    assert proves and proves[0]["source"] == "intent:secretfinder"
    assert proves[0]["target"] == vulns[0]["id"]


def test_unattributed_vulnerability_hangs_off_pentest_goal():
    finding = SimpleNamespace(id=uuid.uuid4(), title="x", category="c", severity_hint="low",
                              host="a.example.com", source_event_id=None, evidence=None)
    out = _build("example.com", "full", "complete", [], [finding], [], now=NOW)
    proves = [e for e in out["edges"] if e["rel"] == "proves"]
    assert proves[0]["source"] == "goal:pentest"


def test_build_finding_candidate_events_are_not_facts():
    e1 = _ev("FINDING_CANDIDATE", "vulnassess", "a.example.com")
    out = _build("example.com", "vuln", "complete", [e1], [], [], now=NOW)
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
        s.add(ScanJob(id=sid, target_domain="example.com", mode="full", status="running",
                      scope_config={"in_scope": ["*.example.com"], "out_scope": [],
                                    "max_distance": 5}))
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
    assert out["summary"]["goals"] == 3
    assert out["summary"]["vulnerabilities"] == 1
    chains = {(e["source"], e["target"]) for e in out["edges"] if e["rel"] == "intent-chain"}
    assert ("intent:subfinder", "intent:httpx_probe") in chains
    ids = {n["id"] for n in out["nodes"]}
    assert "scope" in ids
    assert all(e["source"] in ids and e["target"] in ids for e in out["edges"])


async def test_exploration_no_db():
    out = await build_exploration(_Mgr(), None)
    assert out["scan"] is None and out["nodes"] == []
