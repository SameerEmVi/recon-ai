"""
Live asset-graph tests.

Pure `graph_delta` coverage (one event → the nodes + edges it implies, deduped by
identity) + the `build_graph` assembler over a seeded temp sqlite, + route auth /
no-DB. The same `graph_delta` feeds the REST assembler and the live WS stream, so
testing it directly covers both.
"""

from __future__ import annotations

import uuid

import httpx

from api.app import create_app
from api.config import Settings
from api.graph import build_graph, graph_delta, merge_delta
from api.scans import ScanManager

TOKEN = "t"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


# ── graph_delta (pure) ────────────────────────────────────────────────────────

def _ids(items):
    return {i["id"] for i in items}


def test_subdomain_links_to_root():
    nodes, edges = graph_delta("subdomain", {"hostname": "api.ex.com"}, "ex.com")
    assert f"host:api.ex.com" in _ids(nodes)
    assert f"domain:ex.com" in _ids(nodes)
    assert any(e["source"] == "domain:ex.com" and e["target"] == "host:api.ex.com"
               and e["rel"] == "subdomain" for e in edges)


def test_subdomain_without_root_has_no_domain_edge():
    nodes, edges = graph_delta("subdomain", {"hostname": "api.ex.com"}, None)
    assert _ids(nodes) == {"host:api.ex.com"}
    assert edges == []


def test_ip_edge_from_resolved_from():
    nodes, edges = graph_delta("ip", {"address": "1.2.3.4", "resolved_from": "www.ex.com"}, "ex.com")
    assert "ip:1.2.3.4" in _ids(nodes) and "host:www.ex.com" in _ids(nodes)
    assert any(e["source"] == "host:www.ex.com" and e["target"] == "ip:1.2.3.4"
               and e["rel"] == "resolves" for e in edges)


def test_dns_cname_links_host_to_target():
    nodes, edges = graph_delta(
        "dns_record", {"hostname": "a.ex.com", "record_type": "CNAME", "value": "d.cloudfront.net"}, "ex.com")
    assert "host:d.cloudfront.net" in _ids(nodes)
    assert any(e["rel"] == "cname" for e in edges)


def test_http_service_node_carries_status_and_host_edge():
    nodes, edges = graph_delta(
        "http_service", {"url": "https://www.ex.com/", "status_code": 200, "title": "Home"}, "ex.com")
    svc = next(n for n in nodes if n["kind"] == "service")
    assert svc["status"] == 200 and svc["url"] == "https://www.ex.com/"
    assert any(e["source"] == "host:www.ex.com" and e["rel"] == "service" for e in edges)


def test_technology_node_deduped_by_name():
    n1, _ = graph_delta("technology", {"host": "a.ex.com", "name": "nginx", "version": "1.25"}, "ex.com")
    n2, _ = graph_delta("technology", {"host": "b.ex.com", "name": "nginx"}, "ex.com")
    tid = next(n["id"] for n in n1 if n["kind"] == "tech")
    assert tid == next(n["id"] for n in n2 if n["kind"] == "tech") == "tech:nginx"


def test_finding_node_and_edge():
    nodes, edges = graph_delta(
        "finding_candidate",
        {"host": "ex.com", "title": "Exposed admin", "category": "exposed-interface",
         "severity_hint": "medium"}, "ex.com")
    f = next(n for n in nodes if n["kind"] == "finding")
    assert f["severity"] == "medium" and f["label"] == "Exposed admin"
    assert any(e["rel"] == "finding" for e in edges)


def test_email_anchors_to_found_in_host():
    nodes, edges = graph_delta(
        "email", {"address": "ceo@ex.com", "found_in": "https://www.ex.com/team"}, "ex.com")
    assert "email:ceo@ex.com" in _ids(nodes)
    assert any(e["source"] == "host:www.ex.com" and e["rel"] == "email" for e in edges)


def test_unknown_event_is_empty():
    assert graph_delta("mystery", {"x": 1}, "ex.com") == ([], [])
    assert graph_delta("subdomain", {}, "ex.com") == ([], [])


def test_merge_delta_dedupes_and_enriches():
    acc = {"nodes": {}, "edges": {}}
    # host first appears as a bare edge endpoint (from an IP event) ...
    merge_delta(acc, *graph_delta("ip", {"address": "1.2.3.4", "resolved_from": "www.ex.com"}, "ex.com"))
    # ... then its own http_service enriches the SAME host-derived service node.
    merge_delta(acc, *graph_delta("http_service", {"url": "https://www.ex.com/", "status_code": 200}, "ex.com"))
    assert "host:www.ex.com" in acc["nodes"]           # one host node, not two
    assert sum(1 for n in acc["nodes"].values() if n["id"] == "host:www.ex.com") == 1
    # idempotent edge ids
    before = len(acc["edges"])
    merge_delta(acc, *graph_delta("ip", {"address": "1.2.3.4", "resolved_from": "www.ex.com"}, "ex.com"))
    assert len(acc["edges"]) == before


# ── build_graph (assembler) ───────────────────────────────────────────────────

async def _seed(url: str) -> uuid.UUID:
    from database.repository import EventRepository, ScanRepository
    from database.session import init_db, make_engine, make_session_factory
    from events.types import (
        DnsRecordData, Event, EventType, FindingCandidateData, HttpServiceData,
        IpData, SubdomainData, TechnologyData,
    )
    from scope.types import ScopeStatus

    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        await ScanRepository(s).create(sid, "ex.com", {}, "A")
        er = EventRepository(s)

        async def save(et, data):
            e = Event.create(et, data, scan_job_id=sid, source_tool="t")
            e.scope_status = ScopeStatus.IN
            await er.save(e)

        await save(EventType.SUBDOMAIN, SubdomainData(hostname="www.ex.com", source="t"))
        await save(EventType.IP, IpData(address="1.2.3.4", resolved_from="www.ex.com"))
        await save(EventType.DNS_RECORD,
                   DnsRecordData(hostname="www.ex.com", record_type="A", value="1.2.3.4"))
        await save(EventType.HTTP_SERVICE,
                   HttpServiceData(url="https://www.ex.com/", status_code=200, title="Home"))
        await save(EventType.TECHNOLOGY, TechnologyData(host="www.ex.com", name="nginx"))
        await save(EventType.FINDING_CANDIDATE,
                   FindingCandidateData(host="www.ex.com", title="Exposed admin",
                                        description="d", category="exposed-interface",
                                        evidence={}, severity_hint="medium"))
    await engine.dispose()
    return sid


async def test_build_graph_from_db(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'g.db').as_posix()}"
    sid = await _seed(url)

    out = await build_graph(ScanManager(), url, str(sid))
    assert out["scan"]["domain"] == "ex.com"

    ids = {n["id"] for n in out["nodes"]}
    assert {"domain:ex.com", "host:www.ex.com", "ip:1.2.3.4",
            "tech:nginx"}.issubset(ids)
    assert any(n["kind"] == "service" for n in out["nodes"])
    assert any(n["kind"] == "finding" for n in out["nodes"])

    # Every edge's endpoints exist as nodes (the cap-safety invariant).
    for e in out["edges"]:
        assert e["source"] in ids and e["target"] in ids

    assert out["summary"]["by_kind"]["host"] == 1       # one host, not duplicated
    assert out["truncated"] is False


async def test_build_graph_requires_db_and_route_auth():
    app = create_app(Settings(token=TOKEN, db_url=None), ScanManager())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/graph")).status_code == 401
        r = await c.get("/api/graph", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["scan"] is None and body["nodes"] == [] and body["edges"] == []


async def test_build_graph_falls_back_to_latest_scan(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'g2.db').as_posix()}"
    sid = await _seed(url)
    out = await build_graph(ScanManager(), url)      # no scan_id → newest
    assert out["scan"]["scan_id"] == str(sid)
