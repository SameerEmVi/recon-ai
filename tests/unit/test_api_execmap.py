"""Unit tests for the tool-execution mindmap assembler (api/execmap.py)."""

from __future__ import annotations

import uuid

import pytest

from api.execmap import build_execmap
from database.models import EventRecord, ScanJob
from database.session import init_db, make_engine, make_session_factory


class _Mgr:
    def list(self):
        return []


def _ev(sid, etype, tool, host):
    return EventRecord(
        id=uuid.uuid4(), scan_job_id=sid, type=etype,
        data={"hostname": host}, scope_status="IN", distance=1,
        dedup_key=f"{etype}:{host}:{uuid.uuid4()}", source_tool=tool)


@pytest.fixture
async def db(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'e.db'}"
    engine = make_engine(url)
    await init_db(engine)
    sid = uuid.uuid4()
    async with make_session_factory(engine)() as s:
        s.add(ScanJob(id=sid, target_domain="example.com", mode="full", status="complete"))
        for e in [
            _ev(sid, "SUBDOMAIN", "subfinder", "a.example.com"),
            _ev(sid, "SUBDOMAIN", "subfinder", "b.example.com"),
            _ev(sid, "HTTP_SERVICE", "httpx", "a.example.com"),
            _ev(sid, "URL", "js_intel", "a.example.com"),
            _ev(sid, "URL", "js_intel", "a.example.com"),
        ]:
            s.add(e)
        await s.commit()
    await engine.dispose()
    return {"url": url, "scan_id": str(sid)}


async def test_execmap_tree_shape(db):
    out = await build_execmap(_Mgr(), db["url"], db["scan_id"])
    assert out["scan"]["domain"] == "example.com"
    assert out["summary"]["tools"] == 3                  # subfinder, httpx, js_intel
    assert out["summary"]["events"] == 5
    # root + 3 tools + event-type children
    kinds = [n["kind"] for n in out["nodes"]]
    assert kinds.count("scan") == 1
    assert kinds.count("tool") == 3
    assert kinds.count("etype") >= 3
    # Every edge connects existing nodes.
    ids = {n["id"] for n in out["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in out["edges"])


async def test_execmap_tool_counts_and_ranking(db):
    out = await build_execmap(_Mgr(), db["url"], db["scan_id"])
    by_tool = out["summary"]["by_tool"]
    assert by_tool["subfinder"] == 2
    assert by_tool["js_intel"] == 2
    assert by_tool["httpx"] == 1
    # js_intel's URL child carries the count.
    js_url = [n for n in out["nodes"] if n["id"] == "tool:js_intel:URL"][0]
    assert js_url["count"] == 2
    assert "×2" in js_url["label"]


async def test_execmap_no_db():
    out = await build_execmap(_Mgr(), None)
    assert out["scan"] is None and out["nodes"] == []
