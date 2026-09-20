"""
Fingerprint-tool integration tests — httpx tech-detect + WhatWeb normalization
into the TECHNOLOGY event model, with provenance, dedup, and scope enforcement.
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlparse

from events.dedup import derive_dedup_key
from events.types import EventType, HttpServiceData, TechnologyData
from modules.registry import FULL_MODULES, WEB_MODULES, ModuleRegistry
from normalize.parsers import parse_httpx_json, parse_whatweb_json
from scope.engine import ScopeEngine
from scope.types import Scope, ScopeStatus


# ── helpers ─────────────────────────────────────────────────────────────────

def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def _http_event(url="https://example.com/", server=None, title=None, technologies=None):
    ev = MagicMock()
    ev.type = EventType.HTTP_SERVICE
    ev.data = HttpServiceData(
        url=url, status_code=200, server=server, title=title,
        technologies=technologies or [],
    )
    ev.id = uuid.uuid4()
    ev.distance = 1
    return ev


def _techs(ctrl):
    return [
        c[0][0].data
        for c in ctrl.stamp_and_publish.call_args_list
        if c[0][0].type == EventType.TECHNOLOGY
    ]


class _ScopingController:
    def __init__(self, scope: Scope):
        self.scan_id = uuid.uuid4()
        self._engine = ScopeEngine(scope)
        self.accepted: list = []

    async def stamp_and_publish(self, event) -> bool:
        host = getattr(event.data, "host", "") or (
            urlparse(getattr(event.data, "url", "")).hostname or ""
        )
        d = self._engine.evaluate(host, source_distance=max(0, event.distance - 1))
        event.scope_status = d.status
        if d.status is ScopeStatus.IN:
            self.accepted.append(event)
            return True
        return False


# ── httpx tech-detect parsing ────────────────────────────────────────────────

def test_httpx_parser_captures_tech_array():
    line = json.dumps({
        "url": "https://example.com",
        "status_code": 200,
        "webserver": "nginx",
        "tech": ["Nginx:1.18.0", "PHP:7.4.3", "React"],
    })
    d = parse_httpx_json(line)
    assert d is not None
    assert d.technologies == ["Nginx:1.18.0", "PHP:7.4.3", "React"]


def test_httpx_parser_no_tech_is_empty_list():
    line = json.dumps({"url": "https://e.com", "status_code": 200})
    d = parse_httpx_json(line)
    assert d.technologies == []


# ── fingerprint normalizes httpx technologies → TECHNOLOGY ────────────────────

async def test_fingerprint_emits_from_httpx_technologies():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["fingerprint"], controller=ctrl)[0]
    await m.handle_event(_http_event(technologies=["Nginx:1.18.0", "PHP:7.4", "React"]))

    techs = {(t.name, t.version): t for t in _techs(ctrl)}
    assert ("Nginx", "1.18.0") in techs
    assert ("PHP", "7.4") in techs
    assert ("React", None) in techs
    # provenance + best-effort category
    assert techs[("Nginx", "1.18.0")].source == "httpx"
    assert techs[("Nginx", "1.18.0")].category == "server"
    assert techs[("React", None)].category == "framework"


async def test_fingerprint_heuristic_source_tagged():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["fingerprint"], controller=ctrl)[0]
    await m.handle_event(_http_event(server="Apache/2.4.52"))
    techs = _techs(ctrl)
    assert any(t.name == "Apache" and t.source == "heuristic" for t in techs)


async def test_fingerprint_dedups_httpx_and_heuristic_within_event():
    # nginx from both the httpx tech array and the Server-header heuristic must
    # collapse to a single emission (httpx wins, it runs first).
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["fingerprint"], controller=ctrl)[0]
    await m.handle_event(_http_event(server="nginx/1.18.0", technologies=["Nginx:1.18.0"]))

    nginx = [t for t in _techs(ctrl) if t.name.lower() == "nginx"]
    assert len(nginx) == 1
    assert nginx[0].source == "httpx"


# ── WhatWeb parsing ──────────────────────────────────────────────────────────

WHATWEB_FIXTURE = json.dumps([
    {
        "target": "https://example.com/",
        "http_status": 200,
        "plugins": {
            "nginx": {"version": ["1.18.0"]},
            "PHP": {"version": ["7.4.3"]},
            "X-Powered-By": {"string": ["PHP/7.4.3"]},
            "Country": {"string": ["UNITED STATES"]},
            "IP": {"string": ["93.184.216.34"]},
            "Title": {"string": ["Example Domain"]},
        },
    }
])


def test_whatweb_parser_extracts_and_filters():
    out = parse_whatweb_json(WHATWEB_FIXTURE)
    by_name = {t["name"]: t["version"] for t in out}
    assert by_name["nginx"] == "1.18.0"
    assert by_name["PHP"] == "7.4.3"
    # metadata plugins filtered out
    assert "Country" not in by_name
    assert "IP" not in by_name
    assert "Title" not in by_name


def test_whatweb_parser_handles_malformed():
    for junk in ["", "not json", "{", "[1,2,3]", json.dumps({"plugins": "bad"})]:
        assert isinstance(parse_whatweb_json(junk), list)


def test_whatweb_parser_ndjson():
    ndjson = "\n".join([
        json.dumps({"target": "https://a/", "plugins": {"Apache": {"version": ["2.4"]}}}),
        json.dumps({"target": "https://b/", "plugins": {"Express": {}}}),
    ])
    out = parse_whatweb_json(ndjson)
    names = {t["name"] for t in out}
    assert names == {"Apache", "Express"}


# ── WhatWeb module emission ──────────────────────────────────────────────────

async def test_whatweb_module_emits_technology_with_source():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["whatweb"], controller=ctrl)[0]
    m._run_whatweb = AsyncMock(return_value=WHATWEB_FIXTURE)

    await m.handle_event(_http_event(url="https://example.com/"))

    techs = _techs(ctrl)
    names = {t.name for t in techs}
    assert "nginx" in names and "PHP" in names
    assert all(t.source == "whatweb" for t in techs)
    assert all(t.host == "example.com" for t in techs)


async def test_whatweb_module_scope_enforced():
    # A tech on an out-of-scope host must be dropped by the gate.
    scope = Scope.from_strings(in_scope=["*.example.com", "example.com"], out_scope=[])
    ctrl = _ScopingController(scope)
    m = ModuleRegistry.load(names=["whatweb"], controller=ctrl)[0]
    m._run_whatweb = AsyncMock(
        return_value=json.dumps([{"target": "https://evil.com/",
                                  "plugins": {"nginx": {"version": ["1.0"]}}}])
    )
    ev = _http_event(url="https://evil.com/")
    await m.handle_event(ev)
    assert ctrl.accepted == []


# ── cross-tool dedup guarantee ───────────────────────────────────────────────

def test_dedup_key_ignores_source_so_tools_collapse():
    # Same tech from two different tools → identical dedup key (source excluded),
    # so the EventBus collapses them to one.
    a = TechnologyData(host="example.com", name="nginx", version="1.18.0", source="httpx")
    b = TechnologyData(host="example.com", name="nginx", version="1.18.0", source="whatweb")
    assert derive_dedup_key(EventType.TECHNOLOGY, a) == derive_dedup_key(EventType.TECHNOLOGY, b)


# ── registration ─────────────────────────────────────────────────────────────

def test_whatweb_registered():
    assert "whatweb" in WEB_MODULES
    assert "whatweb" in FULL_MODULES
    m = ModuleRegistry.load(names=["whatweb"], controller=_mock_controller())[0]
    assert m.name == "whatweb"
    assert m.watched_events == ["HTTP_SERVICE"]
    assert m.produced_events == ["TECHNOLOGY"]
    assert m.deps_binary == ["whatweb"]
