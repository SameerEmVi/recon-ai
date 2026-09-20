"""
apifinder module tests — JavaScript & API endpoint discovery.

Covers (per the improvement spec):
  - JavaScript URL extraction
  - relative URL resolution
  - absolute URL extraction
  - API endpoint discovery / classification
  - parameter discovery
  - duplicate removal
  - scope enforcement (out-of-scope discoveries are dropped by the gate)
  - malformed JavaScript / input (never raises)
  - non-JavaScript responses (not fetched)
  - the acceptance-criteria fetch() fixture
  - registration / event wiring
"""

from __future__ import annotations

import types
import uuid
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlparse

from events.types import EventType, UrlData
from modules.registry import DISCOVERY_MODULES, FULL_MODULES, ModuleRegistry
from modules.web.apifinder import (
    classify_api_url,
    discover,
    params_from_url,
    resolve_ref,
    _is_fetchable,
)
from scope.engine import ScopeEngine
from scope.types import Scope, ScopeStatus

ACCEPTANCE_JS = """
fetch("/api/v1/users");
fetch("/api/v1/users?id=123");
fetch("https://example.com/graphql");
"""


# ── helpers ─────────────────────────────────────────────────────────────────

def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def _source_event(url: str, etype=EventType.URL):
    ev = types.SimpleNamespace()
    ev.id = uuid.uuid4()
    ev.distance = 1
    ev.type = etype
    ev.data = UrlData(url=url)
    return ev


class _ScopingController:
    """Minimal controller that enforces scope exactly like the real one:
    host is derived from the event's URL and run through the ScopeEngine."""

    def __init__(self, scope: Scope):
        self.scan_id = uuid.uuid4()
        self._engine = ScopeEngine(scope)
        self.accepted: list = []

    async def stamp_and_publish(self, event) -> bool:
        host = urlparse(getattr(event.data, "url", "")).hostname or getattr(
            event.data, "host", ""
        )
        decision = self._engine.evaluate(host, source_distance=max(0, event.distance - 1))
        event.scope_status = decision.status
        if decision.status is ScopeStatus.IN:
            self.accepted.append(event)
            return True
        return False


def _emitted(ctrl, etype):
    return [
        c[0][0].data
        for c in ctrl.stamp_and_publish.call_args_list
        if c[0][0].type == etype
    ]


# ── pure extraction: JS URL extraction ───────────────────────────────────────

def test_extracts_js_referenced_urls():
    urls = discover(ACCEPTANCE_JS, "https://example.com/app.js")
    assert "https://example.com/api/v1/users" in urls
    assert "https://example.com/api/v1/users?id=123" in urls
    assert "https://example.com/graphql" in urls


def test_absolute_url_extraction():
    js = 'var a = "https://api.example.com/v2/items"; b("http://cdn.example.com/x/y");'
    urls = discover(js, "https://example.com/")
    assert "https://api.example.com/v2/items" in urls
    assert "http://cdn.example.com/x/y" in urls


# ── relative URL resolution ──────────────────────────────────────────────────

def test_relative_url_resolution():
    base = "https://example.com/dir/page"
    assert resolve_ref("/api/v1", base) == "https://example.com/api/v1"
    assert resolve_ref("sub/thing", base) == "https://example.com/dir/sub/thing"
    assert resolve_ref("//cdn.example.com/lib.js", base) == "https://cdn.example.com/lib.js"
    assert resolve_ref("https://other.com/x", base) == "https://other.com/x"


def test_resolve_ref_rejects_non_http_and_hostless():
    assert resolve_ref("mailto:a@b.com", "https://example.com/") is None
    assert resolve_ref("javascript:alert(1)", "https://example.com/") is None


def test_relative_paths_extracted_and_resolved_from_content():
    js = 'axios.get("api/v2/orders"); load("/settings/profile");'
    urls = discover(js, "https://example.com/app/")
    assert "https://example.com/app/api/v2/orders" in urls
    assert "https://example.com/settings/profile" in urls


# ── API endpoint discovery / classification ──────────────────────────────────

def test_classify_api_url():
    assert classify_api_url("https://e.com/api/") == "api"
    assert classify_api_url("https://e.com/api/v1/users") == "api-version"
    assert classify_api_url("https://e.com/api/v2/users") == "api-version"
    assert classify_api_url("https://e.com/graphql") == "graphql"
    assert classify_api_url("https://e.com/graphiql") == "graphql"
    assert classify_api_url("https://e.com/swagger.json") == "swagger"
    assert classify_api_url("https://e.com/openapi.json") == "openapi"
    assert classify_api_url("https://e.com/v2/api-docs") == "api-docs"
    assert classify_api_url("https://e.com/home") is None
    assert classify_api_url("https://e.com/about/team") is None


# ── parameter discovery ──────────────────────────────────────────────────────

def test_param_discovery():
    params = params_from_url("https://e.com/api/v1/users?id=123&q=test&flag=")
    assert params == [("id", "123"), ("q", "test"), ("flag", "")]


def test_param_discovery_none_when_no_query():
    assert params_from_url("https://e.com/api/v1/users") == []


# ── duplicate removal ────────────────────────────────────────────────────────

def test_dedup_removes_duplicate_urls():
    js = 'fetch("/api/v1/users"); fetch("/api/v1/users"); x("/api/v1/users");'
    urls = discover(js, "https://example.com/")
    assert urls.count("https://example.com/api/v1/users") == 1


# ── malformed / non-JS input ─────────────────────────────────────────────────

def test_malformed_js_does_not_raise():
    for junk in ["", "}{ fetch( '' ", "\x00\x01 garbage ", 'fetch("', "//"]:
        assert isinstance(discover(junk, "https://example.com/"), list)


def test_mime_types_and_static_assets_skipped():
    js = 'type="text/html"; img="/logo.png"; css="/a/style.css"; ok="/api/v1/x";'
    urls = discover(js, "https://example.com/")
    assert "https://example.com/api/v1/x" in urls
    assert not any(u.endswith(("text/html", "/logo.png", "/a/style.css")) for u in urls)


def test_non_javascript_responses_not_fetchable():
    assert _is_fetchable("https://e.com/logo.png", "image/png") is False
    assert _is_fetchable("https://e.com/style.css", "text/css") is False
    assert _is_fetchable("https://e.com/app.js", None) is True
    assert _is_fetchable("https://e.com/data.json", None) is True
    assert _is_fetchable("https://e.com/", None) is True
    assert _is_fetchable("https://e.com/page", "text/html") is True


# ── emission: discoveries become the right event types ───────────────────────

async def test_emits_url_endpoint_param_technology():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["apifinder"], controller=ctrl)[0]
    src = _source_event("https://example.com/app.js")

    await m._process_text(ACCEPTANCE_JS, "https://example.com/app.js", src)

    urls = {u.url for u in _emitted(ctrl, EventType.URL)}
    assert "https://example.com/api/v1/users" in urls
    assert "https://example.com/api/v1/users?id=123" in urls
    assert "https://example.com/graphql" in urls

    endpoints = {e.url for e in _emitted(ctrl, EventType.ENDPOINT)}
    assert "https://example.com/api/v1/users" in endpoints
    assert "https://example.com/graphql" in endpoints

    params = _emitted(ctrl, EventType.PARAMETER)
    assert any(p.name == "id" and p.sample_value == "123" for p in params)

    techs = {t.name for t in _emitted(ctrl, EventType.TECHNOLOGY)}
    assert "GraphQL" in techs


async def test_provenance_preserved_on_emitted_events():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["apifinder"], controller=ctrl)[0]
    src = _source_event("https://example.com/app.js")

    await m._process_text('fetch("/api/v1/users");', "https://example.com/app.js", src)

    ev = ctrl.stamp_and_publish.call_args_list[0][0][0]
    assert ev.source_event_id == src.id          # source event
    assert ev.scan_job_id == ctrl.scan_id        # scan ID
    assert ev.source_tool == "apifinder"         # discovery method
    assert ev.data.found_via == "js-analysis"


# ── scope enforcement (the security requirement) ─────────────────────────────

async def test_scope_enforcement_drops_out_of_scope_discoveries():
    # example.com in scope; evil.com is not. A JS file that references both
    # must only yield in-scope URLs past the gate.
    scope = Scope.from_strings(in_scope=["*.example.com", "example.com"], out_scope=[])
    ctrl = _ScopingController(scope)
    m = ModuleRegistry.load(names=["apifinder"], controller=ctrl)[0]
    src = _source_event("https://example.com/app.js")

    js = 'fetch("https://example.com/api/v1/users"); fetch("https://evil.com/api/steal");'
    await m._process_text(js, "https://example.com/app.js", src)

    accepted_hosts = {urlparse(e.data.url).hostname for e in ctrl.accepted
                      if hasattr(e.data, "url")}
    assert "example.com" in accepted_hosts
    assert "evil.com" not in accepted_hosts


async def test_scope_enforcement_respects_out_scope_deny():
    scope = Scope.from_strings(
        in_scope=["*.example.com", "example.com"], out_scope=["x.example.com"]
    )
    ctrl = _ScopingController(scope)
    m = ModuleRegistry.load(names=["apifinder"], controller=ctrl)[0]
    src = _source_event("https://example.com/app.js")

    js = 'a("https://api.example.com/v1"); b("https://x.example.com/api/secret");'
    await m._process_text(js, "https://example.com/app.js", src)

    hosts = {urlparse(e.data.url).hostname for e in ctrl.accepted if hasattr(e.data, "url")}
    assert "api.example.com" in hosts
    assert "x.example.com" not in hosts


# ── well-known API/doc candidates on a live service ──────────────────────────

async def test_http_service_emits_well_known_candidates():
    from events.types import HttpServiceData

    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["apifinder"], controller=ctrl)[0]

    ev = types.SimpleNamespace()
    ev.id = uuid.uuid4()
    ev.distance = 1
    ev.type = EventType.HTTP_SERVICE
    ev.data = HttpServiceData(url="https://example.com/", status_code=200)

    # Fetching the base page would hit the network — disable it, keep candidates.
    m._fetch_and_extract = AsyncMock(return_value=None)
    await m.handle_event(ev)

    urls = {u.url for u in _emitted(ctrl, EventType.URL)}
    assert "https://example.com/graphql" in urls
    assert "https://example.com/openapi.json" in urls
    assert "https://example.com/api/v1/" in urls


# ── registration / wiring ────────────────────────────────────────────────────

def test_registered_and_in_discovery_group():
    assert "apifinder" in DISCOVERY_MODULES
    assert "apifinder" in FULL_MODULES
    m = ModuleRegistry.load(names=["apifinder"], controller=_mock_controller())[0]
    assert m.name == "apifinder"
    assert set(m.watched_events) == {"HTTP_SERVICE", "URL"}
    assert set(m.produced_events) == {"URL", "ENDPOINT", "PARAMETER", "TECHNOLOGY"}
