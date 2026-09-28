"""
Tests for the JavaScript Intelligence Engine (recon.jsintel) with a realistic
webpack-style bundle fixture, plus the extensible-extractor contract.
"""

from __future__ import annotations

import pytest

from recon import jsintel
from recon.jsintel import Extractor, JsAnalysis, analyze

BASE = "https://app.example.com/static/js/main.abc123.js"

# A realistic (compact) SPA bundle: API calls, versioned API, GraphQL, websocket,
# source map, config, routes, a service class, framework signatures.
BUNDLE = r"""
/*! app bundle */
webpackJsonp([0],{
  0:function(e,t,n){
    "use strict";
    var API_BASE_URL = "https://api.example.com";
    var graphqlEndpoint = "/graphql";
    const WS_URL = "wss://realtime.example.com/socket";
    fetch("/api/v2/users/profile");
    fetch(API_BASE_URL + "/api/v3/orders");
    axios.get("https://api.example.com/api/v1/payments");
    const ws = new WebSocket("/live/notifications");
    class OrderService { list(){ return fetch("/api/v2/orders"); } }
    const routes = [
      { path: "/dashboard", name: "dash" },
      { path: "/admin/settings", name: "settings" },
    ];
    var firebaseConfig = { apiKey: "x", authDomain: "app.firebaseapp.com" };
    var s = import.meta.env.VITE_API_HOST;
    query CurrentUser { id email }
    function loadUserProfile(){}
    var img = "/assets/logo.png";
    var mime = "application/json";
  }
});
//# sourceMappingURL=main.abc123.js.map
"""

HTML = """
<html><head>
<script>var INLINE_API_URL = "/api/v1/config"; fetch("/api/v1/session"); ReactDOM.render(app, el);</script>
<script src="/static/js/vendor.js"></script>
<script src="https://cdn.example.com/lib.js"></script>
</head><body>app</body></html>
"""


@pytest.fixture
def result() -> JsAnalysis:
    return analyze(BUNDLE, BASE)


# ── endpoints / URLs / API ────────────────────────────────────────────────────

def test_absolute_urls_extracted(result):
    assert "https://api.example.com/api/v1/payments" in result.urls


def test_relative_api_paths_resolved_and_classified(result):
    endpoint_urls = {u for u, _ in result.endpoints}
    assert "https://app.example.com/api/v2/users/profile" in endpoint_urls
    assert any(tag in ("api", "api-version") for _, tag in result.endpoints)


def test_api_versions_present(result):
    endpoint_urls = " ".join(u for u, _ in result.endpoints)
    assert "/api/v2/" in endpoint_urls
    assert "/api/v3/" in endpoint_urls or "/api/v1/" in endpoint_urls


def test_graphql_endpoint_and_names(result):
    # /graphql relative resolves; GraphQL op name from `query CurrentUser`
    assert any(tag == "graphql" for _, tag in result.endpoints) or \
        any("graphql" in u for u in result.urls)
    assert "CurrentUser" in result.graphql


# ── websockets ────────────────────────────────────────────────────────────────

def test_websocket_urls(result):
    assert "wss://realtime.example.com/socket" in result.websockets
    # relative WebSocket ctor resolved + scheme-swapped to wss
    assert any(w.startswith("wss://app.example.com/live/notifications") for w in result.websockets)


# ── source maps ────────────────────────────────────────────────────────────────

def test_source_map_detected(result):
    assert any(u.endswith("main.abc123.js.map") for u in result.source_maps)


# ── configuration indicators ─────────────────────────────────────────────────

def test_config_indicators(result):
    names = {n for n, _ in result.config_indicators}
    assert "API_BASE_URL" in names
    assert "graphqlEndpoint" in names
    assert any(k == "import-meta-env" for _, k in result.config_indicators)


# ── routes / services / technology ───────────────────────────────────────────

def test_routes(result):
    assert "/dashboard" in result.routes
    assert "/admin/settings" in result.routes


def test_service_names(result):
    assert "OrderService" in result.services


def test_technology_indicators(result):
    assert "Webpack" in result.technologies


def test_js_identifiers(result):
    assert "loadUserProfile" in result.identifiers


# ── "don't treat arbitrary strings as endpoints" ─────────────────────────────

def test_static_assets_and_mime_not_endpoints(result):
    assert not any(u.endswith("logo.png") for u in result.urls)
    assert "application/json" not in result.urls
    assert not any("logo.png" in u for u, _ in result.endpoints)


# ── inline JS from HTML ──────────────────────────────────────────────────────

def test_inline_script_analyzed():
    a = analyze(HTML, "https://app.example.com/", is_html=True)
    endpoint_urls = {u for u, _ in a.endpoints}
    assert "https://app.example.com/api/v1/session" in endpoint_urls
    assert "React" in a.technologies


def test_external_script_srcs_resolved():
    srcs = jsintel.script_srcs(HTML, "https://app.example.com/")
    assert "https://app.example.com/static/js/vendor.js" in srcs
    assert "https://cdn.example.com/lib.js" in srcs


# ── robustness / extensibility ────────────────────────────────────────────────

def test_empty_and_garbage_input_safe():
    assert analyze("", BASE).urls == []
    assert isinstance(analyze("\x00\xff not js {[}", BASE), JsAnalysis)


def test_extensible_custom_extractor():
    class FlagExtractor(Extractor):
        name = "flags"
        def extract(self, content, base_url, analysis):
            if "feature_x" in content:
                analysis.add("identifiers", "feature_x_seen")

    a = analyze('var feature_x = true;', BASE, extractors=[FlagExtractor()])
    assert "feature_x_seen" in a.identifiers


def test_broken_extractor_does_not_break_pipeline():
    class Boom(Extractor):
        name = "boom"
        def extract(self, content, base_url, analysis):
            raise RuntimeError("boom")

    # A raising extractor is swallowed; analysis still returns.
    a = analyze(BUNDLE, BASE, extractors=[Boom(), jsintel.UrlExtractor()])
    assert "https://api.example.com/api/v1/payments" in a.urls
