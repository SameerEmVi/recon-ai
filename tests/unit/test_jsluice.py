"""
jsluice wrapper + module tests.

Pure parsing/command coverage plus module behaviour (JS gating, ENDPOINT/URL
emission, EXPR handling, opt-in redacted secrets) — all mocked, no binary/network.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from events.types import EventType, UrlData
from modules.registry import ModuleRegistry
from recon.fetch import FetchResult
from recon.jsluice import (
    JsluiceSecret,
    JsluiceUrl,
    build_command,
    parse_secrets_json,
    parse_urls_json,
)


# ── build_command (pure) ──────────────────────────────────────────────────────

def test_build_command_urls_and_secrets():
    assert build_command("/tmp/a.js") == ["jsluice", "urls", "/tmp/a.js"]
    assert build_command("/tmp/a.js", mode="secrets") == ["jsluice", "secrets", "/tmp/a.js"]


def test_build_command_rejects_bad_mode_and_flag_target():
    with pytest.raises(ValueError):
        build_command("/tmp/a.js", mode="tree")
    with pytest.raises(ValueError):
        build_command("-rf")
    with pytest.raises(ValueError):
        build_command("")


# ── parse_urls_json (pure) ────────────────────────────────────────────────────

def test_parse_urls_basic_fields_and_params():
    line = ('{"url":"/api/v1/users","method":"post","type":"fetch",'
            '"queryParams":["page","page"],"bodyParams":["name","email"]}')
    out = parse_urls_json(line)
    assert len(out) == 1
    u = out[0]
    assert u.url == "/api/v1/users" and u.method == "POST" and u.kind == "fetch"
    assert u.query_params == ("page",)            # de-duped
    assert u.body_params == ("name", "email")


def test_parse_urls_skips_noise_and_missing_url():
    text = 'not json\n\n{"method":"GET"}\n{"url":"https://x/api","type":"xhr"}\n'
    out = parse_urls_json(text)
    assert [u.url for u in out] == ["https://x/api"]
    assert out[0].method == "GET"


def test_parse_urls_empty():
    assert parse_urls_json("") == []
    assert parse_urls_json(None) == []


# ── parse_secrets_json (pure) — must drop the raw value ───────────────────────

def test_parse_secrets_keeps_only_kind_and_severity():
    line = ('{"kind":"AWS Access Key","severity":"high",'
            '"data":{"key":"AKIAIOSFODNN7EXAMPLE","secret":"wJalr..."},'
            '"context":{"line":"const k=\\"AKIA...\\""}}')
    out = parse_secrets_json(line)
    assert out == [JsluiceSecret(kind="AWS Access Key", severity="high")]
    # The raw value must NOT survive anywhere in the parsed record.
    blob = repr(out)
    assert "AKIA" not in blob and "wJalr" not in blob


def test_parse_secrets_normalizes_bad_severity_and_skips_kindless():
    out = parse_secrets_json('{"kind":"Generic","severity":"weird"}\n{"severity":"high"}')
    assert out == [JsluiceSecret(kind="Generic", severity="info")]


# ── module ────────────────────────────────────────────────────────────────────

def _ctrl():
    from ratelimit import NOOP
    c = MagicMock()
    c.scan_id = uuid.uuid4()
    c.rate_limiter = NOOP
    c.stamp_and_publish = AsyncMock(return_value=True)
    return c


def _module(ctrl):
    ModuleRegistry.discover()
    return ModuleRegistry.load(names=["jsluice"], controller=ctrl)[0]


def _url_event(url="https://t.com/app.js", ctype="application/javascript"):
    ev = MagicMock()
    ev.data = UrlData(url=url, content_type=ctype)
    ev.id = uuid.uuid4()
    ev.distance = 2
    ev.type = EventType.URL
    return ev


async def test_module_skips_non_js_url():
    ctrl = _ctrl()
    m = _module(ctrl)
    with patch.object(m, "fetch", new=AsyncMock()) as fetch:
        await m.handle_event(_url_event("https://t.com/index.html", "text/html"))
    fetch.assert_not_awaited()


async def test_module_emits_endpoints_and_urls():
    ctrl = _ctrl()
    m = _module(ctrl)
    js = FetchResult(url="https://t.com/app.js", status_code=200, text="/*js*/", ok=True)
    jsluice_out = (
        '{"url":"/api/v1/users","method":"GET","queryParams":["page"],"bodyParams":[]}\n'
        '{"url":"https://t.com/api/login","method":"POST","bodyParams":["user","pass"]}\n'
        '{"url":"/api/EXPR/item","method":"GET"}\n'   # dynamic → ENDPOINT only
    )
    with patch.object(m, "fetch", new=AsyncMock(return_value=js)), \
         patch.object(m, "run_proc", new=AsyncMock(return_value=jsluice_out)):
        await m.handle_event(_url_event())

    by_type: dict = {}
    for c in ctrl.stamp_and_publish.await_args_list:
        ev = c.args[0]
        by_type.setdefault(ev.type, []).append(ev.data)

    endpoints = {d.url for d in by_type.get(EventType.ENDPOINT, [])}
    urls = {d.url for d in by_type.get(EventType.URL, [])}
    # 3 endpoints resolved against the JS origin
    assert endpoints == {
        "https://t.com/api/v1/users",
        "https://t.com/api/login",
        "https://t.com/api/EXPR/item",
    }
    # URLs only for concrete http(s) targets without EXPR
    assert urls == {"https://t.com/api/v1/users", "https://t.com/api/login"}
    assert "https://t.com/api/EXPR/item" not in urls
    # params ride on the ENDPOINT
    login = next(d for d in by_type[EventType.ENDPOINT] if d.url.endswith("/login"))
    assert set(login.parameters) == {"user", "pass"}


async def test_module_secrets_opt_in_emits_redacted_finding():
    ctrl = _ctrl()
    m = _module(ctrl)
    m._config["secrets"] = True
    js = FetchResult(url="https://t.com/app.js", status_code=200, text="x", ok=True)

    def run_proc_side(cmd, **kw):
        if "secrets" in cmd:
            return '{"kind":"AWS API Key","severity":"high","data":{"k":"AKIAEXAMPLE"}}'
        return ""   # no urls

    with patch.object(m, "fetch", new=AsyncMock(return_value=js)), \
         patch.object(m, "run_proc", new=AsyncMock(side_effect=run_proc_side)):
        await m.handle_event(_url_event())

    findings = [c.args[0] for c in ctrl.stamp_and_publish.await_args_list
                if c.args[0].type is EventType.FINDING_CANDIDATE]
    assert len(findings) == 1
    f = findings[0]
    assert f.data.category == "exposed-secret:jsluice:AWS API Key"
    assert f.data.severity_hint == "high"
    # The raw secret value must never appear in the emitted finding.
    assert "AKIA" not in str(f.data.evidence) and "AKIA" not in f.data.description


async def test_module_no_secrets_by_default():
    ctrl = _ctrl()
    m = _module(ctrl)   # secrets option defaults False
    js = FetchResult(url="https://t.com/app.js", status_code=200, text="x", ok=True)
    calls = []

    def run_proc_side(cmd, **kw):
        calls.append(cmd)
        return ""

    with patch.object(m, "fetch", new=AsyncMock(return_value=js)), \
         patch.object(m, "run_proc", new=AsyncMock(side_effect=run_proc_side)):
        await m.handle_event(_url_event())
    # only the `urls` subcommand runs, never `secrets`
    assert all("secrets" not in c for c in calls)


def test_registry_and_classification():
    ModuleRegistry.discover()
    from modules.registry import FULL_MODULES
    from policy.policy import MODULE_CAPABILITIES
    assert "jsluice" in FULL_MODULES
    assert MODULE_CAPABILITIES["jsluice"] == frozenset({"TARGET_HTTP_REQUEST"})
    assert "URL" in ModuleRegistry.get("jsluice").watched_events
