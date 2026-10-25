"""
katana wrapper tests — command assembly + JSONL parsing.

JSONL fixtures follow katana v1.8.0's real schema (captured live): request
{method,endpoint,tag,source}, response{status_code,technologies,forms},
knowledgebase{PageType}. No network.
"""

from __future__ import annotations

import json

import pytest

from recon.katana import (
    KatanaError,
    build_command,
    parse_katana_jsonl,
)


# ── build_command ─────────────────────────────────────────────────────────────

def test_build_command_full_flags():
    cmd = build_command("https://t.example", depth=5, concurrency=10,
                        parallelism=3, rate=10, retry=1, timeout=10)
    # JSONL to stdout, no -o
    assert "-j" in cmd and "-o" not in cmd
    assert cmd[cmd.index("-d") + 1] == "5"
    assert cmd[cmd.index("-c") + 1] == "10"
    assert cmd[cmd.index("-p") + 1] == "3"
    assert cmd[cmd.index("-rl") + 1] == "10"
    assert cmd[cmd.index("-retry") + 1] == "1"
    for f in ("-jc", "-xhr", "-fx", "-td", "-kb", "-iqp", "-silent"):
        assert f in cmd
    assert cmd[cmd.index("-kf") + 1] == "all"


def test_build_command_rate_none_omits_rl():
    assert "-rl" not in build_command("https://t.example", rate=None)
    assert "-rl" not in build_command("https://t.example", rate=0)


def test_build_command_toggles_off():
    cmd = build_command("https://t.example", xhr=False, form_extraction=False,
                        tech_detect=False, knowledge_base=False,
                        ignore_query_params=False, js_crawl=False, known_files=None)
    for f in ("-xhr", "-fx", "-td", "-kb", "-iqp", "-jc", "-kf"):
        assert f not in cmd


def test_build_command_kf_needs_depth_3():
    # known_files is dropped below depth 3 (katana requires >=3 for known files).
    assert "-kf" not in build_command("https://t.example", depth=2, known_files="all")
    assert "-kf" in build_command("https://t.example", depth=3, known_files="all")


def test_build_command_proxy_and_elog():
    cmd = build_command("https://t.example", proxy="http://127.0.0.1:8080",
                        error_log="/tmp/e.log")
    assert cmd[cmd.index("-proxy") + 1] == "http://127.0.0.1:8080"
    assert cmd[cmd.index("-elog") + 1] == "/tmp/e.log"


@pytest.mark.parametrize("bad", ["", "-u", "--depth"])
def test_build_command_rejects_flaglike_target(bad):
    with pytest.raises(KatanaError):
        build_command(bad)


def test_build_command_rejects_bad_known_files():
    with pytest.raises(KatanaError):
        build_command("https://t.example", known_files="bogus")


# ── parse_katana_jsonl ────────────────────────────────────────────────────────

_PAGE = json.dumps({
    "request": {"method": "GET", "endpoint": "https://t.example/",
                "tag": "", "source": ""},
    "response": {"status_code": 200, "technologies": ["Cloudflare", "HTTP/3"]},
    "knowledgebase": {"PageType": "landing"},
})
_SCRIPT = json.dumps({
    "request": {"method": "GET", "endpoint": "https://t.example/app.js",
                "tag": "script", "attribute": "src", "source": "https://t.example/"},
    "response": {"status_code": 200, "technologies": ["Webpack"]},
})
_FORM = json.dumps({
    "request": {"method": "GET", "endpoint": "https://t.example/login", "tag": "a"},
    "response": {"status_code": 200, "forms": [
        {"method": "POST", "action": "https://t.example/auth",
         "enctype": "application/x-www-form-urlencoded",
         "parameters": ["username", "password", "csrf"]}]},
})
_XHR = json.dumps({
    "request": {"method": "POST", "endpoint": "https://t.example/api/v1/cart",
                "tag": "xhr", "source": "https://t.example/shop"},
    "response": {"status_code": 200},
})


def test_parse_basic_record_with_tech_and_pagetype():
    recs = parse_katana_jsonl(_PAGE)
    assert len(recs) == 1
    r = recs[0]
    assert r.url == "https://t.example/" and r.method == "GET" and r.status == 200
    assert r.technologies == ("Cloudflare", "HTTP/3")
    assert r.page_type == "landing"


def test_parse_form_extraction():
    r = parse_katana_jsonl(_FORM)[0]
    assert len(r.forms) == 1
    f = r.forms[0]
    assert f.method == "POST" and f.action == "https://t.example/auth"
    assert f.parameters == ("username", "password", "csrf")


def test_parse_xhr_method_preserved():
    r = parse_katana_jsonl(_XHR)[0]
    assert r.method == "POST" and r.tag == "xhr"
    assert r.url == "https://t.example/api/v1/cart"


def test_parse_tolerates_noise_and_missing_endpoint():
    text = (
        "[INF] Current katana version v1.8.0\n"
        "\n"
        "not json\n"
        + _PAGE + "\n"
        + json.dumps({"request": {"method": "GET"}}) + "\n"   # no endpoint → skipped
        + _SCRIPT + "\n"
    )
    recs = parse_katana_jsonl(text)
    assert [r.url for r in recs] == ["https://t.example/", "https://t.example/app.js"]


def test_parse_empty():
    assert parse_katana_jsonl("") == []
    assert parse_katana_jsonl(None) == []


def test_parse_form_param_key_variants():
    # katana may use 'fields' or 'inputs' instead of 'parameters'.
    doc = json.dumps({"request": {"endpoint": "https://t.example/x"},
                      "response": {"forms": [{"method": "GET", "action": "/s",
                                              "fields": ["q", "lang"]}]}})
    r = parse_katana_jsonl(doc)[0]
    assert r.forms[0].parameters == ("q", "lang")


# ── module: JSONL → URL/ENDPOINT/PARAMETER/TECHNOLOGY emission ─────────────────

import asyncio  # noqa: E402
import uuid  # noqa: E402
from unittest.mock import AsyncMock, MagicMock, patch  # noqa: E402

from events.types import EventType, HttpServiceData  # noqa: E402
from modules.registry import ModuleRegistry  # noqa: E402


def _ctrl():
    from ratelimit import NOOP
    c = MagicMock()
    c.scan_id = uuid.uuid4()
    c.rate_limiter = NOOP
    c.stamp_and_publish = AsyncMock(return_value=True)
    return c


def _svc_event(url="https://t.example/"):
    ev = MagicMock()
    ev.data = HttpServiceData(url=url, status_code=200)
    ev.id = uuid.uuid4()
    ev.distance = 1
    ev.type = EventType.HTTP_SERVICE
    return ev


async def test_module_emits_all_event_types_from_jsonl():
    ModuleRegistry.discover()
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["katana"], controller=ctrl)[0]
    jsonl = "\n".join([_PAGE, _SCRIPT, _FORM, _XHR])

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=MagicMock())), \
         patch("recon.proc.communicate", AsyncMock(return_value=(jsonl.encode(), b""))):
        await m.handle_event(_svc_event())

    by_type: dict = {}
    for c in ctrl.stamp_and_publish.await_args_list:
        ev = c.args[0]
        by_type.setdefault(ev.type, []).append(ev.data)

    assert EventType.URL in by_type
    assert EventType.ENDPOINT in by_type
    assert EventType.PARAMETER in by_type
    assert EventType.TECHNOLOGY in by_type

    # Form → endpoint action + body params
    eps = {d.url for d in by_type[EventType.ENDPOINT]}
    assert "https://t.example/auth" in eps                 # form action
    assert "https://t.example/api/v1/cart" in eps          # xhr (POST)
    params = {d.name for d in by_type[EventType.PARAMETER]}
    assert {"username", "password", "csrf"} <= params
    techs = {d.name for d in by_type[EventType.TECHNOLOGY]}
    assert {"Cloudflare", "Webpack"} & techs


async def test_module_timeout_kills_tree_and_emits_nothing():
    ModuleRegistry.discover()
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["katana"], controller=ctrl)[0]
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=MagicMock())), \
         patch("recon.proc.communicate", AsyncMock(side_effect=asyncio.TimeoutError())):
        await m.handle_event(_svc_event())   # must not raise
    ctrl.stamp_and_publish.assert_not_awaited()


def test_module_rate_derives_from_shared_limiter():
    from ratelimit import RateLimiter
    ctrl = _ctrl()
    ctrl.rate_limiter = RateLimiter(rate_per_sec=7, name="t")
    ModuleRegistry.discover()
    m = ModuleRegistry.load(names=["katana"], controller=ctrl)[0]
    assert m._rate() == 7          # single rate chokepoint honored
