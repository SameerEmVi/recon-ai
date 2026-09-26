"""
dirsearch tests — native content-discovery engine + module.

Covers:
  - Dictionary generation: %EXT% tag, forced/overwrite/remove extensions,
    prefixes/suffixes, case transforms, dedup, comment/blank stripping.
  - status/size spec parsing and is_valid_status include/exclude precedence.
  - DynamicContentParser + Scanner wildcard / false-positive detection.
  - module orchestration: emits real finds, drops wildcard hits, honours
    status/size filters, recurses into directories (bounded), scope-gated emit.
  - registration / group wiring.
"""

from __future__ import annotations

import types
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from events.types import EventType, HttpServiceData, UrlData
from modules.registry import DISCOVERY_MODULES, FULL_MODULES, ModuleRegistry
from modules.web.dirsearch import DirsearchModule
from recon.dirsearch import (
    Dictionary,
    DictionaryOptions,
    DynamicContentParser,
    Response,
    Scanner,
    generate_random_string,
    is_valid_status,
    parse_sizes,
    parse_status_codes,
)


# ── Dictionary ────────────────────────────────────────────────────────────────

def test_dictionary_ext_tag():
    d = Dictionary.from_text("index.%EXT%", DictionaryOptions(extensions=["php", "html"]))
    assert d.entries() == ["index.php", "index.html"]


def test_dictionary_ext_tag_without_extensions_strips_tag():
    d = Dictionary.from_text("index.%EXT%", DictionaryOptions(extensions=[]))
    assert d.entries() == ["index."]


def test_dictionary_force_extensions_only_extensionless():
    d = Dictionary.from_text(
        "admin\nrobots.txt", DictionaryOptions(extensions=["php"], force_extensions=True)
    )
    assert d.entries() == ["admin", "admin.php", "robots.txt"]


def test_dictionary_overwrite_extensions():
    d = Dictionary.from_text(
        "index.html", DictionaryOptions(extensions=["php"], overwrite_extensions=True)
    )
    assert d.entries() == ["index.php"]


def test_dictionary_remove_extensions():
    d = Dictionary.from_text("index.html", DictionaryOptions(remove_extensions=True))
    assert d.entries() == ["index"]


def test_dictionary_exclude_extensions():
    d = Dictionary.from_text(
        "a.php\nb.jpg", DictionaryOptions(exclude_extensions=["jpg"])
    )
    assert d.entries() == ["a.php"]


def test_dictionary_prefixes_suffixes():
    d = Dictionary.from_text("admin", DictionaryOptions(prefixes=["."], suffixes=["~"]))
    assert d.entries() == [".admin", "admin", "admin~"]


def test_dictionary_case_transforms():
    assert Dictionary.from_text("Admin", DictionaryOptions(lowercase=True)).entries() == ["admin"]
    assert Dictionary.from_text("admin", DictionaryOptions(uppercase=True)).entries() == ["ADMIN"]
    assert Dictionary.from_text("admin", DictionaryOptions(capitalization=True)).entries() == ["Admin"]


def test_dictionary_strips_comments_blanks_and_leading_slash_and_dedups():
    d = Dictionary.from_text("# comment\n\n/api/\nadmin\nadmin\n")
    assert d.entries() == ["api/", "admin"]


# ── spec parsers ──────────────────────────────────────────────────────────────

def test_parse_status_codes_ranges_and_singletons():
    assert parse_status_codes("200,301,400-402") == {200, 301, 400, 401, 402}
    assert parse_status_codes("") == set()
    assert parse_status_codes(None) == set()
    assert parse_status_codes("junk,200") == {200}


def test_parse_sizes_units():
    assert parse_sizes("0,1k,2048,1m") == {0, 1024, 2048, 1024 * 1024}
    assert parse_sizes("") == set()


def test_is_valid_status_include_wins():
    assert is_valid_status(200, include={200}, exclude={200}) is True
    assert is_valid_status(301, include={200}, exclude=None) is False
    assert is_valid_status(404, include=None, exclude={404}) is False
    assert is_valid_status(200, include=None, exclude={404}) is True


# ── wildcard detection ────────────────────────────────────────────────────────

def test_dynamic_content_parser_flags_similar_as_wildcard():
    # Realistic case: a large static template with one reflected dynamic token.
    static = " ".join(f"word{i}" for i in range(200))
    p = DynamicContentParser(f"{static} token_aaaa", f"{static} token_bbbb")
    # Another wildcard page (same template, different reflected token) → high.
    assert p.compare_to(f"{static} token_cccc") >= 0.98
    # A genuinely different page → low.
    assert p.compare_to("totally different admin dashboard control panel logout") < 0.98


def test_scanner_status_difference_is_a_find():
    sc = Scanner(Response(status=200, body="x"), Response(status=200, body="x"))
    assert sc.check(Response(status=403, body="forbidden")) is True


def test_scanner_filters_wildcard_body():
    static = " ".join(f"nav{i}" for i in range(200))
    b1 = Response(status=200, body=f"<html>{static} ref_aaaa</html>")
    b2 = Response(status=200, body=f"<html>{static} ref_bbbb</html>")
    sc = Scanner(b1, b2, token="aaaa")
    wild = Response(status=200, body=f"<html>{static} ref_zzzz</html>")
    real = Response(status=200, body="<html>admin panel user password submit token secret</html>")
    assert sc.check(wild) is False
    assert sc.check(real) is True


def test_scanner_templated_redirect_is_wildcard():
    token = generate_random_string()
    first = Response(status=302, body="", redirect=f"https://x/login?next=/{token}")
    sc = Scanner(first, None, token=token)
    # Any templated redirect with a different token still matches → wildcard.
    other = Response(status=302, body="", redirect="https://x/login?next=/somethingelse")
    assert sc.check(other) is False


# ── module orchestration ──────────────────────────────────────────────────────

def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def _http_event(url: str, distance: int = 0):
    ev = types.SimpleNamespace()
    ev.id = uuid.uuid4()
    ev.distance = distance
    ev.type = EventType.HTTP_SERVICE
    ev.data = HttpServiceData(url=url, status_code=200)
    return ev


def _install_wordlist(mod: DirsearchModule, words: list[str], tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(words), encoding="utf-8")
    mod._config["wordlist"] = str(wl)


@pytest.mark.asyncio
async def test_module_emits_real_finds_and_drops_wildcard(tmp_path, monkeypatch):
    ctrl = _mock_controller()
    mod = DirsearchModule(ctrl, {"extensions": "", "recursive": False, "exclude_status": "404"})
    _install_wordlist(mod, ["admin", "ghost"], tmp_path)

    # Fake the network layer entirely — no httpx, deterministic responses.
    async def fake_request(client, url):
        if url.endswith("/admin"):
            return Response(status=200, body="ADMIN PANEL login user pass token", url=url)
        if url.endswith("/ghost"):
            # identical to the wildcard baseline body → should be filtered
            return Response(status=200, body="wildcard home page nav footer", url=url)
        # random wildcard probes
        return Response(status=200, body="wildcard home page nav footer", url=url)

    monkeypatch.setattr(mod, "_request", fake_request)

    ev = _http_event("http://t.example")
    await mod.handle_event(ev)

    emitted = [c.args[0] for c in ctrl.stamp_and_publish.call_args_list]
    urls = [e.data.url for e in emitted]
    assert "http://t.example/admin" in urls
    assert "http://t.example/ghost" not in urls
    assert all(e.data.found_via == "dirsearch" for e in emitted)


@pytest.mark.asyncio
async def test_module_recurses_into_directories(tmp_path, monkeypatch):
    ctrl = _mock_controller()
    mod = DirsearchModule(
        ctrl, {"extensions": "", "recursive": True, "max_recursion_depth": 1, "exclude_status": "404"}
    )
    _install_wordlist(mod, ["api", "admin"], tmp_path)

    calls: list[str] = []

    async def fake_request(client, url):
        calls.append(url)
        # "api" is a directory (200, no extension); inside it, "admin" exists.
        if url.endswith("/api"):
            return Response(status=200, body="index of api v1 v2 endpoints listing", url=url)
        if url.endswith("/api/admin"):
            return Response(status=200, body="nested ADMIN panel secret controls", url=url)
        if url.endswith("/admin"):
            return Response(status=404, body="nope", url=url)
        return Response(status=404, body="not found random", url=url)

    monkeypatch.setattr(mod, "_request", fake_request)

    await mod.handle_event(_http_event("http://t.example"))

    urls = [c.args[0].data.url for c in ctrl.stamp_and_publish.call_args_list]
    assert "http://t.example/api" in urls
    # recursion actually requested the nested path:
    assert any(u.endswith("/api/admin") for u in calls)
    assert "http://t.example/api/admin" in urls


@pytest.mark.asyncio
async def test_module_missing_wordlist_is_safe(tmp_path, monkeypatch):
    ctrl = _mock_controller()
    mod = DirsearchModule(ctrl, {})
    mod._config["wordlist"] = str(tmp_path / "does-not-exist.txt")
    # Should not raise, should not emit.
    await mod.handle_event(_http_event("http://t.example"))
    ctrl.stamp_and_publish.assert_not_called()


# ── registration ──────────────────────────────────────────────────────────────

def test_registered_in_discovery_and_full():
    assert "dirsearch" in DISCOVERY_MODULES
    assert "dirsearch" in FULL_MODULES


def test_loads_by_name_and_flag():
    ModuleRegistry.discover()
    ctrl = MagicMock()
    by_name = ModuleRegistry.load(names=["dirsearch"], controller=ctrl)
    assert [m.name for m in by_name] == ["dirsearch"]
    by_flag = ModuleRegistry.load(flags=["content-discovery"], controller=ctrl)
    assert "dirsearch" in [m.name for m in by_flag]
