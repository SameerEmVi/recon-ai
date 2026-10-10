"""Unit + integration tests for the extension-fuzzing engine and module."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from recon.extfuzz import (
    APPEND,
    EXTENSIONLESS,
    REPLACE,
    V_AMBIGUOUS,
    V_AUTH,
    V_FILE,
    V_NOT_FOUND,
    V_REDIRECT,
    V_SOFT404,
    V_WAF,
    Baseline,
    build_baseline,
    classify,
    generate_candidates,
    interesting_category,
    normalize_extension,
    normalize_extensions,
    normalize_strategies,
    severity_for,
    signature_matches,
    tech_extensions,
)
from recon.fetch import FetchResult


# ── extension normalization (hostile-input-safe) ──────────────────────────────

def test_normalize_extension_variants():
    assert normalize_extension(".JS") == "js"
    assert normalize_extension("  Bak ") == "bak"
    assert normalize_extension("tar.gz") == "tar.gz"
    assert normalize_extension("php5") == "php5"


def test_normalize_extension_rejects_junk():
    assert normalize_extension("") is None
    assert normalize_extension(".") is None
    assert normalize_extension("..") is None
    assert normalize_extension("a.") is None
    assert normalize_extension("a..b") is None
    assert normalize_extension("has space") is None
    assert normalize_extension("semi;colon") is None
    assert normalize_extension("../etc/passwd") is None
    assert normalize_extension("x" * 20) is None
    assert normalize_extension(None) is None


def test_normalize_extensions_dedup_order_and_cap():
    out = normalize_extensions(["php", ".PHP", "bak", "bad ext", "js"], max_count=10)
    assert out == ["php", "bak", "js"]        # order preserved, dupes/junk dropped
    assert normalize_extensions("a,b,c,d", max_count=2) == ["a", "b"]
    assert normalize_extensions(None) == []


def test_tech_extensions_prioritizes_by_stack():
    assert "php" in tech_extensions(["PHP", "nginx"])
    assert "aspx" in tech_extensions(["Microsoft ASP.NET:4.0"])   # prefix match
    assert "map" in tech_extensions(["React"])
    assert tech_extensions(["totally-unknown"]) == []


def test_normalize_strategies():
    assert normalize_strategies("append, replace") == [APPEND, REPLACE]
    assert normalize_strategies(["bogus"]) == [APPEND, REPLACE, EXTENSIONLESS]  # fallback
    assert normalize_strategies(None) == [APPEND, REPLACE, EXTENSIONLESS]


# ── candidate generation ───────────────────────────────────────────────────────

def test_generate_append_and_replace_on_file():
    cands = generate_candidates(
        "https://x.com/js/app.js", ["bak", "map"], [APPEND, REPLACE]
    )
    assert "https://x.com/js/app.js.bak" in cands   # append
    assert "https://x.com/js/app.js.map" in cands
    assert "https://x.com/js/app.bak" in cands       # replace
    assert "https://x.com/js/app.map" in cands
    # never returns the original
    assert "https://x.com/js/app.js" not in cands


def test_generate_extensionless_strategy():
    cands = generate_candidates(
        "https://x.com/download.php", ["bak"], [EXTENSIONLESS]
    )
    assert "https://x.com/download" in cands         # the bare stem
    assert "https://x.com/download.bak" in cands


def test_generate_append_on_extensionless_path():
    cands = generate_candidates("https://x.com/admin", ["php", "bak"], [APPEND])
    assert "https://x.com/admin.php" in cands
    assert "https://x.com/admin.bak" in cands


def test_generate_dedups_and_drops_query():
    cands = generate_candidates(
        "https://x.com/a/app.js?v=2#frag", ["bak", "bak", "map"],
        [APPEND, REPLACE, EXTENSIONLESS],
    )
    assert all("?" not in c and "#" not in c for c in cands)
    assert len(cands) == len(set(cands))              # no duplicates


def test_generate_skips_directories_and_static_bases():
    assert generate_candidates("https://x.com/assets/", ["bak"], [APPEND]) == []
    assert generate_candidates("https://x.com/", ["bak"], [APPEND]) == []
    # a .png base is a poor source for .png.bak — skipped
    assert generate_candidates("https://x.com/logo.png", ["bak"], [APPEND]) == []
    # but .js is kept (source maps / backups are the prize)
    assert generate_candidates("https://x.com/app.js", ["map"], [APPEND])


def test_generate_respects_per_path_cap():
    exts = [f"e{i}" for i in range(50)]
    cands = generate_candidates("https://x.com/a.js", exts, [APPEND], max_per_path=5)
    assert len(cands) == 5


def test_generate_rejects_non_http():
    assert generate_candidates("ftp://x.com/a.js", ["bak"], [APPEND]) == []
    assert generate_candidates("not a url", ["bak"], [APPEND]) == []


# ── baseline (soft-404 catch-all) ──────────────────────────────────────────────

def test_build_baseline_detects_uniform_catchall():
    b = build_baseline([(200, "x" * 500), (200, "x" * 505)])
    assert b is not None and b.status == 200
    assert b.matches(200, "y" * 500) is True
    assert b.matches(200, "y" * 5000) is False        # different size → real
    assert b.matches(301, "y" * 500) is False          # different status


def test_build_baseline_none_when_host_404s_honestly():
    assert build_baseline([(404, "nope"), (404, "nope")]) is None
    assert build_baseline([(200, "a"), (301, "b")]) is None   # inconsistent status
    assert build_baseline([(None, None)]) is None


# ── classification: the cardinal rules ─────────────────────────────────────────

def test_classify_404_is_not_found():
    c = classify(ext="bak", status=404, body="Not Found")
    assert c.verdict == V_NOT_FOUND and c.confidence == 0.0


def test_classify_redirect_recorded_not_file():
    c = classify(ext="bak", status=302, body="", redirect="https://x.com/login")
    assert c.verdict == V_REDIRECT
    assert c.redirect == "https://x.com/login"


def test_classify_waf_block_dropped():
    c = classify(ext="sql", status=403, body="Attention Required! | Cloudflare")
    assert c.verdict == V_WAF
    c2 = classify(ext="sql", status=429, body="slow down")
    assert c2.verdict == V_WAF


def test_classify_protected_is_auth():
    assert classify(ext="bak", status=401, body="").verdict == V_AUTH
    assert classify(ext="json", status=200, body='<form><input type="password"></form>').verdict == V_AUTH


def test_classify_soft404_html_for_nonhtml_ext():
    # 200 that returns the SPA/HTML shell for a .json request is a soft-404.
    c = classify(ext="json", status=200, body="<!DOCTYPE html><html><body>app</body></html>")
    assert c.verdict == V_SOFT404


def test_classify_soft404_matches_baseline():
    base = Baseline(200, 500)
    c = classify(ext="bak", status=200, body="x" * 500, baseline=base)
    assert c.verdict == V_SOFT404


def test_classify_empty_2xx_is_soft404():
    assert classify(ext="bak", status=200, body="").verdict == V_SOFT404


def test_classify_200_alone_is_ambiguous_not_file():
    # Non-HTML, non-empty, no content-type, no signature: a LEAD, not a file.
    c = classify(ext="bak", status=200, body="some opaque bytes here")
    assert c.verdict == V_AMBIGUOUS
    assert c.confidence < 0.6                          # below finding threshold


def test_classify_file_via_body_signature():
    c = classify(ext="json", status=200, body='{"api":"key","x":1}')
    assert c.verdict == V_FILE and c.confidence >= 0.85
    sql = classify(ext="sql", status=200, body="-- dump\nINSERT INTO users VALUES (1);")
    assert sql.verdict == V_FILE and sql.category == "database-dump"
    sm = classify(ext="map", status=200, body='{"version":3,"mappings":"AAAA","sources":[]}')
    assert sm.verdict == V_FILE and sm.category == "source-map"


def test_classify_file_via_content_type():
    c = classify(ext="bak", status=200, body="raw source text", content_type="application/octet-stream")
    assert c.verdict == V_FILE and c.category == "backup" and c.confidence >= 0.85


def test_classify_oversize_body_uses_content_type():
    c = classify(ext="zip", status=200, body=None, content_type="application/zip")
    assert c.verdict == V_FILE and c.confidence == 0.7


def test_signature_and_category_helpers():
    assert signature_matches("json", '{"a":1}') is True
    assert signature_matches("json", "not json") is False
    assert interesting_category("bak") == "backup"
    assert interesting_category("js") is None
    assert severity_for("database-dump") == "medium"
    assert severity_for("config") == "low"


# ── module integration ──────────────────────────────────────────────────────────

def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.scan_domain = "x.com"
    ctrl.knowledge_base = None            # no KB — learned-seed is a no-op
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def _load_module(ctrl, **cfg):
    from modules.registry import ModuleRegistry
    m = ModuleRegistry.load(names=["extfuzz"], controller=ctrl)[0]
    m._config.update(cfg)
    return m


def test_extfuzz_registered_and_reactive():
    from modules.registry import DISCOVERY_MODULES, FULL_MODULES
    assert "extfuzz" in DISCOVERY_MODULES
    assert "extfuzz" in FULL_MODULES
    ctrl = _mock_controller()
    m = _load_module(ctrl)
    assert set(m.watched_events) >= {"URL", "HTTP_SERVICE", "TECHNOLOGY"}
    assert m.deps_binary == []            # no external binary


async def test_extfuzz_emits_url_and_finding_for_real_backup():
    from events.types import EventType, UrlData

    ctrl = _mock_controller()
    m = _load_module(ctrl, extensions="bak,map", strategies="append,replace",
                     calibration_probes=1)

    def fake_fetch(url, **kw):
        if "extfuzz-probe" in url:
            return FetchResult(url=url, status_code=404, text="nope", ok=True)
        if url == "https://x.com/js/app.bak":
            return FetchResult(url=url, status_code=200,
                               text="var secret = 'leaked source';", ok=True,
                               content_type="application/octet-stream",
                               headers={"content-type": "application/octet-stream"})
        if url == "https://x.com/js/app.js.map":
            return FetchResult(url=url, status_code=200,
                               text='{"version":3,"mappings":"AAAA","sources":["a.ts"]}',
                               ok=True, content_type="application/json")
        # everything else = soft-404 HTML shell
        return FetchResult(url=url, status_code=200, text="<!doctype html><html></html>",
                           ok=True, content_type="text/html")

    m.fetch = AsyncMock(side_effect=fake_fetch)

    ev = MagicMock()
    ev.type = EventType.URL
    ev.data = UrlData(url="https://x.com/js/app.js", found_via="crawl")
    ev.id = uuid.uuid4()
    ev.distance = 1

    await m.handle_event(ev)

    published = [c[0][0] for c in ctrl.stamp_and_publish.call_args_list]
    urls = {e.data.url for e in published if e.type is EventType.URL}
    findings = [e for e in published if e.type is EventType.FINDING_CANDIDATE]

    assert "https://x.com/js/app.bak" in urls          # confirmed via content-type
    assert "https://x.com/js/app.js.map" in urls        # confirmed via signature
    assert all(e.data.found_via == "extension-fuzz" for e in published if e.type is EventType.URL)
    cats = {f.data.category for f in findings}
    assert "exposed-file:backup" in cats
    assert "exposed-file:source-map" in cats
    # soft-404 HTML candidates were NOT emitted
    assert "https://x.com/js/app.map" not in urls       # .map replace returned HTML shell


async def test_extfuzz_200_html_soft404_not_emitted():
    from events.types import EventType, UrlData

    ctrl = _mock_controller()
    m = _load_module(ctrl, extensions="json", strategies="replace", calibration_probes=1)

    def fake_fetch(url, **kw):
        # Everything (incl. probe) returns a 200 HTML shell → SPA catch-all.
        return FetchResult(url=url, status_code=200,
                           text="<!doctype html><html><body>app</body></html>",
                           ok=True, content_type="text/html")

    m.fetch = AsyncMock(side_effect=fake_fetch)

    ev = MagicMock()
    ev.type = EventType.URL
    ev.data = UrlData(url="https://x.com/a/config.js", found_via="crawl")
    ev.id = uuid.uuid4()
    ev.distance = 1
    await m.handle_event(ev)

    published = [c[0][0] for c in ctrl.stamp_and_publish.call_args_list]
    assert all(e.type is not EventType.FINDING_CANDIDATE for e in published)
    assert not any(getattr(e.data, "url", "") == "https://x.com/a/config.json" for e in published)


async def test_extfuzz_does_not_cascade_on_own_findings():
    from events.types import EventType, UrlData

    ctrl = _mock_controller()
    m = _load_module(ctrl)
    m.fetch = AsyncMock()

    ev = MagicMock()
    ev.type = EventType.URL
    ev.data = UrlData(url="https://x.com/app.js.bak", found_via="extension-fuzz")
    ev.id = uuid.uuid4()
    ev.distance = 1
    await m.handle_event(ev)

    m.fetch.assert_not_called()                         # own discovery → no re-fuzz


async def test_extfuzz_transport_failure_emits_nothing():
    from events.types import EventType, UrlData

    ctrl = _mock_controller()
    m = _load_module(ctrl, extensions="bak", strategies="append", calibration_probes=1)
    m.fetch = AsyncMock(return_value=FetchResult(url="x", ok=False, error="boom"))

    ev = MagicMock()
    ev.type = EventType.URL
    ev.data = UrlData(url="https://x.com/app.js", found_via="crawl")
    ev.id = uuid.uuid4()
    ev.distance = 1
    await m.handle_event(ev)

    assert ctrl.stamp_and_publish.call_count == 0


async def test_extfuzz_technology_event_tunes_extensions():
    from events.types import EventType, TechnologyData, UrlData

    ctrl = _mock_controller()
    m = _load_module(ctrl, extensions="bak", strategies="append",
                     calibration_probes=1, tech_aware=True)

    tech_ev = MagicMock()
    tech_ev.type = EventType.TECHNOLOGY
    tech_ev.data = TechnologyData(host="x.com", name="PHP", version="8.1")
    await m.handle_event(tech_ev)
    assert "php" in m._host_tech["x.com"]

    tested: list[str] = []

    def fake_fetch(url, **kw):
        tested.append(url)
        return FetchResult(url=url, status_code=404, text="nope", ok=True)

    m.fetch = AsyncMock(side_effect=fake_fetch)

    url_ev = MagicMock()
    url_ev.type = EventType.URL
    url_ev.data = UrlData(url="https://x.com/index", found_via="crawl")
    url_ev.id = uuid.uuid4()
    url_ev.distance = 1
    await m.handle_event(url_ev)

    # php (technology-aware) is fuzzed even though it isn't in the base list
    assert any(u == "https://x.com/index.php" for u in tested)


async def test_extfuzz_respects_total_budget():
    from events.types import EventType, UrlData

    ctrl = _mock_controller()
    m = _load_module(ctrl, extensions="bak,old,zip,sql,log",
                     strategies="append", calibration_probes=1,
                     max_candidates_total=2)

    calls: list[str] = []

    def fake_fetch(url, **kw):
        if "extfuzz-probe" not in url:
            calls.append(url)
        return FetchResult(url=url, status_code=404, text="n", ok=True)

    m.fetch = AsyncMock(side_effect=fake_fetch)

    ev = MagicMock()
    ev.type = EventType.URL
    ev.data = UrlData(url="https://x.com/app.js", found_via="crawl")
    ev.id = uuid.uuid4()
    ev.distance = 1
    await m.handle_event(ev)

    assert len(calls) <= 2                              # budget enforced
