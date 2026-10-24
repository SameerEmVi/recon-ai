"""
retire.js wrapper + module tests.

Pure parsing/command coverage (against retire's real JSON shape), module
behaviour (JS gating, body collection + dedup, one retire run at finish() →
TECHNOLOGY + FINDING_CANDIDATE), and one optional live-binary integration test
(skipped when `retire` isn't installed). No network in the unit tests.
"""

from __future__ import annotations

import json
import shutil
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from events.types import EventType, UrlData
from modules.registry import ModuleRegistry
from recon.fetch import FetchResult
from recon.retirejs import build_command, parse_retire_json

# A realistic retire --outputformat json report (shape captured from retire 6.1.0).
_REPORT = json.dumps({
    "version": "6.1.0",
    "data": [
        {
            "file": "/tmp/retirejs_x/0000.js",
            "results": [
                {
                    "version": "1.8.3",
                    "component": "jquery",
                    "detection": "filecontent",
                    "vulnerabilities": [
                        {
                            "info": ["https://nvd.nist.gov/vuln/detail/CVE-2012-6708"],
                            "below": "1.9.0b1",
                            "severity": "medium",
                            "identifiers": {"summary": "Selector interpreted as HTML",
                                            "CVE": ["CVE-2012-6708"]},
                            "cwe": ["CWE-79"],
                        },
                        {
                            "info": ["https://nvd.nist.gov/vuln/detail/CVE-2020-11022"],
                            "below": "3.5.0", "atOrAbove": "1.2.0",
                            "severity": "high",
                            "identifiers": {"summary": "XSS via htmlPrefilter",
                                            "CVE": ["CVE-2020-11022"]},
                        },
                    ],
                }
            ],
        }
    ],
})


# ── build_command (pure) ──────────────────────────────────────────────────────

def test_build_command():
    assert build_command("/tmp/d") == ["retire", "--path", "/tmp/d", "--outputformat", "json"]


def test_build_command_rejects_flag_like_path():
    with pytest.raises(ValueError):
        build_command("-rf")
    with pytest.raises(ValueError):
        build_command("")


# ── parse_retire_json (pure) ──────────────────────────────────────────────────

def test_parse_component_and_vulns():
    comps = parse_retire_json(_REPORT)
    assert len(comps) == 1
    c = comps[0]
    assert c.component == "jquery" and c.version == "1.8.3" and c.file == "0000.js"
    assert len(c.vulns) == 2
    assert c.vulns[0].cves == ("CVE-2012-6708",) and c.vulns[0].severity == "medium"
    assert c.vulns[1].cves == ("CVE-2020-11022",) and c.vulns[1].severity == "high"
    assert c.vulns[1].below == "3.5.0" and c.vulns[1].at_or_above == "1.2.0"


def test_parse_tolerates_noise_and_empty():
    assert parse_retire_json("npm notice blah\n" + _REPORT)[0].component == "jquery"
    assert parse_retire_json("") == []
    assert parse_retire_json("not json at all") == []


def test_parse_component_without_vulns_kept():
    doc = json.dumps({"data": [{"file": "a.js", "results": [
        {"component": "lodash", "version": "4.17.21", "vulnerabilities": []}]}]})
    comps = parse_retire_json(doc)
    assert comps[0].component == "lodash" and comps[0].vulns == ()


# ── module ────────────────────────────────────────────────────────────────────

def _ctrl():
    from ratelimit import NOOP
    c = MagicMock()
    c.scan_id = uuid.uuid4()
    c.rate_limiter = NOOP
    c.scan_domain = "t.com"
    c.stamp_and_publish = AsyncMock(return_value=True)
    return c


def _module(ctrl):
    ModuleRegistry.discover()
    return ModuleRegistry.load(names=["retirejs"], controller=ctrl)[0]


def _js_event(url="https://t.com/jquery.js", ctype="application/javascript"):
    ev = MagicMock()
    ev.data = UrlData(url=url, content_type=ctype)
    ev.id = uuid.uuid4()
    ev.distance = 2
    ev.type = EventType.URL
    return ev


async def test_module_skips_non_js():
    ctrl = _ctrl()
    m = _module(ctrl)
    with patch.object(m, "fetch", new=AsyncMock()) as fetch:
        await m.handle_event(_js_event("https://t.com/page.html", ctype="text/html"))
    fetch.assert_not_awaited()


async def test_module_collects_dedups_and_emits_at_finish():
    ctrl = _ctrl()
    m = _module(ctrl)
    js = FetchResult(url="https://t.com/jquery.js", status_code=200,
                     text="/*! jQuery v1.8.3 */", ok=True)

    with patch.object(m, "fetch", new=AsyncMock(return_value=js)):
        await m.handle_event(_js_event("https://t.com/jquery.js"))
        await m.handle_event(_js_event("https://t.com/jquery.js"))  # identical → deduped
    assert m._n == 1  # only one body collected

    # retire report references the file name the module wrote (0000.js).
    with patch.object(m, "run_proc", new=AsyncMock(return_value=_REPORT)):
        await m.finish()

    by_type: dict = {}
    for c in ctrl.stamp_and_publish.await_args_list:
        ev = c.args[0]
        by_type.setdefault(ev.type, []).append(ev.data)

    techs = by_type.get(EventType.TECHNOLOGY, [])
    assert any(t.name == "jquery" and t.version == "1.8.3" and t.source == "retire.js"
               for t in techs)
    findings = by_type.get(EventType.FINDING_CANDIDATE, [])
    assert len(findings) == 2
    cves = {f.evidence.get("cve") for f in findings}
    assert "CVE-2012-6708" in cves and "CVE-2020-11022" in cves
    for f in findings:
        assert f.category == "vuln:vulnerable-js-library"
        assert f.evidence["status"] == "POTENTIAL"      # never confirmed from a version
    sevs = {f.severity_hint for f in findings}
    assert sevs == {"medium", "high"}
    assert m._dir is None  # cleaned up


async def test_module_finish_noop_without_bodies():
    ctrl = _ctrl()
    m = _module(ctrl)
    with patch.object(m, "run_proc", new=AsyncMock()) as rp:
        await m.finish()
    rp.assert_not_awaited()
    ctrl.stamp_and_publish.assert_not_awaited()


def test_registry_and_classification():
    ModuleRegistry.discover()
    from modules.registry import FULL_MODULES
    from policy.policy import MODULE_CAPABILITIES
    assert "retirejs" in FULL_MODULES
    assert MODULE_CAPABILITIES["retirejs"] == frozenset(
        {"VULNERABILITY_CHECK", "TARGET_HTTP_REQUEST"})


# ── optional live integration (skipped without the binary) ────────────────────

@pytest.mark.skipif(shutil.which("retire") is None, reason="retire.js not installed")
def test_live_retire_parses_real_output(tmp_path):
    import subprocess
    (tmp_path / "jquery.js").write_text(
        '/*! jQuery v1.8.3 jquery.com */\nvar jQuery=function(){};'
        'jQuery.fn=jQuery.prototype={jquery:"1.8.3"};\n', encoding="utf-8")
    binary = shutil.which("retire")   # full path (retire.CMD on Windows)
    proc = subprocess.run(
        build_command(str(tmp_path), binary=binary),
        capture_output=True, text=True, timeout=180)
    comps = parse_retire_json(proc.stdout)
    jq = [c for c in comps if c.component == "jquery"]
    assert jq and jq[0].version == "1.8.3"
    assert any(v.cves for v in jq[0].vulns)   # at least one CVE-bearing advisory
