"""Unit + integration tests for the vulnscan vulnerability-assessment layer."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from recon.fetch import FetchResult
from vulnscan import cve
from vulnscan.checks import (
    CheckContext,
    CookieSecurityCheck,
    ExposedInterfaceCheck,
    InfoDisclosureCheck,
    ReflectedInputCheck,
    SecurityHeadersCheck,
    VersionCveCheck,
    select_checks,
)
from vulnscan.engine import AssessmentEngine, AssessmentState
from vulnscan.report import build_report, render_json, render_text, result_from_finding
from vulnscan.schema import Severity, Status, VulnResult


# ── schema ──────────────────────────────────────────────────────────────────

def _vr(**kw):
    base = dict(asset="x.com", check_id="c", check_name="C", category="cat",
                status=Status.OBSERVED, severity=Severity.LOW, confidence=0.5,
                detection_method="test", evidence={"a": "b"})
    base.update(kw)
    return VulnResult(**base)


def test_vulnresult_requires_evidence():
    with pytest.raises(ValueError):
        _vr(evidence={})


def test_vulnresult_validates_status_and_severity():
    with pytest.raises(ValueError):
        _vr(status="MADE_UP")
    with pytest.raises(ValueError):
        _vr(severity="apocalyptic")


def test_vulnresult_clamps_confidence_and_dedup_key():
    assert _vr(confidence=5.0).confidence == 1.0
    assert _vr(confidence=-1).confidence == 0.0
    r = _vr(url="https://x.com/a")
    assert r.dedup_key == "x.com|c|https://x.com/a"


def test_to_finding_data_projection():
    r = _vr(check_id="known-cve", url="https://x.com/a", references=["CVE-1", "CWE-2"],
            remediation="patch it")
    d = r.to_finding_data()
    assert d.category == "vuln:known-cve"
    assert d.evidence["check_id"] == "known-cve"
    assert d.evidence["status"] == Status.OBSERVED
    assert "https://x.com/a" in d.title  # title discriminates by url (dedup)


# ── cve correlation (uncertainty-aware) ───────────────────────────────────────

def test_parse_and_compare_versions_tolerant():
    assert cve.parse_version("v3.4.1") == (3, 4, 1)
    assert cve.parse_version("1.25.0-ubuntu4") == (1, 25, 0)
    assert cve.parse_version("notaversion") == ()
    assert cve.version_le("3.4.1", "3.4.1") is True
    assert cve.version_le("3.5.0", "3.4.1") is False
    assert cve.version_le("3.4.1", "") is False      # unparseable → False, not a match


def test_correlate_vulnerable_version_is_potential_never_confirmed():
    matches = cve.correlate("jquery", "3.4.1")
    assert matches and all(m.status in ("POTENTIAL", "UNCONFIRMED") for m in matches)
    assert all(m.status != "CONFIRMED" for m in matches)
    assert any(m.vuln.cve == "CVE-2020-11022" for m in matches)


def test_correlate_patched_version_no_match():
    assert cve.correlate("jquery", "3.6.0") == []


def test_correlate_no_version_refuses_to_claim():
    assert cve.correlate("jquery", None) == []
    assert cve.correlate("jquery", "") == []


def test_correlate_uncertain_fingerprint_downgrades():
    matches = cve.correlate("jquery", "3.4.1", fingerprint_certain=False)
    assert matches and all(m.status == "UNCONFIRMED" for m in matches)
    assert all(m.confidence < 0.5 for m in matches)


# ── check selection (technology-aware + tier gating) ──────────────────────────

def _ctx(**kw):
    c = CheckContext("x.com", fetch=kw.pop("fetch", None),
                     active_enabled=kw.pop("active", True),
                     intrusive_enabled=kw.pop("intrusive", False))
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_known_cve_only_when_versioned_tech_present():
    chk = VersionCveCheck()
    assert chk.applies(_ctx(technologies={"jquery": "3.4.1"}))
    assert not chk.applies(_ctx(technologies={"jquery": None}))
    assert not chk.applies(_ctx(technologies={}))


def test_tier_gating_excludes_active_when_disabled():
    ctx = _ctx(services=[{"url": "https://x.com/", "status": 200}])
    sel, skipped = select_checks(ctx, active=False, intrusive=False)
    ids = {c.id for c in sel}
    assert "security-headers" not in ids           # active tier disabled
    skip_ids = {cid for cid, _ in skipped}
    assert "security-headers" in skip_ids
    sel2, _ = select_checks(ctx, active=True, intrusive=False)
    assert "security-headers" in {c.id for c in sel2}


def test_api_check_applies_only_with_api_surface():
    from vulnscan.checks import ApiExposureCheck
    assert ApiExposureCheck().applies(_ctx(urls={"https://x.com/api/v1/users"}))
    assert not ApiExposureCheck().applies(_ctx(urls={"https://x.com/about"}))


# ── individual checks ──────────────────────────────────────────────────────────

async def test_security_headers_detects_missing():
    chk = SecurityHeadersCheck()
    ctx = _ctx(services=[{"url": "https://x.com/"}])
    ctx.headers = {"https://x.com/": {"content-type": "text/html"}}  # all hardening headers absent
    res = await chk.run(ctx)
    assert res and res[0].status == Status.OBSERVED
    assert "Content-Security-Policy" in res[0].evidence["missing"]

    ctx2 = _ctx(services=[{"url": "https://x.com/"}])
    ctx2.headers = {"https://x.com/": {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }}
    assert await chk.run(ctx2) == []                # fully hardened → no result


async def test_cookie_security_flags_missing_attrs_names_only():
    chk = CookieSecurityCheck()
    ctx = _ctx(services=[{"url": "https://x.com/"}])
    ctx.set_cookies = {"https://x.com/": ["SESSIONID=abc123secretvalue; Path=/"]}
    res = await chk.run(ctx)
    assert res
    ev = res[0].evidence["cookies"]
    assert "SESSIONID" in ev and "Secure" in ev and "HttpOnly" in ev
    assert "abc123secretvalue" not in ev            # never leak cookie values


async def test_info_disclosure_requires_version_in_header():
    chk = InfoDisclosureCheck()
    ctx = _ctx(services=[{"url": "https://x.com/"}])
    ctx.headers = {"https://x.com/": {"server": "nginx/1.25.0", "x-powered-by": "PHP/8.1.2"}}
    res = await chk.run(ctx)
    assert res and res[0].status == Status.OBSERVED

    ctx2 = _ctx(services=[{"url": "https://x.com/"}])
    ctx2.headers = {"https://x.com/": {"server": "nginx"}}   # no version → not interesting
    assert await chk.run(ctx2) == []


async def test_exposed_interface_reachability_and_protection():
    chk = ExposedInterfaceCheck()
    # reachable admin → medium
    ctx = _ctx(services=[{"url": "https://x.com/admin", "status": 200}])
    ctx.urls = {"https://x.com/admin"}
    res = await chk.run(ctx)
    assert res and res[0].severity == Severity.MEDIUM

    # 404 admin → not reachable → dropped
    ctx2 = _ctx(services=[{"url": "https://x.com/admin", "status": 404}])
    ctx2.urls = {"https://x.com/admin"}
    assert await chk.run(ctx2) == []

    # 403 admin → protected → low
    ctx3 = _ctx(services=[{"url": "https://x.com/admin", "status": 403}])
    ctx3.urls = {"https://x.com/admin"}
    res3 = await chk.run(ctx3)
    assert res3 and res3[0].severity == Severity.LOW


async def test_exposed_interface_no_substring_false_positives():
    chk = ExposedInterfaceCheck()
    # "manage" must NOT match "managed-..." (the amaru.co.nz false positive).
    ctx = _ctx(services=[{"url": "https://x.com/services/managed-security-training/",
                          "status": 200}])
    ctx.urls = {"https://x.com/services/managed-security-training/"}
    assert await chk.run(ctx) == []

    # A static asset with an 'admin' dir in its path is not an interface.
    ctx2 = _ctx(services=[{"url": "https://x.com/themes/divi/core/admin/js/common.js",
                           "status": 200}])
    ctx2.urls = {"https://x.com/themes/divi/core/admin/js/common.js"}
    assert await chk.run(ctx2) == []

    # Real wp-admin is still caught.
    ctx3 = _ctx(services=[{"url": "https://x.com/wp-admin/", "status": 200}])
    ctx3.urls = {"https://x.com/wp-admin/"}
    assert await chk.run(ctx3)


async def test_exposed_interface_unprobed_is_potential_not_observed():
    chk = ExposedInterfaceCheck()
    # /admin known only as a URL (never probed → status None): a POTENTIAL lead,
    # NOT an OBSERVED "reachable" claim.
    ctx = _ctx()
    ctx.urls = {"https://x.com/admin"}
    res = await chk.run(ctx)
    assert res and res[0].status == Status.POTENTIAL
    assert res[0].confidence == 0.4
    # Wording must not claim reachability we never checked.
    assert "reachability was not probed" in res[0].severity_rationale.lower()
    assert res[0].evidence["http_status"] == "unprobed"


async def test_version_cve_check_potential_only():
    chk = VersionCveCheck()
    ctx = _ctx(technologies={"jquery": "3.4.1"})
    res = await chk.run(ctx)
    assert res and all(r.status in (Status.POTENTIAL, Status.UNCONFIRMED) for r in res)
    assert all(r.status != Status.CONFIRMED for r in res)   # never confirmed on version alone
    assert any("CVE-2020-11022" in r.references for r in res)

    # patched version → nothing
    assert await chk.run(_ctx(technologies={"jquery": "3.6.0"})) == []


async def test_reflected_input_benign_canary():
    chk = ReflectedInputCheck()

    async def fetch(url):
        # reflect whatever canary we were given
        token = url.split("q=")[-1]
        return FetchResult(url=url, ok=True, status_code=200, text=f"you said {token}")

    ctx = _ctx(fetch=fetch, params={"https://x.com/s": {"q"}})
    res = await chk.run(ctx)
    assert res and res[0].status == Status.POTENTIAL
    assert "q" in res[0].evidence["reflected_params"]

    # no reflection → no result
    async def no_reflect(url):
        return FetchResult(url=url, ok=True, status_code=200, text="static page")
    ctx2 = _ctx(fetch=no_reflect, params={"https://x.com/s": {"q"}})
    assert await chk.run(ctx2) == []


# ── engine: dedup, isolation, emit flag ───────────────────────────────────────

async def test_engine_dedup_keeps_strongest():
    eng = AssessmentEngine()
    weak = _vr(severity=Severity.LOW, confidence=0.4, url="https://x.com/a")
    strong = _vr(severity=Severity.HIGH, confidence=0.9, url="https://x.com/a")
    out = eng._dedup([weak, strong])
    assert len(out) == 1 and out[0].severity == Severity.HIGH


async def test_engine_isolates_failing_check(monkeypatch):
    from vulnscan import checks

    class Boom(checks.Check):
        id = "boom"; name = "boom"; category = "x"; tier = "passive"
        async def run(self, ctx):
            raise RuntimeError("kaboom")

    checks._CHECKS["boom"] = Boom()
    try:
        st = AssessmentState()
        st.observe(_ev("TECHNOLOGY", SimpleNamespace(host="x.com", name="jquery", version="3.4.1")))
        ctxs = st.build_contexts(active=False, intrusive=False)
        out = await AssessmentEngine(active=False).assess(ctxs)
        assert "boom" in out.failed                 # failure captured, not raised
        assert any(r.check_id == "known-cve" for r in out.results)  # others still ran
    finally:
        checks._CHECKS.pop("boom", None)


# ── consume/normalize existing findings (report-only, not re-emitted) ──────────

async def test_normalize_existing_findings_not_re_emitted():
    st = AssessmentState()
    st.observe(_ev("FINDING_CANDIDATE", SimpleNamespace(
        host="x.com", title="Backup: /db.sql.bak", category="exposed-file:backup",
        severity_hint="medium", evidence={"confidence": 0.9}, description="backup file"),
        tool="extfuzz"))
    st.observe(_ev("FINDING_CANDIDATE", SimpleNamespace(
        host="x.com", title="CORS", category="cors", severity_hint="high",
        evidence={"url": "https://x.com/"}, description="reflected origin"), tool="corscanner"))
    ctxs = st.build_contexts(active=False, intrusive=False)
    out = await AssessmentEngine(active=False).assess(ctxs)
    normalized = [r for r in out.results if r.check_id == "normalize-existing"]
    assert normalized
    assert all(not r.emit for r in normalized)      # never re-emitted
    statuses = {r.status for r in normalized}
    assert Status.CONFIRMED in statuses             # exposed-file conf>=0.85 → CONFIRMED
    assert out.emitted == [r for r in out.results if r.emit]
    assert all(r.emit for r in out.emitted)


# ── report generation ──────────────────────────────────────────────────────────

def test_build_and_render_report():
    results = [
        _vr(check_id="known-cve", severity=Severity.HIGH, status=Status.POTENTIAL,
            url="https://x.com/a", references=["CVE-1"], remediation="upgrade"),
        _vr(check_id="security-headers", severity=Severity.LOW, status=Status.OBSERVED,
            url="https://x.com/"),
    ]
    outcome = SimpleNamespace(executed={"known-cve", "security-headers"},
                              skipped={"api-exposure": "not applicable"}, failed={})
    rep = build_report("x.com", results, outcome=outcome, scan_id="sid")
    assert rep["summary"]["total"] == 2
    assert rep["summary"]["by_severity"]["high"] == 1
    assert rep["coverage"]["checks_skipped"] == {"api-exposure": "not applicable"}
    # JSON round-trips
    parsed = json.loads(render_json(rep))
    assert parsed["target"] == "x.com"
    # text has the required sections
    text = "\n".join(render_text(rep))
    for section in ("Executive summary", "Findings", "Assets affected", "Coverage", "Limitations"):
        assert section in text


def test_result_from_finding_round_trip():
    r = _vr(check_id="known-cve", severity=Severity.MEDIUM, status=Status.POTENTIAL,
            url="https://x.com/a", references=["CVE-1", "CWE-2"], remediation="upgrade")
    fd = r.to_finding_data()
    persisted = {
        "host": fd.host, "title": fd.title, "description": fd.description,
        "category": fd.category, "severity_hint": fd.severity_hint, "evidence": fd.evidence,
    }
    back = result_from_finding(persisted)
    assert back is not None
    assert back.check_id == "known-cve"
    assert back.status == Status.POTENTIAL
    assert "CVE-1" in back.references


# ── module integration ──────────────────────────────────────────────────────────

def _ev(etype, data, tool="mod"):
    return SimpleNamespace(
        type=SimpleNamespace(value=etype), data=data, source_tool=tool, id=uuid.uuid4())


def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.scan_domain = "x.com"
    ctrl.aggregator = None
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def _load(ctrl, **cfg):
    from modules.registry import ModuleRegistry
    m = ModuleRegistry.load(names=["vulnassess"], controller=ctrl)[0]
    m._config.update(cfg)
    return m


def test_vulnassess_registered():
    from modules.registry import ASSESS_MODULES, FULL_MODULES
    assert "vulnassess" in ASSESS_MODULES and "vulnassess" in FULL_MODULES
    ctrl = _mock_controller()
    m = _load(ctrl)
    assert "FINDING_CANDIDATE" in m.watched_events
    assert m.deps_binary == []


async def test_vulnassess_emits_structured_findings_via_chokepoint():
    from events.types import EventType

    ctrl = _mock_controller()
    m = _load(ctrl, active_checks=True)

    # feed recon events
    await m.handle_event(_ev("TECHNOLOGY", SimpleNamespace(host="x.com", name="jquery", version="3.4.1")))
    await m.handle_event(_ev("HTTP_SERVICE", SimpleNamespace(
        url="https://x.com/", status_code=200, title="Home", server="nginx", technologies=[])))
    await m.handle_event(_ev("URL", SimpleNamespace(url="https://x.com/admin", content_type=None)))

    # active header probe returns a response with no hardening headers
    m.fetch = AsyncMock(return_value=FetchResult(
        url="https://x.com/", ok=True, status_code=200, text="<html>home</html>",
        headers={"server": "nginx/1.25.0"}, content_type="text/html"))

    await m.finish()

    published = [c[0][0] for c in ctrl.stamp_and_publish.call_args_list]
    cats = {e.data.category for e in published}
    assert "vuln:known-cve" in cats                 # version→CVE (POTENTIAL)
    assert "vuln:security-headers" in cats          # active header check ran via self.fetch
    assert "vuln:exposed-interface" in cats         # /admin reachable
    # every emitted event is a scope-gated FINDING_CANDIDATE through the chokepoint
    assert all(e.type is EventType.FINDING_CANDIDATE for e in published)
    assert m.fetch.await_count >= 1                  # active checks used the shared fetch


async def test_vulnassess_does_not_reobserve_own_findings():
    ctrl = _mock_controller()
    m = _load(ctrl)
    before = len(m._state.hosts)
    await m.handle_event(_ev("FINDING_CANDIDATE", SimpleNamespace(
        host="x.com", title="vuln", category="vuln:known-cve",
        severity_hint="high", evidence={}, description="x"), tool="vulnassess"))
    assert len(m._state.hosts) == before            # own finding ignored


async def test_vulnassess_out_of_scope_emission_is_safe():
    ctrl = _mock_controller()
    ctrl.stamp_and_publish = AsyncMock(return_value=False)   # scope gate denies everything
    m = _load(ctrl, active_checks=False)
    await m.handle_event(_ev("TECHNOLOGY", SimpleNamespace(host="x.com", name="jquery", version="3.4.1")))
    await m.finish()                                 # must not raise even when all denied
