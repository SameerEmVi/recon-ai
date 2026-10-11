"""Tests for mode-based execution & the central capability policy (section 6)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from policy import (
    CAP_ACTIVE_DISCOVERY,
    CAP_FUZZING,
    CAP_INTRUSIVE_TEST,
    CAP_PASSIVE_EXTERNAL,
    CAP_PORT_SCANNING,
    CAP_TARGET_DNS_QUERY,
    CAP_TARGET_HTTP_REQUEST,
    CAP_VULNERABILITY_CHECK,
    CapabilityDenied,
    CapabilityPolicy,
    get_policy,
)
from policy.policy import ALLOW_ALL
from modules.registry import ModuleRegistry

# Representative modules by behaviour.
PASSIVE = ["subfinder", "crt_sh", "wayback", "cloud_intel", "censys", "gau"]
TARGET_HTTP = ["httpx_probe", "fingerprint", "metascan", "csprecon", "apifinder", "secretfinder"]
ACTIVE_DISC = ["dnsbrute", "puredns", "katana", "zonetransfer"]
FUZZERS = ["ffuf", "extfuzz"]
PORTS = ["naabu", "nmap"]
VULN = ["vulnassess", "nuclei", "corscanner"]


def _cls(name):
    return ModuleRegistry.get(name)


def _allowed(policy, names):
    return {n: policy.module_allowed(_cls(n))[0] for n in names}


# ── 1. osint never invokes active probing/brute/fuzz/port/vuln ────────────────

def test_osint_blocks_all_active_capabilities():
    pol = CapabilityPolicy("osint")
    assert pol.allows(CAP_PASSIVE_EXTERNAL)
    for cap in (CAP_TARGET_DNS_QUERY, CAP_TARGET_HTTP_REQUEST, CAP_ACTIVE_DISCOVERY,
                CAP_FUZZING, CAP_PORT_SCANNING, CAP_VULNERABILITY_CHECK, CAP_INTRUSIVE_TEST):
        assert not pol.allows(cap)
    # passive modules pass; every active/fuzz/port/vuln/dns module is rejected
    assert all(_allowed(pol, PASSIVE).values())
    for names in (TARGET_HTTP, ACTIVE_DISC, FUZZERS, PORTS, VULN, ["dnsx"]):
        assert not any(_allowed(pol, names).values()), names


def test_osint_default_module_set_is_passive_only():
    pol = CapabilityPolicy("osint")
    names = pol.default_module_names(ModuleRegistry.get)
    assert "subfinder" in names and "crt_sh" in names
    for bad in ("httpx_probe", "ffuf", "naabu", "nuclei", "vulnassess", "dnsx", "metascan"):
        assert bad not in names


# ── 2. active runs passive + active discovery + fuzzing + non-intrusive vuln ──

def test_active_allows_full_non_intrusive_pipeline():
    pol = CapabilityPolicy("active")
    for cap in (CAP_PASSIVE_EXTERNAL, CAP_TARGET_DNS_QUERY, CAP_TARGET_HTTP_REQUEST,
                CAP_ACTIVE_DISCOVERY, CAP_FUZZING, CAP_PORT_SCANNING, CAP_VULNERABILITY_CHECK):
        assert pol.allows(cap)
    assert not pol.allows(CAP_INTRUSIVE_TEST)        # intrusive off unless authorized
    for names in (PASSIVE, TARGET_HTTP, ACTIVE_DISC, FUZZERS, PORTS, VULN):
        assert all(_allowed(pol, names).values()), names


# ── 3. vuln runs the assessment without full discovery (no fuzz/port/brute) ───

def test_vuln_mode_minimal_discovery_plus_assessment():
    pol = CapabilityPolicy("vuln")
    assert pol.allows(CAP_VULNERABILITY_CHECK) and pol.allows(CAP_TARGET_HTTP_REQUEST)
    assert pol.allows(CAP_TARGET_DNS_QUERY)
    for cap in (CAP_FUZZING, CAP_PORT_SCANNING, CAP_ACTIVE_DISCOVERY):
        assert not pol.allows(cap)
    assert _allowed(pol, ["vulnassess", "httpx_probe", "dnsx", "corscanner"]) == {
        "vulnassess": True, "httpx_probe": True, "dnsx": True, "corscanner": True}
    assert not any(_allowed(pol, FUZZERS + PORTS + ACTIVE_DISC).values())
    names = pol.default_module_names(ModuleRegistry.get)
    assert "vulnassess" in names and "httpx_probe" in names
    assert "ffuf" not in names and "naabu" not in names and "dnsbrute" not in names


# ── 4. full executes all permitted stages (intrusive only when authorized) ────

def test_full_allows_everything_classified():
    pol = CapabilityPolicy("full")
    for names in (PASSIVE, TARGET_HTTP, ACTIVE_DISC, FUZZERS, PORTS, VULN, ["dnsx"]):
        assert all(_allowed(pol, names).values()), names
    assert not pol.allows(CAP_INTRUSIVE_TEST)
    pol_auth = CapabilityPolicy("full", intrusive_authorized=True)
    assert pol_auth.allows(CAP_INTRUSIVE_TEST)
    # intrusive authorization only unlocks in active/full
    assert not CapabilityPolicy("vuln", intrusive_authorized=True).allows(CAP_INTRUSIVE_TEST)
    assert not CapabilityPolicy("osint", intrusive_authorized=True).allows(CAP_INTRUSIVE_TEST)


# ── 5. AI recommendation / callback / fallback cannot bypass the mode ─────────

def test_agent_tool_registry_filtered_by_mode():
    from agent.tools import build_tool_registry
    osint = build_tool_registry(SimpleNamespace(policy=CapabilityPolicy("osint")))
    assert set(osint) == {"fetch_historical_urls"}      # only the passive tool
    active = build_tool_registry(SimpleNamespace(policy=CapabilityPolicy("active")))
    assert {"probe_url", "nuclei_info", "fetch_historical_urls"} <= set(active)


async def test_agent_tool_refuses_at_call_time_under_osint():
    from agent.tools import ProbeUrlTool, NucleiInfoTool
    ctrl = SimpleNamespace(policy=CapabilityPolicy("osint"))
    res = await ProbeUrlTool(ctrl).run("https://x.com", uuid.uuid4())
    assert res.new_events == 0 and "capability denied" in res.summary
    res2 = await NucleiInfoTool(ctrl).run("https://x.com", uuid.uuid4())
    assert "capability denied" in res2.summary


async def test_basemodule_fetch_denied_in_osint():
    # A passive module that tries a direct target fetch (e.g. a "fallback" to
    # validate a discovered URL) is blocked by the runtime gate — proof the
    # fetch primitive itself enforces the mode (sections 5 & 8).
    from modules.web.secretfinder import SecretFinderModule
    ctrl = SimpleNamespace(policy=CapabilityPolicy("osint"), scan_id=uuid.uuid4(), name="x")
    m = SecretFinderModule(ctrl)
    res = await m.fetch("https://target.example/app.js")
    assert res.ok is False and "capability denied" in (res.error or "")


async def test_basemodule_fetch_allowed_in_active_uses_cache_path(monkeypatch):
    # In active mode the gate passes; with no real response_cache it falls through
    # to a direct fetch (which we stub) — proving the gate doesn't block active.
    from modules.web.secretfinder import SecretFinderModule
    import httpx

    class _Resp:
        status_code = 200; content = b"hi"; text = "hi"
        headers = {"content-type": "text/plain"}

    class _Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k): return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _Client())
    ctrl = SimpleNamespace(policy=CapabilityPolicy("active"), scan_id=uuid.uuid4(), name="x")
    m = SecretFinderModule(ctrl)
    res = await m.fetch("https://target.example/app.js")
    assert res.ok is True and res.status_code == 200


# ── 6. out-of-scope remains blocked in EVERY mode ─────────────────────────────

@pytest.mark.parametrize("mode", ["osint", "vuln", "active", "full"])
async def test_scope_still_enforced_in_every_mode(mode):
    from controller.controller import ScanController
    from events.types import Event, EventType, SubdomainData
    from scope.types import Scope

    scope = Scope.from_strings(in_scope=["x.com", "*.x.com"], out_scope=[], max_distance=5)
    ctrl = ScanController(scope, mode=mode, results_enabled=False, live=False)

    out = Event.create(EventType.SUBDOMAIN, SubdomainData(hostname="evil.com", source="t"),
                       scan_job_id=ctrl.scan_id, source_tool="t", distance=1)
    assert await ctrl.stamp_and_publish(out) is False      # out-of-scope dropped

    good = Event.create(EventType.SUBDOMAIN, SubdomainData(hostname="api.x.com", source="t"),
                        scan_job_id=ctrl.scan_id, source_tool="t", distance=1)
    assert await ctrl.stamp_and_publish(good) is True       # in-scope accepted


# ── 7. core services (limiter, cache, policy, dedup) still wired in each mode ─

@pytest.mark.parametrize("mode", ["osint", "vuln", "active", "full"])
def test_core_services_present_in_every_mode(mode):
    from controller.controller import ScanController
    from ratelimit import RateLimiter
    from recon.fetch import ResponseCache
    from scope.types import Scope

    scope = Scope.from_strings(in_scope=["x.com"], out_scope=[])
    ctrl = ScanController(scope, mode=mode, results_enabled=False)
    assert isinstance(ctrl.rate_limiter, RateLimiter)
    assert isinstance(ctrl.response_cache, ResponseCache)
    assert isinstance(ctrl.policy, CapabilityPolicy) and ctrl.policy.mode == mode


def test_get_policy_test_safety_fallback():
    # A mock/mapless controller yields ALLOW_ALL (so unit tests aren't gated).
    assert get_policy(SimpleNamespace()) is ALLOW_ALL
    assert get_policy(SimpleNamespace(policy=CapabilityPolicy("osint"))).mode == "osint"


# ── central module filtering (strict, before setup) ──────────────────────────

async def test_controller_drops_active_modules_in_osint():
    from controller.controller import ScanController
    from scope.types import Scope

    scope = Scope.from_strings(in_scope=["x.com", "*.x.com"], out_scope=[])
    ctrl = ScanController(
        scope, mode="osint", results_enabled=False, live=False,
        enabled_modules=["crt_sh", "httpx_probe", "ffuf", "vulnassess", "dnsx"],
    )
    seed, reactive = await ctrl._load_and_setup_modules()
    loaded = {m.name for m in seed + reactive}
    disabled = {n for n, _ in ctrl._disabled_modules}
    assert "crt_sh" in loaded                      # passive survives
    assert {"httpx_probe", "ffuf", "vulnassess", "dnsx"} <= disabled
    assert not ({"httpx_probe", "ffuf", "vulnassess", "dnsx"} & loaded)


async def test_controller_keeps_active_modules_in_active_mode():
    from controller.controller import ScanController
    from scope.types import Scope

    scope = Scope.from_strings(in_scope=["x.com", "*.x.com"], out_scope=[])
    ctrl = ScanController(
        scope, mode="active", results_enabled=False, live=False,
        enabled_modules=["crt_sh", "httpx_probe", "vulnassess"],
    )
    await ctrl._load_and_setup_modules()
    # policy disabled none of them (setup() may still skip on missing binaries,
    # but that is not a policy decision)
    assert ctrl._disabled_modules == []


# ── 9. invalid mode / missing permission fail safely ──────────────────────────

def test_invalid_mode_fails_closed():
    with pytest.raises(CapabilityDenied):
        CapabilityPolicy("super-aggressive")


def test_check_raises_on_disallowed_capability():
    pol = CapabilityPolicy("osint")
    with pytest.raises(CapabilityDenied):
        pol.check(CAP_TARGET_HTTP_REQUEST, who="test")
    pol.check(CAP_PASSIVE_EXTERNAL)   # allowed → no raise


def test_unclassified_module_fail_closed_except_full():
    class Mystery:
        name = "mystery-new-module"
        capabilities: list = []
    assert CapabilityPolicy("osint").module_allowed(Mystery)[0] is False
    assert CapabilityPolicy("active").module_allowed(Mystery)[0] is False
    ok, reason = CapabilityPolicy("full").module_allowed(Mystery)
    assert ok is True and "unclassified" in reason


def test_explicit_classvar_overrides_table():
    # subfinder is flagged "active" but declares PASSIVE_EXTERNAL → allowed in osint.
    assert CapabilityPolicy("osint").module_allowed(_cls("subfinder"))[0] is True
