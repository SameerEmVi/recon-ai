"""Three execution tiers (osint → recon → pentest) + legacy mode aliases."""

from __future__ import annotations

import pytest

from modules.registry import FULL_MODULES, ModuleRegistry, _registry
from policy import (
    LEGACY_MODES,
    MODES,
    TIER_CAPS,
    TIERS,
    CapabilityDenied,
    CapabilityPolicy,
    intrusive_capable,
    resolve_mode,
    tier_of_caps,
    tier_unlocked,
)
from policy.policy import (
    CAP_FUZZING,
    CAP_INTRUSIVE_TEST,
    CAP_PASSIVE_EXTERNAL,
    CAP_PORT_SCANNING,
    CAP_TARGET_DNS_QUERY,
    CAP_TARGET_HTTP_REQUEST,
    CAP_VULNERABILITY_CHECK,
)

ModuleRegistry.discover()


def _cls(name):
    return _registry[name]


# ── tier ceilings ───────────────────────────────────────────────────────────────

def test_tiers_are_ordered_and_nested():
    assert TIERS == ("osint", "recon", "pentest")
    assert TIER_CAPS["osint"] < TIER_CAPS["recon"] < TIER_CAPS["pentest"]
    assert TIER_CAPS["osint"] == {CAP_PASSIVE_EXTERNAL}
    assert TIER_CAPS["pentest"] - TIER_CAPS["recon"] == {CAP_VULNERABILITY_CHECK}
    for caps in TIER_CAPS.values():
        assert CAP_INTRUSIVE_TEST not in caps      # never part of a base ceiling


def test_recon_is_discovery_without_vulnerability_checks():
    pol = CapabilityPolicy("recon")
    for cap in (CAP_TARGET_DNS_QUERY, CAP_TARGET_HTTP_REQUEST, CAP_FUZZING, CAP_PORT_SCANNING):
        assert pol.allows(cap)
    assert not pol.allows(CAP_VULNERABILITY_CHECK)
    for name in ("dnsx", "httpx_probe", "ffuf", "katana", "rustscan", "nmap"):
        assert pol.module_allowed(_cls(name))[0], name
    for name in ("vulnassess", "nuclei", "retirejs", "corscanner", "bypass403", "takeover"):
        ok, reason = pol.module_allowed(_cls(name))
        assert not ok and "VULNERABILITY_CHECK" in reason, name


def test_intrusive_unlocks_only_on_pentest():
    assert CapabilityPolicy("pentest", intrusive_authorized=True).allows(CAP_INTRUSIVE_TEST)
    assert not CapabilityPolicy("pentest").allows(CAP_INTRUSIVE_TEST)
    for mode in ("osint", "recon", "vuln"):
        assert not CapabilityPolicy(mode, intrusive_authorized=True).allows(CAP_INTRUSIVE_TEST)
    assert intrusive_capable("pentest") and not intrusive_capable("recon")


# ── legacy aliases ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("legacy", ["active", "full"])
def test_active_and_full_are_pentest(legacy):
    tier, note = resolve_mode(legacy)
    assert tier == "pentest" and "deprecated" in note
    pol = CapabilityPolicy(legacy)
    assert pol.mode == "pentest" and pol.deprecation
    assert pol.allowed_capabilities == CapabilityPolicy("pentest").allowed_capabilities
    assert CapabilityPolicy(legacy, intrusive_authorized=True).allows(CAP_INTRUSIVE_TEST)


def test_vuln_keeps_its_narrow_legacy_ceiling():
    # Never silently widened to pentest: no fuzzing / port scanning / discovery.
    tier, note = resolve_mode("vuln")
    assert tier == "vuln" and "deprecated" in note
    pol = CapabilityPolicy("vuln")
    assert pol.allows(CAP_VULNERABILITY_CHECK)
    assert not pol.allows(CAP_FUZZING) and not pol.allows(CAP_PORT_SCANNING)


def test_every_accepted_mode_resolves_and_unknown_fails_closed():
    assert MODES == TIERS + LEGACY_MODES
    for m in MODES:
        assert resolve_mode(m)[0] in TIERS + ("vuln",)
    for bad in ("aggressive", "", "PENTEST", "intrusive"):
        with pytest.raises(CapabilityDenied):
            CapabilityPolicy(bad)


# ── module tiers ────────────────────────────────────────────────────────────────

def test_tier_of_caps():
    assert tier_of_caps(frozenset({CAP_PASSIVE_EXTERNAL})) == "osint"
    assert tier_of_caps(frozenset({CAP_TARGET_DNS_QUERY})) == "recon"
    assert tier_of_caps(frozenset({CAP_FUZZING, CAP_TARGET_HTTP_REQUEST})) == "recon"
    assert tier_of_caps(frozenset({CAP_VULNERABILITY_CHECK, CAP_TARGET_HTTP_REQUEST})) == "pentest"
    # Intrusive is unlocked on top of pentest — never a lower tier.
    assert tier_of_caps(frozenset({CAP_INTRUSIVE_TEST})) == "pentest"
    assert tier_of_caps(frozenset({CAP_INTRUSIVE_TEST, CAP_PASSIVE_EXTERNAL})) == "pentest"
    assert tier_of_caps(None) is None and tier_of_caps(frozenset()) is None


def test_every_registered_module_has_a_minimal_tier():
    """Each module runs in its own tier and is blocked in the tier below it — the
    tier is exactly 'the lowest tier that may run it', for all 53 modules."""
    assert _registry, "no modules discovered"
    for name, cls in _registry.items():
        tier = CapabilityPolicy.module_tier(cls)
        assert tier in TIERS, name
        assert CapabilityPolicy(tier).module_allowed(cls)[0], f"{name} blocked in its own tier"
        idx = TIERS.index(tier)
        if idx:
            below = TIERS[idx - 1]
            assert not CapabilityPolicy(below).module_allowed(cls)[0], f"{name} also runs in {below}"


def test_known_module_tiers():
    expect = {"subfinder": "osint", "crt_sh": "osint", "wayback": "osint",
              "dnsx": "recon", "ffuf": "recon", "metascan": "recon", "csprecon": "recon",
              "nuclei": "pentest", "vulnassess": "pentest", "retirejs": "pentest"}
    for name, tier in expect.items():
        assert CapabilityPolicy.module_tier(_cls(name)) == tier, name


def test_default_module_sets_respect_tiers():
    get = ModuleRegistry.get
    osint = CapabilityPolicy("osint").default_module_names(get)
    recon = CapabilityPolicy("recon").default_module_names(get)
    pentest = CapabilityPolicy("pentest").default_module_names(get)
    assert pentest == list(FULL_MODULES)
    assert "ffuf" in recon and "katana" in recon and "nuclei" not in recon
    assert all(CapabilityPolicy.module_tier(get(n)) in ("osint", "recon") for n in recon)
    assert all(CapabilityPolicy.module_tier(get(n)) == "osint" for n in osint)


def test_tier_unlocked():
    assert tier_unlocked("osint", "osint") and not tier_unlocked("osint", "recon")
    assert tier_unlocked("recon", "recon") and not tier_unlocked("recon", "pentest")
    assert all(tier_unlocked("pentest", t) for t in TIERS)
    assert tier_unlocked("vuln", "pentest") and tier_unlocked("vuln", "recon")
    assert all(tier_unlocked(None, t) for t in TIERS)   # unknown: never claim locked


# ── CLI: `recon-ai osint|recon|pentest` == `scan --mode <tier>` ────────────────────

def test_tier_subcommands_mirror_scan_options():
    import inspect

    import cli.main as cli

    scan_params = [p for p in inspect.signature(cli.scan).parameters if p != "mode"]
    for tier in TIERS:
        cmd = next(c.callback for c in cli.app.registered_commands if c.name == tier)
        assert list(inspect.signature(cmd).parameters) == scan_params
        assert "mode" not in inspect.signature(cmd).parameters


@pytest.mark.parametrize("tier", TIERS)
def test_tier_subcommand_runs_scan_with_its_tier(tier, monkeypatch):
    from typer.testing import CliRunner

    import cli.main as cli

    seen = {}
    monkeypatch.setattr(cli, "scan", lambda **kw: seen.update(kw))
    res = CliRunner().invoke(cli.app, [tier, "example.com", "-r", "5"])
    assert res.exit_code == 0, res.output
    assert seen["mode"] == tier and seen["domain"] == "example.com"
    assert seen["rate_limit"] == 5.0


# ── API schema ──────────────────────────────────────────────────────────────────

def test_scan_create_accepts_tiers_and_legacy_names():
    from pydantic import ValidationError

    from api.schemas import ScanCreate

    assert ScanCreate(domain="x.com").mode == "pentest"     # same ceiling as the old default
    for m in MODES:
        assert ScanCreate(domain="x.com", mode=m).mode == m
    with pytest.raises(ValidationError):
        ScanCreate(domain="x.com", mode="aggressive")
