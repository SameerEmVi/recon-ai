"""
Tests for the Adaptive Reconnaissance Planner (planner.ReconPlanner).

Covers: cost/value model, technology-conditional activation, passive-first and
aggressive modes, execution budgets, per-host loop prevention, prerequisites,
seed gating, and explainability. Also asserts the planner never touches scope or
rate limiting (it only gates dispatch).
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from events.types import (
    Event,
    EventType,
    HttpServiceData,
    TechnologyData,
    UrlData,
)
from planner import (
    COST_HIGH,
    COST_LOW,
    COST_MEDIUM,
    MODE_AGGRESSIVE,
    MODE_DEFAULT,
    MODE_PASSIVE_FIRST,
    PlannerConfig,
    ReconPlanner,
    VALUE_HIGH,
)

SCAN = uuid.uuid4()


# ── helpers ────────────────────────────────────────────────────────────────

def mod(name, *, flags=(), techs=(), prereqs=(), cost=None, value=None):
    return SimpleNamespace(
        name=name,
        flags=list(flags),
        supported_technologies=list(techs),
        prerequisites=list(prereqs),
        estimated_cost=cost,
        expected_value=value,
    )


def tech_event(host, name):
    return Event.create(EventType.TECHNOLOGY, TechnologyData(host=host, name=name),
                        scan_job_id=SCAN, source_tool="fingerprint")


def http_event(url, status=200):
    return Event.create(EventType.HTTP_SERVICE, HttpServiceData(url=url, status_code=status),
                        scan_job_id=SCAN, source_tool="httpx_probe")


def url_event(url):
    return Event.create(EventType.URL, UrlData(url=url, found_via="katana"),
                        scan_job_id=SCAN, source_tool="katana")


# ── cost / value model ───────────────────────────────────────────────────────

def test_cost_derived_from_flags():
    assert ReconPlanner.cost_of(mod("a", flags=["slow", "active"])) == COST_HIGH
    assert ReconPlanner.cost_of(mod("b", flags=["passive"])) == COST_LOW
    assert ReconPlanner.cost_of(mod("c", flags=["active", "web"])) == COST_MEDIUM


def test_explicit_cost_overrides_flags():
    assert ReconPlanner.cost_of(mod("a", flags=["passive"], cost=COST_HIGH)) == COST_HIGH


def test_value_tech_match_boosts():
    m = mod("x")
    assert ReconPlanner.value_of(m, tech_matched=True) == VALUE_HIGH
    assert ReconPlanner.value_of(m, tech_matched=False) < VALUE_HIGH


# ── technology-conditional activation (the core spec example) ────────────────

def test_tech_module_skipped_without_technology():
    p = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    graphql = mod("graphql", flags=["active", "web"], techs=["GraphQL"])
    dec = p.evaluate(graphql, http_event("https://api.x.com/"))
    assert dec.run is False
    assert "supported technology" in dec.reason


def test_tech_module_activated_after_technology_discovered():
    p = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    graphql = mod("graphql", flags=["active", "web"], techs=["GraphQL"])

    # HTTP service detected → inspect technology → technology = GraphQL …
    p.observe(tech_event("api.x.com", "GraphQL"))
    # … → activate GraphQL module
    dec = p.evaluate(graphql, http_event("https://api.x.com/"))
    assert dec.run is True
    assert "graphql" in dec.reason.lower()          # explainability


def test_tech_match_is_scoped_per_host():
    p = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    graphql = mod("graphql", flags=["active"], techs=["GraphQL"])
    p.observe(tech_event("api.x.com", "GraphQL"))
    # different host → no match
    assert p.evaluate(graphql, http_event("https://www.x.com/")).run is False
    # same host → match
    assert p.evaluate(graphql, http_event("https://api.x.com/")).run is True


def test_tech_event_itself_triggers_match():
    p = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    graphql = mod("graphql", flags=["active"], techs=["graphql"])
    ev = tech_event("api.x.com", "GraphQL")
    p.observe(ev)
    assert p.evaluate(graphql, ev).run is True


# ── modes ────────────────────────────────────────────────────────────────────

def test_passive_first_defers_active_modules():
    p = ReconPlanner(PlannerConfig(mode=MODE_PASSIVE_FIRST))
    active = mod("ffuf", flags=["active", "slow", "web"])
    passive = mod("wayback", flags=["passive"])
    assert p.evaluate(active, http_event("https://x.com/")).run is False
    assert p.evaluate(passive, url_event("https://x.com/a")).run is True


def test_passive_first_skips_active_seed():
    p = ReconPlanner(PlannerConfig(mode=MODE_PASSIVE_FIRST))
    assert p.allow_seed(mod("subfinder", flags=["active"])).run is False
    assert p.allow_seed(mod("crt_sh", flags=["passive"])).run is True


def test_default_mode_runs_active():
    p = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    assert p.evaluate(mod("ffuf", flags=["active", "web"]), http_event("https://x.com/")).run is True


def test_aggressive_allows_more_runs_per_host():
    agg = ReconPlanner(PlannerConfig(mode=MODE_AGGRESSIVE))
    dflt = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    m = mod("ffuf", flags=["active"])
    # run the same module on the same host many times; aggressive tolerates more
    agg_runs = sum(agg.evaluate(m, http_event("https://x.com/")).run for _ in range(120))
    dflt_runs = sum(dflt.evaluate(m, http_event("https://x.com/")).run for _ in range(120))
    assert agg_runs > dflt_runs


# ── budgets & loop prevention ────────────────────────────────────────────────

def test_execution_budget_exhausts():
    p = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT, max_executions=3))
    m = mod("ffuf", flags=["active"])
    runs = [p.evaluate(m, http_event(f"https://h{i}.x.com/")).run for i in range(6)]
    assert sum(runs) == 3
    assert runs[:3] == [True, True, True]
    assert any("budget" in d.reason for d in p.decisions if not d.run)


def test_per_host_cap_prevents_loops():
    p = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT, per_host_cap=2))
    m = mod("linkfinder", flags=["active"])
    runs = [p.evaluate(m, url_event("https://x.com/page")).run for _ in range(5)]
    assert sum(runs) == 2
    assert any("loop prevention" in d.reason for d in p.decisions if not d.run)


def test_prerequisite_gate():
    p = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    # module needs an HTTP_SERVICE observed on the host first
    m = mod("nuclei", flags=["active"], prereqs=["HTTP_SERVICE"])
    dec1 = p.evaluate(m, url_event("https://x.com/a"))
    assert dec1.run is False and "prerequisite" in dec1.reason
    p.observe(http_event("https://x.com/"))
    assert p.evaluate(m, url_event("https://x.com/a")).run is True


# ── explainability ───────────────────────────────────────────────────────────

def test_explain_reports_selection_and_skips():
    p = ReconPlanner(PlannerConfig(mode=MODE_PASSIVE_FIRST))
    p.evaluate(mod("wayback", flags=["passive"]), url_event("https://x.com/a"))
    p.evaluate(mod("ffuf", flags=["active"]), http_event("https://x.com/"))
    text = p.explain()
    assert "wayback" in text
    assert "passive-first" in text
    stats = p.stats
    assert stats["ran"] == 1 and stats["skipped"] == 1
    assert stats["mode"] == MODE_PASSIVE_FIRST


def test_decision_explain_string():
    p = ReconPlanner()
    dec = p.evaluate(mod("wayback", flags=["passive"]), url_event("https://x.com/a"))
    s = dec.explain()
    assert s.startswith("run wayback on x.com")


# ── planner stays out of scope / rate limiting ───────────────────────────────

def test_planner_does_not_mutate_event_scope():
    p = ReconPlanner()
    ev = http_event("https://x.com/")
    before = ev.scope_status
    p.observe(ev)
    p.evaluate(mod("ffuf", flags=["active"]), ev)
    assert ev.scope_status == before          # planner never re-decides scope


def test_bad_mode_rejected():
    with pytest.raises(ValueError):
        PlannerConfig(mode="turbo")


# ── port scanners must not be auto-skipped (regression) ──────────────────────
# The port scanner carries the "slow" flag → cost HIGH(8); with only the default
# value MEDIUM(3) the score is -5, below min_value(0), so the planner silently
# skipped naabu/rustscan and no OPEN_PORT ever fired. Their explicit
# expected_value=HIGH must keep them running at the default threshold.

def _ip_event(addr="10.0.0.5"):
    from events.types import IpData
    return Event.create(EventType.IP, IpData(address=addr),
                        scan_job_id=SCAN, source_tool="dnsx")


@pytest.mark.parametrize("name", ["naabu", "rustscan", "nmap"])
def test_port_scanner_not_skipped_at_default_threshold(name):
    from modules.registry import ModuleRegistry
    ModuleRegistry.discover()
    cls = ModuleRegistry.get(name)
    assert cls is not None
    planner = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    ev = _ip_event()
    planner.observe(ev)
    dec = planner.evaluate(cls, ev)
    assert dec.run, f"{name} was skipped: {dec.reason}"


def test_slow_high_value_module_runs_but_default_value_slow_is_skipped():
    # Documents the exact scoring: HIGH value cancels HIGH cost (score 0 ≥ 0),
    # while the old MEDIUM-value slow module would score -5 and be dropped.
    planner = ReconPlanner(PlannerConfig(mode=MODE_DEFAULT))
    ev = _ip_event()
    planner.observe(ev)
    assert planner.evaluate(mod("good", flags=["slow", "active"], value=VALUE_HIGH), ev).run
    assert not planner.evaluate(mod("bad", flags=["slow", "active"]), ev).run
