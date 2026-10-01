"""
Tests for related_domains — horizontal discovery of sibling root domains.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

from events.types import EventType, SubdomainData
from modules.passive.related_domains import (
    DomainProfile,
    brand_stems,
    confidence,
    generate_candidates,
    interesting_labels,
    parse_doh,
    parse_reverse_whois,
    parse_securitytrails,
    registrable_domain,
    roots_from_crtsh,
    score_candidate,
    split_registrable,
)
from modules.registry import FULL_MODULES, SCAN_PROFILES, ModuleRegistry

SEED = "oceaniahealthcare.co.nz"
CF_NS = {"june.ns.cloudflare.com", "seamus.ns.cloudflare.com"}
MIMECAST = {"au-smtp-inbound-1.mimecast.com", "au-smtp-inbound-2.mimecast.com"}


def _ctrl():
    c = MagicMock()
    c.scan_id = uuid.uuid4()
    c.stamp_and_publish = AsyncMock(return_value=True)
    return c


def _sub_event(host, source="subfinder"):
    ev = MagicMock(); ev.type = EventType.SUBDOMAIN
    ev.data = SubdomainData(hostname=host, source=source); ev.id = uuid.uuid4(); ev.distance = 1
    return ev


def _findings(ctrl):
    return [c[0][0] for c in ctrl.stamp_and_publish.call_args_list
            if c[0][0].type == EventType.FINDING_CANDIDATE]


# ── registrable-domain helpers ───────────────────────────────────────────────

def test_split_registrable_multi_label_suffix():
    assert split_registrable("a.b.oceaniahealthcare.co.nz") == ("oceaniahealthcare", "co.nz")
    assert split_registrable("oceanialiving.nz") == ("oceanialiving", "nz")
    assert split_registrable("www.example.com") == ("example", "com")


def test_split_registrable_rejects_suffix_and_single_label():
    assert split_registrable("co.nz") is None
    assert split_registrable("localhost") is None
    assert registrable_domain("") is None


# ── candidate generation ─────────────────────────────────────────────────────

def test_brand_stems_strips_trailing_keyword():
    assert brand_stems("oceaniahealthcare", ["", "care", "healthcare"]) == \
        ["oceaniahealthcare", "oceania"]
    assert brand_stems("acme", ["care"], extra=["Acme Co!"]) == ["acme", "acmeco"]


def test_interesting_labels_skips_generic_and_other_domains():
    hosts = [
        "www.oceaniahealthcare.co.nz", "api.oceaniahealthcare.co.nz",
        "waterford.oceaniahealthcare.co.nz", "www.thebayview.oceaniahealthcare.co.nz",
        "ec2test.oceaniahealthcare.co.nz", "waterford.other.co.nz",
    ]
    assert interesting_labels(hosts, SEED) == ["waterford", "thebayview"]


def test_generate_candidates_covers_all_generators():
    cands = generate_candidates(SEED, ["waterford", "thehelier"])
    assert SEED not in cands
    assert cands["oceaniahealthcare.com"] == "brand-tld"
    assert cands["oceaniahealthcare.nz"] == "brand-tld"
    assert cands["oceanialiving.nz"] == "brand-keyword"
    assert cands["oceaniavillage.com"] == "brand-keyword"
    assert cands["waterfordvillage.co.nz"] == "sub-label"
    assert cands["thehelier.co.nz"] == "sub-label"
    # sub-label candidates stay in the seed's TLD family
    assert "waterfordvillage.com" not in cands


def test_generate_candidates_respects_cap():
    assert len(generate_candidates(SEED, ["waterford"], max_candidates=5)) == 5


# ── parsers ──────────────────────────────────────────────────────────────────

def test_parse_doh():
    ok = {"Status": 0, "Answer": [{"data": "june.ns.cloudflare.com."},
                                  {"data": '"v=spf1 -all"'}]}
    assert parse_doh(ok) == ["june.ns.cloudflare.com", "v=spf1 -all"]
    assert parse_doh({"Status": 3}) is None
    assert parse_doh({"Status": 0}) == []


def test_roots_from_crtsh_excludes_seed():
    entries = [{"name_value": "oceaniahealthcare.co.nz\n*.oceaniahealthcare.co.nz\nqualcare.co.nz"},
               {"name_value": "www.eldercare.co.nz"}]
    assert roots_from_crtsh(entries, SEED) == {"qualcare.co.nz", "eldercare.co.nz"}
    assert roots_from_crtsh({"bad": 1}, SEED) == set()


def test_parse_api_payloads():
    assert parse_securitytrails({"records": [{"hostname": "A.com"}, {}]}) == ["a.com"]
    assert parse_reverse_whois({"domainsList": ["x.nz", ""]}) == ["x.nz"]
    assert parse_securitytrails(None) == [] and parse_reverse_whois([]) == []


# ── scoring ──────────────────────────────────────────────────────────────────

def _seed_profile():
    return DomainProfile(exists=True, ns=set(CF_NS), mx=set(MIMECAST),
                         txt={"v=spf1 include:au._netblocks.mimecast.com -all",
                              "google-site-verification=abcdefghijklmnop"})


def test_score_same_ns_and_mx_is_high():
    cand = DomainProfile(exists=True, ns=set(CF_NS), mx=set(MIMECAST))
    pts, sig = score_candidate(SEED, _seed_profile(), cand, {"brand-keyword"})
    assert sig == ["same-ns-set", "same-mx-set"] and confidence(pts) == "high"


def test_score_same_ns_only_is_medium():
    cand = DomainProfile(exists=True, ns=set(CF_NS))
    assert confidence(score_candidate(SEED, _seed_profile(), cand, set())[0]) == "medium"


def test_score_unrelated_domain_is_dropped():
    cand = DomainProfile(exists=True, ns={"ns1.otherhost.net", "ns2.otherhost.net"},
                         mx={"mx.other.net"}, txt={"v=spf1 -all"})
    pts, sig = score_candidate(SEED, _seed_profile(), cand, {"sub-label"})
    assert pts == 0 and sig == [] and confidence(pts) is None


def test_score_strong_signals():
    seed = _seed_profile()
    redirect = DomainProfile(exists=True, redirect="https://oceaniahealthcare.co.nz/")
    assert score_candidate(SEED, seed, redirect, set())[1] == ["redirects-to-seed"]
    infra = DomainProfile(exists=True, mx={"mail.oceaniahealthcare.co.nz"})
    assert "infra-on-seed-domain" in score_candidate(SEED, seed, infra, set())[1]
    token = DomainProfile(exists=True, txt={"google-site-verification=abcdefghijklmnop"})
    assert "shared-txt-token" in score_candidate(SEED, seed, token, set())[1]
    cert = DomainProfile(exists=True)
    assert confidence(score_candidate(SEED, seed, cert, {"crt.sh"})[0]) == "high"


# ── module flow ──────────────────────────────────────────────────────────────

def _fake_doh(zones):
    """zones: {domain: {"NS": [...], "MX": [...], "TXT": [...]}}; absent = NXDOMAIN."""
    async def doh(client, name, rtype):
        z = zones.get(name)
        if z is None:
            return None
        return list(z.get(rtype, []))
    return doh


async def test_module_reports_related_domains_on_seed_host():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["related_domains"], controller=ctrl,
                            module_config={"related_domains": {"crtsh": False}})[0]
    ns = sorted(CF_NS)
    mx = [f"5 {h}" for h in sorted(MIMECAST)]
    m._doh = _fake_doh({
        SEED: {"NS": ns, "MX": mx},
        "oceanialiving.nz": {"NS": ns, "MX": mx},              # high
        "waterfordvillage.co.nz": {"NS": ns},                   # medium
        "oceaniahealthcare.com": {"NS": ["ns1.parking.example"]},  # unrelated → dropped
    })
    await m.handle_event(_sub_event(SEED, source="seed"))
    await m.handle_event(_sub_event(f"waterford.{SEED}"))
    await m.finish()

    found = {e.data.evidence["domain"]: e for e in _findings(ctrl)}
    assert set(found) == {"oceanialiving.nz", "waterfordvillage.co.nz"}
    for e in found.values():
        # Attached to the in-scope seed — the candidate itself is never a target.
        assert e.data.host == SEED
        assert e.data.category == "related-domain"
        assert e.data.severity_hint == "info"
    assert found["oceanialiving.nz"].data.evidence["confidence"] == "high"
    assert found["waterfordvillage.co.nz"].data.evidence["confidence"] == "medium"
    assert found["waterfordvillage.co.nz"].data.evidence["sources"] == "sub-label"
    # Never emits SUBDOMAIN (which would feed candidates to active modules).
    assert all(c[0][0].type == EventType.FINDING_CANDIDATE
               for c in ctrl.stamp_and_publish.call_args_list)


async def test_module_min_confidence_filters():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["related_domains"], controller=ctrl, module_config={
        "related_domains": {"crtsh": False, "min_confidence": "high"}})[0]
    ns = sorted(CF_NS)
    m._doh = _fake_doh({SEED: {"NS": ns}, "oceanialiving.nz": {"NS": ns}})
    await m.handle_event(_sub_event(SEED, source="seed"))
    await m.finish()
    assert _findings(ctrl) == []


async def test_module_http_check_is_opt_in():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["related_domains"], controller=ctrl,
                            module_config={"related_domains": {"crtsh": False}})[0]
    m._doh = _fake_doh({SEED: {"NS": ["a"]}, "oceanialiving.nz": {"NS": ["b"]}})
    m._redirect_to = AsyncMock(return_value="https://oceaniahealthcare.co.nz/")
    await m.handle_event(_sub_event(SEED, source="seed"))
    await m.finish()
    m._redirect_to.assert_not_called()
    assert _findings(ctrl) == []


async def test_module_http_check_upgrades_on_redirect():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["related_domains"], controller=ctrl, module_config={
        "related_domains": {"crtsh": False, "http_check": True}})[0]
    m._doh = _fake_doh({SEED: {"NS": ["a"]}, "oceanialiving.nz": {"NS": ["b"]}})
    m._redirect_to = AsyncMock(side_effect=lambda c, d, s: (
        "https://oceaniahealthcare.co.nz/" if d == "oceanialiving.nz" else None))
    await m.handle_event(_sub_event(SEED, source="seed"))
    await m.finish()
    [e] = _findings(ctrl)
    assert e.data.evidence["signals"] == "redirects-to-seed"
    assert e.data.evidence["confidence"] == "high"


async def test_module_noop_without_seed_event():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["related_domains"], controller=ctrl)[0]
    m._doh = AsyncMock()
    await m.handle_event(_sub_event(f"www.{SEED}"))
    await m.finish()
    m._doh.assert_not_called()


def test_related_module_registered_in_groups():
    assert "related_domains" in ModuleRegistry.all_names()
    assert "related_domains" in FULL_MODULES
    assert "related_domains" in SCAN_PROFILES["fast"]["modules"]
    klass = ModuleRegistry.load(names=["related_domains"], controller=_ctrl())[0]
    assert "passive" in klass.flags


# ── CLI wiring ───────────────────────────────────────────────────────────────

def test_cli_related_flags_wire_module_and_config(monkeypatch):
    from typer.testing import CliRunner

    import cli.main as cli_main
    import controller.controller as ctrl_mod

    captured = {}

    class FakeController:
        def __init__(self, scope, **kw):
            captured.update(kw)

        async def run(self, domain):
            return None

    monkeypatch.setattr(ctrl_mod, "ScanController", FakeController)
    res = CliRunner().invoke(cli_main.app, [
        "scan", SEED, "--related-http", "--brand", "oceania", "-q", "--no-color"])
    assert res.exit_code == 0, res.output
    assert captured["enabled_modules"] == ["subfinder", "dnsx", "httpx_probe", "related_domains"]
    assert captured["module_config"]["related_domains"] == {
        "http_check": True, "brands": ["oceania"]}
