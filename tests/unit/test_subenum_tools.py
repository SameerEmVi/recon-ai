"""
Tests for the added subdomain-enumeration technique modules (quick-wins group):
zonetransfer, tlsx, hakip2host, github_subdomains, takeover.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from events.types import DnsRecordData, EventType, IpData, SubdomainData
from modules.registry import (
    DEEP_DNS_MODULES, EXTRA_PASSIVE_MODULES, FULL_MODULES, WEB_MODULES,
    ModuleRegistry,
)
from modules.active.zonetransfer import parse_ns, parse_axfr
from modules.active.tlsx import parse_tlsx_sans
from modules.active.hakip2host import parse_hakip2host
from modules.passive.github_subdomains import parse_lines
from modules.web.takeover import assess_takeover, classify_takeover
from scope.engine import ScopeEngine
from scope.types import Scope, ScopeStatus


def _ctrl():
    c = MagicMock()
    c.scan_id = uuid.uuid4()
    c.stamp_and_publish = AsyncMock(return_value=True)
    return c


def _load(name):
    return ModuleRegistry.load(names=[name], controller=_ctrl())[0]


def _emitted(ctrl, etype):
    return [c[0][0].data for c in ctrl.stamp_and_publish.call_args_list
            if c[0][0].type == etype]


def _sub_event(host):
    ev = MagicMock(); ev.type = EventType.SUBDOMAIN
    ev.data = SubdomainData(hostname=host, source="seed"); ev.id = uuid.uuid4(); ev.distance = 1
    return ev


# ── zonetransfer ─────────────────────────────────────────────────────────────

def test_parse_ns():
    assert parse_ns("ns1.example.com.\nns2.example.com.\n") == \
        ["ns1.example.com", "ns2.example.com"]


AXFR_OK = """
example.com.        3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600
example.com.        3600 IN NS ns1.example.com.
www.example.com.    3600 IN A 93.184.216.34
internal.example.com. 3600 IN A 10.0.0.5
"""


def test_parse_axfr_success():
    names, ok = parse_axfr(AXFR_OK, "example.com")
    assert ok is True
    assert "www.example.com" in names
    assert "internal.example.com" in names


def test_parse_axfr_failure():
    names, ok = parse_axfr("; Transfer failed.", "example.com")
    assert ok is False
    assert names == []


async def test_zonetransfer_emits_subdomains_and_finding():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["zonetransfer"], controller=ctrl)[0]
    m.run_proc = AsyncMock(side_effect=["ns1.example.com.\n", AXFR_OK])
    await m.run("example.com", ctrl.scan_id)

    subs = {s.hostname for s in _emitted(ctrl, EventType.SUBDOMAIN)}
    assert "internal.example.com" in subs
    finds = _emitted(ctrl, EventType.FINDING_CANDIDATE)
    assert any(f.category == "dns-zone-transfer" for f in finds)


# ── tlsx ─────────────────────────────────────────────────────────────────────

def test_parse_tlsx_sans():
    out = "*.example.com\napi.example.com\nexample.com\n"
    assert parse_tlsx_sans(out) == ["example.com", "api.example.com"]


async def test_tlsx_emits_new_subdomains():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["tlsx"], controller=ctrl)[0]
    m.run_proc = AsyncMock(return_value="api.example.com\nvpn.example.com\n")
    await m.handle_event(_sub_event("www.example.com"))
    subs = {s.hostname for s in _emitted(ctrl, EventType.SUBDOMAIN)}
    assert subs == {"api.example.com", "vpn.example.com"}


# ── hakip2host ───────────────────────────────────────────────────────────────

def test_parse_hakip2host():
    out = ("93.184.216.34 - [DNS-PTR] www.example.com\n"
           "93.184.216.34 - [TLS-CN] example.com\n")
    assert parse_hakip2host(out) == ["www.example.com", "example.com"]


async def test_hakip2host_emits_subdomains():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["hakip2host"], controller=ctrl)[0]
    m.run_proc = AsyncMock(return_value="1.2.3.4 - [DNS-PTR] host.example.com\n")
    ev = MagicMock(); ev.type = EventType.IP
    ev.data = IpData(address="1.2.3.4"); ev.id = uuid.uuid4(); ev.distance = 1
    await m.handle_event(ev)
    subs = {s.hostname for s in _emitted(ctrl, EventType.SUBDOMAIN)}
    assert "host.example.com" in subs


# ── github_subdomains ────────────────────────────────────────────────────────

def test_github_parse_lines_scopes_to_domain():
    out = "api.example.com\nevil.com\nwww.example.com\n"
    assert parse_lines(out, "example.com") == ["api.example.com", "www.example.com"]


async def test_github_subdomains_skips_without_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["github_subdomains"], controller=ctrl)[0]
    m.run_proc = AsyncMock(return_value="should.not.be.used\n")
    await m.run("example.com", ctrl.scan_id)
    assert ctrl.stamp_and_publish.call_count == 0


# ── takeover ─────────────────────────────────────────────────────────────────

def test_classify_takeover():
    assert classify_takeover("myapp.herokuapp.com") == "Heroku"
    assert classify_takeover("bucket.s3.amazonaws.com") == "AWS S3"
    assert classify_takeover("user.github.io") == "GitHub Pages"
    assert classify_takeover("real.example.com") is None


def _cname_event(host, value):
    ev = MagicMock(); ev.type = EventType.DNS_RECORD
    ev.data = DnsRecordData(hostname=host, record_type="CNAME", value=value)
    ev.id = uuid.uuid4(); ev.distance = 1
    return ev


async def test_takeover_confirmed_high_on_unclaimed_fingerprint():
    from unittest.mock import AsyncMock
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["takeover"], controller=ctrl)[0]
    # Host returns Heroku's unclaimed page → confirmed HIGH.
    m._fetch_body = AsyncMock(return_value=(404, "No such app\nherokucdn.com/error-pages/no-such-app.html"))
    await m.handle_event(_cname_event("blog.example.com", "ghost.herokuapp.com"))
    finds = _emitted(ctrl, EventType.FINDING_CANDIDATE)
    assert len(finds) == 1
    assert finds[0].category == "subdomain-takeover"
    assert finds[0].evidence["service"] == "Heroku"
    assert finds[0].severity_hint == "high"
    assert "unverified" not in finds[0].title


async def test_takeover_live_claimed_resource_is_not_flagged():
    # The CloudFront/S3 false-positive: a live, claimed resource behind a known
    # service (S3 has a fingerprint, but the body doesn't match it) → NO finding.
    from unittest.mock import AsyncMock
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["takeover"], controller=ctrl)[0]
    m._fetch_body = AsyncMock(return_value=(403, "<Error><Code>AccessDenied</Code></Error>"))
    await m.handle_event(_cname_event("files.example.com", "bucket.s3.amazonaws.com"))
    assert _emitted(ctrl, EventType.FINDING_CANDIDATE) == []


async def test_takeover_no_fingerprint_service_is_low_unverified():
    # CloudFront has no reliable body fingerprint → LOW unverified, not HIGH.
    from unittest.mock import AsyncMock
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["takeover"], controller=ctrl)[0]
    m._fetch_body = AsyncMock(return_value=(403, "anything"))
    m._target_resolves = AsyncMock(return_value=None)  # resolution inconclusive
    await m.handle_event(_cname_event("assets.example.com", "d123.cloudfront.net"))
    finds = _emitted(ctrl, EventType.FINDING_CANDIDATE)
    assert len(finds) == 1
    assert finds[0].severity_hint == "low"
    assert "unverified" in finds[0].title
    assert finds[0].evidence["service"] == "AWS CloudFront"


async def test_takeover_unreachable_host_is_low_unverified():
    from unittest.mock import AsyncMock
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["takeover"], controller=ctrl)[0]
    m._fetch_body = AsyncMock(return_value=(None, None))
    m._target_resolves = AsyncMock(return_value=None)  # resolution inconclusive
    await m.handle_event(_cname_event("blog.example.com", "ghost.herokuapp.com"))
    finds = _emitted(ctrl, EventType.FINDING_CANDIDATE)
    assert len(finds) == 1
    assert finds[0].severity_hint == "low"
    assert "unverified" in finds[0].title


async def test_takeover_nxdomain_target_is_medium_likely():
    # Body inconclusive (CloudFront has no body fingerprint), but the CNAME
    # target itself does not resolve (NXDOMAIN) → MEDIUM "likely" takeover,
    # driven purely by the HTTP-independent DNS signal.
    from unittest.mock import AsyncMock
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["takeover"], controller=ctrl)[0]
    m._fetch_body = AsyncMock(return_value=(502, "anything"))
    m._target_resolves = AsyncMock(return_value=False)
    await m.handle_event(_cname_event("assets.example.com", "d123.cloudfront.net"))
    finds = _emitted(ctrl, EventType.FINDING_CANDIDATE)
    assert len(finds) == 1
    assert finds[0].severity_hint == "medium"
    assert "Likely" in finds[0].title
    assert finds[0].evidence["detection"] == "cname-target-nxdomain"
    assert finds[0].evidence["cname_target_resolves"] == "false"
    assert finds[0].evidence["sig_version"]


def test_assess_takeover_matrix():
    # 1. unclaimed body fingerprint → confirmed HIGH, keep.
    assert assess_takeover("AWS S3", True, None) == (True, "high", "unclaimed-fingerprint")
    # 2. live/claimed body → suppressed (not a takeover), regardless of DNS.
    assert assess_takeover("AWS S3", False, False) == (False, "", "claimed")
    assert assess_takeover("AWS S3", False, True) == (False, "", "claimed")
    # 3. body inconclusive + target NXDOMAIN → likely MEDIUM.
    assert assess_takeover("AWS CloudFront", None, False) == (True, "medium", "cname-target-nxdomain")
    # 4. body inconclusive + target resolves / unknown → unverified LOW.
    assert assess_takeover("AWS CloudFront", None, True) == (True, "low", "unverified")
    assert assess_takeover("AWS CloudFront", None, None) == (True, "low", "unverified")


async def test_target_resolves_states(monkeypatch):
    import socket
    from unittest.mock import AsyncMock, MagicMock
    import modules.web.takeover as tk

    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["takeover"], controller=ctrl)[0]

    def _patch(side_effect):
        fake_loop = MagicMock()
        fake_loop.getaddrinfo = AsyncMock(side_effect=side_effect)
        monkeypatch.setattr(tk.asyncio, "get_running_loop", lambda: fake_loop)
        return fake_loop

    # Resolves → True.
    _patch([[(2, 1, 6, "", ("1.2.3.4", 0))]])
    assert await m._target_resolves("live.cloudfront.net") is True

    # NXDOMAIN on both attempts → False (re-observed), getaddrinfo called twice.
    nx = socket.gaierror(11001, "host not found")
    loop = _patch([nx, nx])
    assert await m._target_resolves("gone.cloudfront.net") is False
    assert loop.getaddrinfo.await_count == 2

    # Transient (errno not a definitive NXDOMAIN) → inconclusive None.
    loop = _patch([socket.gaierror(11002, "try again")])
    assert await m._target_resolves("flaky.cloudfront.net") is None

    # NXDOMAIN once, then resolves → True (retry recovered the blip).
    loop = _patch([nx, [[(2, 1, 6, "", ("1.2.3.4", 0))]]])
    assert await m._target_resolves("blip.cloudfront.net") is True

    # Empty target → None without any lookup.
    assert await m._target_resolves("") is None


async def test_takeover_ignores_non_cname_and_unknown():
    ctrl = _ctrl()
    m = ModuleRegistry.load(names=["takeover"], controller=ctrl)[0]
    a = MagicMock(); a.type = EventType.DNS_RECORD
    a.data = DnsRecordData(hostname="x.example.com", record_type="A", value="1.2.3.4")
    a.id = uuid.uuid4(); a.distance = 1
    b = MagicMock(); b.type = EventType.DNS_RECORD
    b.data = DnsRecordData(hostname="y.example.com", record_type="CNAME",
                           value="internal.example.com")
    b.id = uuid.uuid4(); b.distance = 1
    await m.handle_event(a)
    await m.handle_event(b)
    assert _emitted(ctrl, EventType.FINDING_CANDIDATE) == []


# ── registration ─────────────────────────────────────────────────────────────

def test_quickwin_modules_registered():
    for name in ("zonetransfer", "tlsx", "hakip2host", "github_subdomains", "takeover"):
        m = _load(name)
        assert m.name == name
    assert "github_subdomains" in EXTRA_PASSIVE_MODULES
    assert {"zonetransfer", "tlsx", "hakip2host"} <= set(DEEP_DNS_MODULES)
    assert "takeover" in WEB_MODULES
    for name in ("zonetransfer", "tlsx", "hakip2host", "github_subdomains", "takeover"):
        assert name in FULL_MODULES
