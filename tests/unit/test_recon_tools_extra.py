"""
Tests for the web-scraping (urlfinder/waymore/csprecon), brute/perm
(puredns/gotator) and cloud-bucket (s3scanner/cloud_enum) technique modules.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

from events.types import EventType, HttpServiceData, SubdomainData
from modules.registry import (
    CLOUD_MODULES, DEEP_DNS_MODULES, FULL_MODULES, WEB_MODULES, ModuleRegistry,
)
from modules.web.urlfinder import parse_urls
from modules.web.csprecon import extract_csp_hosts
from modules.active.puredns import parse_hosts
from modules.active.gotator import parse_resolved
from modules.active.s3scanner import parse_s3scanner
from modules.passive.cloud_enum import parse_cloud_enum


def _ctrl():
    c = MagicMock()
    c.scan_id = uuid.uuid4()
    c.stamp_and_publish = AsyncMock(return_value=True)
    return c


def _load(name, ctrl=None):
    return ModuleRegistry.load(names=[name], controller=ctrl or _ctrl())[0]


def _emitted(ctrl, etype):
    return [c[0][0].data for c in ctrl.stamp_and_publish.call_args_list
            if c[0][0].type == etype]


def _sub_event(host, source_tool="subfinder"):
    ev = MagicMock(); ev.type = EventType.SUBDOMAIN
    ev.data = SubdomainData(hostname=host, source="x")
    ev.id = uuid.uuid4(); ev.distance = 1; ev.source_tool = source_tool
    return ev


# ── web-scraping: urlfinder / waymore ────────────────────────────────────────

def test_parse_urls_filters_and_dedups():
    text = "https://a.example.com/x\nnope\nhttp://b.example.com\nhttps://a.example.com/x\n"
    assert parse_urls(text) == ["https://a.example.com/x", "http://b.example.com"]


async def test_urlfinder_emits_urls():
    ctrl = _ctrl()
    m = _load("urlfinder", ctrl)
    m.run_proc = AsyncMock(return_value="https://api.example.com/v1\nhttps://example.com/\n")
    await m.handle_event(_sub_event("example.com"))
    urls = {u.url for u in _emitted(ctrl, EventType.URL)}
    assert urls == {"https://api.example.com/v1", "https://example.com/"}


async def test_waymore_emits_urls():
    ctrl = _ctrl()
    m = _load("waymore", ctrl)
    m._collect = AsyncMock(return_value="https://old.example.com/a\nhttps://example.com/b\n")
    await m.handle_event(_sub_event("example.com"))
    urls = {u.url for u in _emitted(ctrl, EventType.URL)}
    assert "https://old.example.com/a" in urls


# ── web-scraping: csprecon ───────────────────────────────────────────────────

def test_extract_csp_hosts():
    csp = ("default-src 'self'; script-src 'unsafe-inline' https://cdn.example.com "
           "*.assets.example.com data:; img-src 'nonce-abc' https://img.example.com:443/p")
    hosts = set(extract_csp_hosts(csp))
    assert hosts == {"cdn.example.com", "assets.example.com", "img.example.com"}


async def test_csprecon_emits_subdomains():
    ctrl = _ctrl()
    m = _load("csprecon", ctrl)
    m._fetch_csp = AsyncMock(return_value=["default-src 'self' https://api.example.com"])
    ev = MagicMock(); ev.type = EventType.HTTP_SERVICE
    ev.data = HttpServiceData(url="https://example.com/", status_code=200)
    ev.id = uuid.uuid4(); ev.distance = 1
    await m.handle_event(ev)
    subs = {s.hostname for s in _emitted(ctrl, EventType.SUBDOMAIN)}
    assert "api.example.com" in subs


# ── brute / perm: puredns / gotator ──────────────────────────────────────────

def test_puredns_parse_hosts_scopes_to_domain():
    text = "api.example.com\nevil.com\nwww.example.com\n"
    assert parse_hosts(text, "example.com") == ["api.example.com", "www.example.com"]


async def test_puredns_emits_subdomains():
    ctrl = _ctrl()
    m = _load("puredns", ctrl)
    m.run_proc = AsyncMock(return_value="dev.example.com\napi.example.com\n")
    await m.run("example.com", ctrl.scan_id)
    subs = {s.hostname for s in _emitted(ctrl, EventType.SUBDOMAIN)}
    assert subs == {"dev.example.com", "api.example.com"}


def test_gotator_parse_resolved():
    assert parse_resolved("a.example.com\n\nb.example.com\n") == \
        ["a.example.com", "b.example.com"]


async def test_gotator_resolves_and_emits():
    ctrl = _ctrl()
    m = _load("gotator", ctrl)
    m._generate = AsyncMock(return_value=["dev-api.example.com", "api2.example.com"])
    m.run_proc = AsyncMock(return_value="dev-api.example.com\n")
    await m.handle_event(_sub_event("api.example.com"))
    subs = {s.hostname for s in _emitted(ctrl, EventType.SUBDOMAIN)}
    assert "dev-api.example.com" in subs


async def test_gotator_skips_own_output():
    ctrl = _ctrl()
    m = _load("gotator", ctrl)
    m._generate = AsyncMock()
    await m.handle_event(_sub_event("api.example.com", source_tool="gotator"))
    m._generate.assert_not_called()
    assert ctrl.stamp_and_publish.call_count == 0


# ── cloud buckets: s3scanner / cloud_enum ────────────────────────────────────

def test_parse_s3scanner():
    text = ("example-assets | exists | AuthUsers: [], AllUsers: [READ]\n"
            "random line without signal\n")
    hits = parse_s3scanner(text)
    assert len(hits) == 1
    assert hits[0]["bucket"].startswith("example-assets")


async def test_s3scanner_emits_finding():
    ctrl = _ctrl()
    m = _load("s3scanner", ctrl)
    m.run_proc = AsyncMock(return_value="example-assets | exists | AllUsers: [READ]\n")
    await m.handle_event(_sub_event("assets.example.com"))
    finds = _emitted(ctrl, EventType.FINDING_CANDIDATE)
    assert finds and finds[0].category == "cloud-bucket"


def test_parse_cloud_enum():
    text = ("[+] Checking S3\n"
            "  OPEN S3 BUCKET: http://example.s3.amazonaws.com/\n"
            "  Nothing here\n")
    hits = parse_cloud_enum(text)
    assert len(hits) == 1
    assert hits[0]["url"] == "http://example.s3.amazonaws.com/"


async def test_cloud_enum_emits_finding():
    ctrl = _ctrl()
    m = _load("cloud_enum", ctrl)
    m.run_proc = AsyncMock(
        return_value="  OPEN GCP BUCKET: https://storage.googleapis.com/example-data\n"
    )
    await m.run("example.com", ctrl.scan_id)
    finds = _emitted(ctrl, EventType.FINDING_CANDIDATE)
    assert finds and finds[0].category == "cloud-bucket"


# ── registration ─────────────────────────────────────────────────────────────

def test_extra_modules_registered():
    for name in ("urlfinder", "waymore", "csprecon"):
        assert name in WEB_MODULES and _load(name).name == name
    for name in ("puredns", "gotator"):
        assert name in DEEP_DNS_MODULES and _load(name).name == name
    for name in ("s3scanner", "cloud_enum"):
        assert name in CLOUD_MODULES and _load(name).name == name
    for name in ("urlfinder", "waymore", "csprecon", "puredns", "gotator",
                 "s3scanner", "cloud_enum"):
        assert name in FULL_MODULES
