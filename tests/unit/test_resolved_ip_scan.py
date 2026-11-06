"""
Resolved-IP port scanning + its CDN guard.

Covers:
  * recon.cdncheck — IP-range and CNAME CDN detection (incl. the real swise.ai
    CloudFront IPs).
  * ScopeEngine.authorize_ip — a resolved IP becomes IN, but DENY and the
    distance bound still win.
  * ScanController._observe_for_resolved_ip_scan — default-on authorization,
    CDN IPs skipped unless scan_cdn_ips, and nothing authorized in a mode that
    forbids port scanning (osint).
"""

from __future__ import annotations

import uuid

from controller.controller import ScanController
from events.types import Event, EventType, DnsRecordData, IpData
from recon.cdncheck import cdn_provider, cdn_provider_for_cname, cdn_provider_for_ip
from scope.engine import ScopeEngine
from scope.types import Scope, ScopeStatus


# ── cdncheck ──────────────────────────────────────────────────────────────────

def test_cdn_ip_detection_covers_cloudfront_and_cloudflare():
    # The actual swise.ai resolved IPs.
    assert cdn_provider_for_ip("65.8.140.129") == "aws-cloudfront"
    assert cdn_provider_for_ip("2600:9000:209a:1600:1d:1550:7c80:93a1") == "aws-cloudfront"
    assert cdn_provider_for_ip("104.16.1.1") == "cloudflare"
    assert cdn_provider_for_ip("151.101.1.1") == "fastly"


def test_non_cdn_ip_is_none():
    assert cdn_provider_for_ip("203.0.113.10") is None       # TEST-NET-3 (origin-like)
    assert cdn_provider_for_ip("198.51.100.7") is None
    assert cdn_provider_for_ip("not-an-ip") is None
    assert cdn_provider_for_ip("") is None


def test_cdn_cname_detection():
    assert cdn_provider_for_cname("d123.cloudfront.net") == "aws-cloudfront"
    assert cdn_provider_for_cname("x.akamaiedge.net") == "akamai"
    assert cdn_provider_for_cname("app.example.com") is None
    assert cdn_provider("203.0.113.10", "d1.cloudfront.net") == "aws-cloudfront"  # cname fallback


# ── ScopeEngine.authorize_ip ──────────────────────────────────────────────────

def _scope(**kw):
    return Scope.from_strings(in_scope=["*.ex.com", "ex.com"], out_scope=kw.get("out", []),
                              max_distance=kw.get("md", 5))


def test_authorize_ip_makes_it_in_scope():
    eng = ScopeEngine(_scope())
    assert eng.evaluate("203.0.113.10").status is ScopeStatus.OUT   # IP OUT by default
    assert eng.authorize_ip("203.0.113.10") is True
    assert eng.evaluate("203.0.113.10").status is ScopeStatus.IN


def test_authorized_ip_still_loses_to_deny():
    eng = ScopeEngine(_scope(out=["203.0.113.10"]))
    eng.authorize_ip("203.0.113.10")
    # DENY is checked before the authorized-IP allow step.
    assert eng.evaluate("203.0.113.10").status is ScopeStatus.OUT


def test_authorized_ip_still_bounded_by_distance():
    eng = ScopeEngine(_scope(md=1))
    eng.authorize_ip("203.0.113.10")
    # distance = source_distance + 1; source_distance 5 → distance 6 > max 1 → OUT
    assert eng.evaluate("203.0.113.10", source_distance=5).status is ScopeStatus.OUT


def test_authorize_bad_ip_returns_false():
    eng = ScopeEngine(_scope())
    assert eng.authorize_ip("nope") is False


# ── controller integration ────────────────────────────────────────────────────

def _ctrl(mode="active", **kw):
    scope = Scope.from_strings(in_scope=["*.ex.com", "ex.com"], out_scope=[], max_distance=5)
    return ScanController(scope, mode=mode, results_enabled=False, **kw)


def _ip_event(ctrl, ip, host="a.ex.com"):
    return Event.create(EventType.IP, IpData(address=ip, resolved_from=host),
                        scan_job_id=ctrl.scan_id, source_tool="dnsx")


def test_resolved_non_cdn_ip_is_authorized_in_active():
    c = _ctrl()
    c._observe_for_resolved_ip_scan(_ip_event(c, "203.0.113.10"))
    assert c.scope_engine.evaluate("203.0.113.10").status is ScopeStatus.IN


def test_resolved_cdn_ip_is_skipped_by_default():
    c = _ctrl()
    c._observe_for_resolved_ip_scan(_ip_event(c, "65.8.140.129"))   # CloudFront
    assert c.scope_engine.evaluate("65.8.140.129").status is ScopeStatus.OUT


def test_resolved_cdn_ip_scanned_when_override_set():
    c = _ctrl(scan_cdn_ips=True)
    c._observe_for_resolved_ip_scan(_ip_event(c, "65.8.140.129"))
    assert c.scope_engine.evaluate("65.8.140.129").status is ScopeStatus.IN


def test_cname_fronted_host_ip_is_skipped():
    c = _ctrl()
    # A CNAME to Akamai (IP not in our CIDR list) marks the host CDN-fronted.
    cname = Event.create(EventType.DNS_RECORD,
                         DnsRecordData(hostname="a.ex.com", record_type="CNAME",
                                       value="x.akamaiedge.net"),
                         scan_job_id=c.scan_id, source_tool="dnsx")
    c._observe_for_resolved_ip_scan(cname)
    c._observe_for_resolved_ip_scan(_ip_event(c, "203.0.113.10", host="a.ex.com"))
    assert c.scope_engine.evaluate("203.0.113.10").status is ScopeStatus.OUT


def test_no_authorization_in_osint_mode():
    c = _ctrl(mode="osint")
    c._observe_for_resolved_ip_scan(_ip_event(c, "203.0.113.10"))
    # osint forbids PORT_SCANNING → resolved IPs are never authorized.
    assert c.scope_engine.evaluate("203.0.113.10").status is ScopeStatus.OUT


def test_disabled_flag_authorizes_nothing():
    c = _ctrl(scan_resolved_ips=False)
    c._observe_for_resolved_ip_scan(_ip_event(c, "203.0.113.10"))
    assert c.scope_engine.evaluate("203.0.113.10").status is ScopeStatus.OUT
