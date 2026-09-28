"""
Tests for the Censys host-enrichment integration:
  - recon.censys.parse_host_response (pure parsing, realistic fixture)
  - modules.passive.censys.CensysModule setup gating + scope-gated emission

No real API key or network is used (the module's setup reads CENSYS_API_KEY from
the environment; emission is tested through a fake controller).
"""

from __future__ import annotations

import uuid

import pytest

from events.types import DnsRecordData, Event, EventType, IpData
from recon import censys
from recon.censys import HostInfo, host_url, parse_host_response

# A realistic Censys Platform host-lookup response (trimmed).
FIXTURE = {
    "result": {
        "resource": {
            "ip": "203.0.113.10",
            "autonomous_system": {"asn": 64500, "name": "EXAMPLE-ORG", "country_code": "NZ"},
            "service_count": 3,
            "services": [
                {"port": 443, "protocol": "HTTP"},
                {"port": 22, "protocol": "SSH"},
                {"port": 443, "protocol": "HTTP"},          # dup port+proto → collapsed
                {"port": 3306, "service_name": "MYSQL"},
            ],
            "dns": {"names": ["api.example.com", "intranet.example.com", "unrelated.other.com"]},
            "reverse_dns": {"names": ["host10.example.com"]},
        }
    }
}


# ── pure parsing ───────────────────────────────────────────────────────────────

def test_parse_host_response_fields():
    h = parse_host_response(FIXTURE)
    assert h.ip == "203.0.113.10"
    assert h.asn == 64500 and h.org == "EXAMPLE-ORG" and h.country == "NZ"
    assert h.service_count == 3
    assert (443, "HTTP") in h.services and (22, "SSH") in h.services and (3306, "MYSQL") in h.services
    assert len([s for s in h.services if s == (443, "HTTP")]) == 1     # deduped
    assert "api.example.com" in h.dns_names and "host10.example.com" in h.dns_names


def test_org_label():
    assert parse_host_response(FIXTURE).org_label() == "ASN64500 EXAMPLE-ORG (NZ)"


@pytest.mark.parametrize("bad", [{}, None, {"result": {}}, {"result": {"resource": None}}, {"x": 1}])
def test_parse_bad_input_safe(bad):
    h = parse_host_response(bad)
    assert isinstance(h, HostInfo) and h.services == [] and h.dns_names == []


def test_host_url():
    assert host_url("1.2.3.4") == "https://api.platform.censys.io/v3/global/asset/host/1.2.3.4"


# ── module: setup gating on the API key ───────────────────────────────────────

class _FakeCtrl:
    def __init__(self):
        self.scan_id = uuid.uuid4()
        self.scan_domain = "example.com"
        self.rate_limiter = None          # get_limiter → NOOP
        self.emitted: list[Event] = []

    async def stamp_and_publish(self, event: Event) -> bool:
        self.emitted.append(event)
        return True


async def test_setup_disabled_without_key(monkeypatch):
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    from modules.passive.censys import CensysModule
    m = CensysModule(_FakeCtrl())
    assert await m.setup() is False


async def test_setup_enabled_with_key(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "censys_dummy_testtoken")
    from modules.passive.censys import CensysModule
    m = CensysModule(_FakeCtrl())
    assert await m.setup() is True
    assert m._key == "censys_dummy_testtoken"


# ── module: scope-gated emission from a parsed host ───────────────────────────

async def test_emit_host_produces_expected_events(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "censys_dummy_testtoken")
    from modules.passive.censys import CensysModule
    ctrl = _FakeCtrl()
    m = CensysModule(ctrl)
    await m.setup()

    await m._emit_host(parse_host_response(FIXTURE), event=None)

    by_type: dict[str, list] = {}
    for e in ctrl.emitted:
        by_type.setdefault(e.type.value, []).append(e.data)

    # ASN/org anomaly
    anomalies = by_type.get("ANOMALY", [])
    assert any(a.category == "host-org" and "ASN64500" in a.description for a in anomalies)
    # open ports
    ports = {(p.host, p.port) for p in by_type.get("OPEN_PORT", [])}
    assert ("203.0.113.10", 443) in ports and ("203.0.113.10", 22) in ports and ("203.0.113.10", 3306) in ports
    # technologies (service protocols), UNKNOWN excluded
    techs = {t.name for t in by_type.get("TECHNOLOGY", [])}
    assert "HTTP" in techs and "SSH" in techs
    # subdomains from DNS names (all emitted; scope gate would filter live)
    subs = {s.hostname for s in by_type.get("SUBDOMAIN", [])}
    assert "api.example.com" in subs and "host10.example.com" in subs
    assert all(getattr(s, "source", "") == "censys" for s in by_type.get("SUBDOMAIN", []))


async def test_ip_extraction_from_events():
    from modules.passive.censys import CensysModule
    m = CensysModule(_FakeCtrl())
    a = Event.create(EventType.DNS_RECORD, DnsRecordData(hostname="x.example.com", record_type="A", value="203.0.113.10"), scan_job_id=uuid.uuid4(), source_tool="dnsx")
    assert m._ip_from(a) == "203.0.113.10"
    ipev = Event.create(EventType.IP, IpData(address="198.51.100.7"), scan_job_id=uuid.uuid4(), source_tool="dnsx")
    assert m._ip_from(ipev) == "198.51.100.7"
    cname = Event.create(EventType.DNS_RECORD, DnsRecordData(hostname="x.example.com", record_type="CNAME", value="foo.cdn.net"), scan_job_id=uuid.uuid4(), source_tool="dnsx")
    assert m._ip_from(cname) == ""            # only A/AAAA yield an IP
