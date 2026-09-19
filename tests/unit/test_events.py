"""
Event model tests — validation, sanitization, dedup_key derivation, and bus behaviour.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from events.bus import EventBus
from events.dedup import derive_dedup_key
from events.types import (
    AnomalyData,
    DnsRecordData,
    EndpointData,
    Event,
    EventType,
    FindingCandidateData,
    HttpServiceData,
    IpData,
    OpenPortData,
    ParameterData,
    SubdomainData,
    TechnologyData,
    UrlData,
)
from scope.types import ScopeStatus

SCAN_ID = uuid.uuid4()


def make(event_type: EventType, data) -> Event:
    return Event.create(event_type, data, scan_job_id=SCAN_ID, source_tool="test")


# ── trust boundary / sanitization ─────────────────────────────────────────────

def test_subdomain_strips_control_chars():
    d = SubdomainData(hostname="api.example.com\x00\x1b[31m", source="test")
    assert "\x00" not in d.hostname
    assert "\x1b" not in d.hostname


def test_subdomain_hostname_capped_at_253():
    d = SubdomainData(hostname="a" * 300, source="test")
    assert len(d.hostname) <= 253


def test_http_title_capped_at_256():
    d = HttpServiceData(url="https://x.com/", status_code=200, title="T" * 300)
    assert len(d.title) <= 256


def test_finding_evidence_values_capped():
    d = FindingCandidateData(
        host="x.com", title="XSS", description="reflected",
        category="xss", evidence={"payload": "A" * 600},
    )
    assert len(d.evidence["payload"]) <= 512


def test_finding_evidence_limited_to_20_entries():
    evidence = {str(i): "v" for i in range(30)}
    d = FindingCandidateData(
        host="x.com", title="t", description="d",
        category="c", evidence=evidence,
    )
    assert len(d.evidence) <= 20


def test_finding_evidence_must_be_dict():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        FindingCandidateData(
            host="x.com", title="t", description="d",
            category="c", evidence="not a dict",  # type: ignore
        )


def test_open_port_rejects_port_zero():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        OpenPortData(host="10.0.0.1", port=0, protocol="tcp")


def test_open_port_rejects_port_above_65535():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        OpenPortData(host="10.0.0.1", port=99999, protocol="tcp")


def test_http_rejects_status_below_100():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        HttpServiceData(url="https://x.com/", status_code=99)


# ── event creation ─────────────────────────────────────────────────────────────

def test_event_born_pending():
    e = make(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="t"))
    assert e.scope_status is ScopeStatus.PENDING


def test_event_has_uuid_and_dedup_key():
    e = make(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="t"))
    assert e.id is not None
    assert isinstance(e.dedup_key, str) and e.dedup_key


def test_event_scan_job_id_preserved():
    e = make(EventType.IP, IpData(address="10.0.0.1"))
    assert e.scan_job_id == SCAN_ID


# ── dedup_key derivation ───────────────────────────────────────────────────────

def test_subdomain_dedup_case_insensitive():
    k1 = derive_dedup_key(EventType.SUBDOMAIN, SubdomainData(hostname="API.Example.COM", source="t"))
    k2 = derive_dedup_key(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="t"))
    assert k1 == k2


def test_url_dedup_strips_query_string():
    k1 = derive_dedup_key(EventType.URL, UrlData(url="https://api.example.com/v1/users?page=1"))
    k2 = derive_dedup_key(EventType.URL, UrlData(url="https://api.example.com/v1/users?page=2"))
    assert k1 == k2


def test_url_dedup_respects_method():
    k1 = derive_dedup_key(EventType.URL, UrlData(url="https://api.example.com/v1/users", method="GET"))
    k2 = derive_dedup_key(EventType.URL, UrlData(url="https://api.example.com/v1/users", method="POST"))
    assert k1 != k2


def test_port_dedup_differentiates_ports():
    k1 = derive_dedup_key(EventType.OPEN_PORT, OpenPortData(host="10.0.0.1", port=80, protocol="tcp"))
    k2 = derive_dedup_key(EventType.OPEN_PORT, OpenPortData(host="10.0.0.1", port=443, protocol="tcp"))
    assert k1 != k2


def test_technology_dedup_includes_version():
    k1 = derive_dedup_key(EventType.TECHNOLOGY, TechnologyData(host="x.com", name="nginx", version="1.24"))
    k2 = derive_dedup_key(EventType.TECHNOLOGY, TechnologyData(host="x.com", name="nginx", version="1.25"))
    assert k1 != k2


# ── EventBus ───────────────────────────────────────────────────────────────────

def _in_scope_event() -> Event:
    e = make(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="t"))
    e.scope_status = ScopeStatus.IN
    e.distance = 1
    return e


async def test_bus_drops_pending_event():
    bus = EventBus()
    e = make(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="t"))
    result = await bus.publish(e)
    assert result is False


async def test_bus_drops_out_of_scope_event():
    bus = EventBus()
    e = make(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="t"))
    e.scope_status = ScopeStatus.OUT
    result = await bus.publish(e)
    assert result is False


async def test_bus_accepts_in_scope_event():
    bus = EventBus()
    result = await bus.publish(_in_scope_event())
    assert result is True


async def test_bus_deduplicates():
    bus = EventBus()
    r1 = await bus.publish(_in_scope_event())
    r2 = await bus.publish(_in_scope_event())   # same hostname → same dedup_key
    assert r1 is True
    assert r2 is False


async def test_bus_calls_subscriber():
    bus = EventBus()
    received = []

    async def handler(event: Event) -> None:
        received.append(event)

    bus.subscribe(EventType.SUBDOMAIN, handler)
    e = _in_scope_event()
    await bus.publish(e)
    await asyncio.sleep(0.05)   # let the spawned task run
    assert len(received) == 1
    assert received[0].dedup_key == e.dedup_key
