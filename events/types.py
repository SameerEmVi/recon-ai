"""
Event model — the atom of the whole system.

Every recon tool produces Events. Every event passes through the scope engine
before anything downstream sees it. The 11 types here cover the full recon
surface from subdomain to finding candidate.

Trust boundary: ALL string fields from target-controlled sources are
length-capped and control-char-stripped at construction via Pydantic validators.
Sanitized records are what the rest of the system (and eventually the LLM) sees.
Raw tool output never travels past this module.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Union
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from scope.types import ScopeStatus

# ── trust boundary helpers ────────────────────────────────────────────────────

_MAX_STR = 2048


def _cap(v: str, max_len: int = _MAX_STR) -> str:
    """Strip non-printable chars and cap length. Called on every target-controlled field."""
    return "".join(c for c in v if c.isprintable() or c in (" ", "\t"))[:max_len]


# ── event types ───────────────────────────────────────────────────────────────

class EventType(str, enum.Enum):
    SUBDOMAIN           = "SUBDOMAIN"
    DNS_RECORD          = "DNS_RECORD"
    IP                  = "IP"
    OPEN_PORT           = "OPEN_PORT"
    HTTP_SERVICE        = "HTTP_SERVICE"
    TECHNOLOGY          = "TECHNOLOGY"
    URL                 = "URL"
    ENDPOINT            = "ENDPOINT"
    PARAMETER           = "PARAMETER"
    ANOMALY             = "ANOMALY"
    FINDING_CANDIDATE   = "FINDING_CANDIDATE"


# ── per-type data schemas ─────────────────────────────────────────────────────
# Each is a Pydantic model validated on creation. String fields from
# target-controlled sources are sanitized here — not upstream, not downstream.

class SubdomainData(BaseModel):
    hostname: str
    source: str

    @field_validator("hostname")
    @classmethod
    def _v_hostname(cls, v: str) -> str:
        return _cap(v, 253)

    @field_validator("source")
    @classmethod
    def _v_source(cls, v: str) -> str:
        return _cap(v, 64)


class DnsRecordData(BaseModel):
    hostname: str
    record_type: str   # A, AAAA, CNAME, MX, TXT, NS
    value: str

    @field_validator("hostname", "value")
    @classmethod
    def _v_str(cls, v: str) -> str:
        return _cap(v, 512)

    @field_validator("record_type")
    @classmethod
    def _v_rt(cls, v: str) -> str:
        return _cap(v.upper(), 16)


class IpData(BaseModel):
    address: str
    resolved_from: str | None = None

    @field_validator("address")
    @classmethod
    def _v_addr(cls, v: str) -> str:
        return _cap(v, 45)

    @field_validator("resolved_from")
    @classmethod
    def _v_rf(cls, v: str | None) -> str | None:
        return _cap(v, 253) if v else v


class OpenPortData(BaseModel):
    host: str
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    banner: str | None = None

    @field_validator("host")
    @classmethod
    def _v_host(cls, v: str) -> str:
        return _cap(v, 253)

    @field_validator("protocol")
    @classmethod
    def _v_proto(cls, v: str) -> str:
        return _cap(v.lower(), 8)

    @field_validator("banner")
    @classmethod
    def _v_banner(cls, v: str | None) -> str | None:
        return _cap(v, 512) if v else v


class HttpServiceData(BaseModel):
    url: str
    status_code: int = Field(ge=100, le=599)
    title: str | None = None
    server: str | None = None
    content_length: int | None = None
    redirect_location: str | None = None
    # Raw technology strings from the prober (e.g. httpx -td / Wappalyzer),
    # each optionally "Name:version". Normalized into TECHNOLOGY events by the
    # fingerprint module. Target-controlled — sanitized/capped below.
    technologies: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def _v_url(cls, v: str) -> str:
        return _cap(v, 2048)

    @field_validator("title", "server")
    @classmethod
    def _v_short(cls, v: str | None) -> str | None:
        return _cap(v, 256) if v else v

    @field_validator("redirect_location")
    @classmethod
    def _v_redirect(cls, v: str | None) -> str | None:
        return _cap(v, 2048) if v else v

    @field_validator("technologies")
    @classmethod
    def _v_techs(cls, v: list[str]) -> list[str]:
        return [_cap(t, 256) for t in (v or []) if t and t.strip()][:100]


class TechnologyData(BaseModel):
    host: str
    name: str
    version: str | None = None
    category: str | None = None   # cms, framework, server, language
    # Detection provenance: which tool/method produced this technology, e.g.
    # "httpx", "whatweb", "nuclei", "heuristic". Dedup is by host:name:version
    # (see events/dedup.py), so the surviving event records its first detector.
    source: str | None = None

    @field_validator("host", "name")
    @classmethod
    def _v_str(cls, v: str) -> str:
        return _cap(v, 256)

    @field_validator("version", "category", "source")
    @classmethod
    def _v_short(cls, v: str | None) -> str | None:
        return _cap(v, 64) if v else v


class UrlData(BaseModel):
    url: str
    method: str = "GET"
    status_code: int | None = Field(default=None, ge=100, le=599)
    content_type: str | None = None
    found_via: str | None = None   # crawl, forced-browse, spider

    @field_validator("url")
    @classmethod
    def _v_url(cls, v: str) -> str:
        return _cap(v, 2048)

    @field_validator("method")
    @classmethod
    def _v_method(cls, v: str) -> str:
        return _cap(v.upper(), 16)

    @field_validator("content_type", "found_via")
    @classmethod
    def _v_short(cls, v: str | None) -> str | None:
        return _cap(v, 128) if v else v


class EndpointData(BaseModel):
    url: str
    method: str
    parameters: list[str] = []
    content_type: str | None = None

    @field_validator("url")
    @classmethod
    def _v_url(cls, v: str) -> str:
        return _cap(v, 2048)

    @field_validator("method")
    @classmethod
    def _v_method(cls, v: str) -> str:
        return _cap(v.upper(), 16)

    @field_validator("parameters")
    @classmethod
    def _v_params(cls, v: list[str]) -> list[str]:
        return [_cap(p, 128) for p in v[:100]]

    @field_validator("content_type")
    @classmethod
    def _v_ct(cls, v: str | None) -> str | None:
        return _cap(v, 128) if v else v


class ParameterData(BaseModel):
    url: str
    name: str
    location: str   # query, body, header, path, cookie
    sample_value: str | None = None   # sanitized, never raw response content

    @field_validator("url")
    @classmethod
    def _v_url(cls, v: str) -> str:
        return _cap(v, 2048)

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        return _cap(v, 128)

    @field_validator("sample_value")
    @classmethod
    def _v_sample(cls, v: str | None) -> str | None:
        # Target-controlled — sanitize+cap at construction like every other
        # target string. Never let raw values travel past this module.
        return _cap(v, 256) if v is not None else None

    @field_validator("location")
    @classmethod
    def _v_loc(cls, v: str) -> str:
        return _cap(v.lower(), 16)

    @field_validator("sample_value")
    @classmethod
    def _v_val(cls, v: str | None) -> str | None:
        return _cap(v, 256) if v else v


class AnomalyData(BaseModel):
    host: str
    description: str
    category: str | None = None

    @field_validator("host")
    @classmethod
    def _v_host(cls, v: str) -> str:
        return _cap(v, 253)

    @field_validator("description")
    @classmethod
    def _v_desc(cls, v: str) -> str:
        return _cap(v, 1024)

    @field_validator("category")
    @classmethod
    def _v_cat(cls, v: str | None) -> str | None:
        return _cap(v, 64) if v else v


class FindingCandidateData(BaseModel):
    host: str
    title: str
    description: str
    category: str     # xss, sqli, misconfig, idor, ssrf, ...
    evidence: dict    # structured key→value, never raw HTML or response bodies
    severity_hint: str | None = None   # low / medium / high / critical

    @field_validator("host")
    @classmethod
    def _v_host(cls, v: str) -> str:
        return _cap(v, 253)

    @field_validator("title")
    @classmethod
    def _v_title(cls, v: str) -> str:
        return _cap(v, 256)

    @field_validator("description")
    @classmethod
    def _v_desc(cls, v: str) -> str:
        return _cap(v, 2048)

    @field_validator("category", "severity_hint")
    @classmethod
    def _v_short(cls, v: str | None) -> str | None:
        return _cap(v, 64) if v else v

    @field_validator("evidence")
    @classmethod
    def _v_evidence(cls, v: object) -> dict:
        if not isinstance(v, dict):
            raise ValueError("evidence must be a dict")
        # Cap keys and values; limit to 20 entries
        return {_cap(str(k), 64): _cap(str(val), 512) for k, val in list(v.items())[:20]}


# Union of all concrete data types
EventData = Union[
    SubdomainData, DnsRecordData, IpData, OpenPortData,
    HttpServiceData, TechnologyData, UrlData, EndpointData,
    ParameterData, AnomalyData, FindingCandidateData,
]


# ── Event ─────────────────────────────────────────────────────────────────────

@dataclass
class Event:
    """One unit of recon output. Born PENDING; only the scope engine stamps IN/OUT.
    A tool must refuse to act on any event not marked IN."""

    id: UUID
    scan_job_id: UUID
    type: EventType
    data: EventData
    scope_status: ScopeStatus
    distance: int
    dedup_key: str
    source_tool: str
    source_event_id: UUID | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @staticmethod
    def create(
        event_type: EventType,
        data: EventData,
        scan_job_id: UUID,
        source_tool: str,
        source_event_id: UUID | None = None,
        distance: int = 0,
    ) -> "Event":
        from events.dedup import derive_dedup_key
        return Event(
            id=uuid.uuid4(),
            scan_job_id=scan_job_id,
            type=event_type,
            data=data,
            scope_status=ScopeStatus.PENDING,
            distance=distance,
            dedup_key=derive_dedup_key(event_type, data),
            source_tool=source_tool,
            source_event_id=source_event_id,
        )
