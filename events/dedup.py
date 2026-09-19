"""
Dedup key derivation — one stable string per logical "thing" found.

The key is inserted into a DB uniqueness constraint (or an in-memory set for
now) so re-discovered events are dropped rather than processed again. This also
bounds recursion: a cycle in the event graph produces duplicate keys, which
get dropped before they can fan out further.

Keys are designed to be:
  - Stable: same logical target always produces the same key.
  - Discriminating: meaningfully different targets produce different keys.
  - Cheap: no external I/O, just string ops.
"""

from __future__ import annotations

import hashlib
import urllib.parse

from events.types import (
    AnomalyData,
    DnsRecordData,
    EndpointData,
    EventData,
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


def derive_dedup_key(event_type: EventType, data: EventData) -> str:
    match event_type:
        case EventType.SUBDOMAIN:
            assert isinstance(data, SubdomainData)
            return f"subdomain:{data.hostname.lower()}"

        case EventType.DNS_RECORD:
            assert isinstance(data, DnsRecordData)
            return f"dns:{data.hostname.lower()}:{data.record_type}:{data.value.lower()}"

        case EventType.IP:
            assert isinstance(data, IpData)
            return f"ip:{data.address.lower()}"

        case EventType.OPEN_PORT:
            assert isinstance(data, OpenPortData)
            return f"port:{data.host.lower()}:{data.port}:{data.protocol}"

        case EventType.HTTP_SERVICE:
            assert isinstance(data, HttpServiceData)
            return f"http:{_normalize_url(data.url)}"

        case EventType.TECHNOLOGY:
            assert isinstance(data, TechnologyData)
            ver = (data.version or "").lower()
            return f"tech:{data.host.lower()}:{data.name.lower()}:{ver}"

        case EventType.URL:
            assert isinstance(data, UrlData)
            return f"url:{data.method.upper()}:{_normalize_url(data.url)}"

        case EventType.ENDPOINT:
            assert isinstance(data, EndpointData)
            return f"endpoint:{data.method.upper()}:{_normalize_url(data.url)}"

        case EventType.PARAMETER:
            assert isinstance(data, ParameterData)
            return f"param:{_normalize_url(data.url)}:{data.location}:{data.name.lower()}"

        case EventType.ANOMALY:
            assert isinstance(data, AnomalyData)
            return "anomaly:" + _short_hash(f"{data.host}:{data.description}")

        case EventType.FINDING_CANDIDATE:
            assert isinstance(data, FindingCandidateData)
            return "finding:" + _short_hash(f"{data.host}:{data.title}:{data.category}")

        case _:
            raise ValueError(f"unknown event type: {event_type!r}")


def _normalize_url(url: str) -> str:
    """Normalize a URL for dedup: lowercase, strip query/fragment, strip trailing slash."""
    try:
        p = urllib.parse.urlparse(url.lower())
        path = p.path.rstrip("/") or "/"
        return f"{p.scheme}://{p.netloc}{path}"
    except Exception:
        return url.lower()[:256]


def _short_hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]
