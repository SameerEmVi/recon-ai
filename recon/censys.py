"""
recon.censys — pure parsing for the Censys Platform host-lookup response.

The censys module (modules/passive/censys.py) calls the Censys Platform API
`GET /v3/global/asset/host/{ip}` (free-tier host lookup) to enrich IPs the
pipeline already discovered. This module holds the deterministic, network-free
parsing so it is unit-testable without the API or a key.

Note: the Platform *search* API (domain → hosts/certs) is a paid feature; the
free tier only exposes per-IP/per-cert lookups. So Censys here enriches known
IPs (ASN/org, open services, DNS names) rather than enumerating subdomains from
a domain query.
"""

from __future__ import annotations

from dataclasses import dataclass, field

BASE_URL = "https://api.platform.censys.io/v3/global"
ACCEPT_HOST = "application/vnd.censys.api.v3.host.v1+json"


def host_url(ip: str) -> str:
    return f"{BASE_URL}/asset/host/{ip}"


@dataclass
class HostInfo:
    ip: str = ""
    asn: int | None = None
    org: str = ""
    country: str = ""
    service_count: int = 0
    services: list[tuple[int, str]] = field(default_factory=list)  # (port, service/proto)
    dns_names: list[str] = field(default_factory=list)

    def org_label(self) -> str:
        bits = []
        if self.asn:
            bits.append(f"ASN{self.asn}")
        if self.org:
            bits.append(self.org)
        if self.country:
            bits.append(f"({self.country})")
        return " ".join(bits)


def parse_host_response(data: dict) -> HostInfo:
    """Parse a Censys Platform host-lookup JSON body into a HostInfo. Never raises."""
    try:
        res = ((data or {}).get("result") or {}).get("resource") or {}
    except Exception:
        return HostInfo()
    if not isinstance(res, dict):
        return HostInfo()

    asys = res.get("autonomous_system") or {}
    services: list[tuple[int, str]] = []
    seen_ports: set[tuple[int, str]] = set()
    for s in (res.get("services") or []):
        if not isinstance(s, dict):
            continue
        port = s.get("port")
        proto = (s.get("protocol") or s.get("service_name")
                 or s.get("transport_protocol") or "").upper() or "UNKNOWN"
        if isinstance(port, int):
            key = (port, proto)
            if key not in seen_ports:
                seen_ports.add(key)
                services.append(key)

    names: list[str] = []
    for src in ((res.get("dns") or {}).get("names"),
                (res.get("reverse_dns") or {}).get("names"),
                (res.get("forward_dns") or {}).get("names")):
        for n in (src or []):
            if isinstance(n, str) and n and n not in names:
                names.append(n.strip().rstrip("."))

    return HostInfo(
        ip=res.get("ip") or "",
        asn=asys.get("asn") if isinstance(asys.get("asn"), int) else None,
        org=asys.get("name") or asys.get("description") or "",
        country=asys.get("country_code") or asys.get("country") or "",
        service_count=res.get("service_count") or len(services),
        services=services,
        dns_names=names,
    )
