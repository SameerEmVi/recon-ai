"""
censys — Censys Platform host enrichment (passive, evidence-based).

The Censys free-tier API cannot search by domain (that is a paid feature), but
its per-IP **host lookup** is free. So this module enriches the IPs the pipeline
already resolves: it watches `DNS_RECORD` (A/AAAA) and `IP` events, looks each IP
up in Censys, and emits:

  * ANOMALY  (`host-org`)  — the IP's autonomous system / organization + service
                            count (the "organisation IP" intel), also logged
  * OPEN_PORT / TECHNOLOGY — the services Censys observed on that IP
  * SUBDOMAIN              — DNS names Censys associates with the IP (scope-gated,
                            so junk names from shared IPs are dropped and only
                            in-scope org hostnames survive and re-enter the pipeline)

Credentials: `CENSYS_API_KEY` env var (Platform PAT, `censys_…`); optional
`CENSYS_ORG_ID` for paid tiers. The key is never logged or emitted. Without a key
the module warn-and-skips.

Rate limit: the key permits **one concurrent request**, enforced by a dedicated
asyncio.Lock (in addition to the shared RateLimiter's spacing/WAF backoff). A
per-scan `max_lookups` cap protects the account quota. All emission is scope-gated
via `self.emit`. In `EXTRA_PASSIVE` / `--full` (and `-p fast`).
"""

from __future__ import annotations

import asyncio
import os

from events.types import (
    AnomalyData,
    Event,
    EventType,
    OpenPortData,
    SubdomainData,
    TechnologyData,
)
from modules.base import BaseModule
from modules.registry import register
from recon import censys


@register
class CensysModule(BaseModule):
    name = "censys"
    description = "Censys Platform host enrichment: ASN/org, ports, services, DNS names for discovered IPs"
    watched_events = ["DNS_RECORD", "IP"]
    produced_events = ["ANOMALY", "OPEN_PORT", "TECHNOLOGY", "SUBDOMAIN"]
    flags = ["passive", "dns", "cloud", "correlation"]
    expected_value = 8
    options = {
        "timeout": 30,
        "max_lookups": 50,       # cap Censys lookups per scan (quota protection)
        "max_dns_names": 500,    # cap DNS names emitted per host (scope gate filters)
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._key: str | None = None
        self._org: str | None = None
        self._lock = asyncio.Lock()   # enforces the key's 1-concurrent-request limit
        self._seen: set[str] = set()
        self._count = 0

    async def setup(self) -> bool:
        self._key = os.environ.get("CENSYS_API_KEY")
        self._org = os.environ.get("CENSYS_ORG_ID")
        if not self._key:
            self._log.warning("CENSYS_API_KEY not set — module disabled")
            return False
        return True

    async def handle_event(self, event: Event) -> None:
        ip = self._ip_from(event)
        if not ip or ip in self._seen:
            return
        if self._count >= int(self.opt("max_lookups") or 50):
            return
        self._seen.add(ip)
        self._count += 1
        info = await self._lookup(ip)
        if info:
            await self._emit_host(info, event)

    @staticmethod
    def _ip_from(event: Event) -> str:
        d = event.data
        if event.type is EventType.IP:
            return getattr(d, "address", "") or ""
        if event.type is EventType.DNS_RECORD and getattr(d, "record_type", "") in ("A", "AAAA"):
            return getattr(d, "value", "") or ""
        return ""

    async def _lookup(self, ip: str) -> "censys.HostInfo | None":
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return None
        headers = {"Authorization": f"Bearer {self._key}", "Accept": censys.ACCEPT_HOST}
        if self._org:
            headers["X-Organization-ID"] = self._org
        try:
            # One Censys request at a time (rate-limit) + shared limiter spacing/WAF.
            async with self._lock:
                async with self.guard("censys"):
                    async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                        r = await client.get(censys.host_url(ip), headers=headers)
            self.inspect_response(r)
            if r.status_code == 200:
                return censys.parse_host_response(r.json())
            self._log.debug("censys: %s → HTTP %s", ip, r.status_code)
        except Exception as exc:
            self._log.debug("censys lookup failed for %s: %s", ip, exc)
        return None

    async def _emit_host(self, info: "censys.HostInfo", event: Event | None) -> None:
        ip = info.ip
        # Organisation / ASN intel — logged so it is visible even when the IP is
        # out of scope (the ANOMALY below is scope-gated like everything else).
        if info.asn:
            self._log.info("censys: %s %s · %d services", ip, info.org_label(), info.service_count)
            await self.emit(
                EventType.ANOMALY,
                AnomalyData(host=ip,
                            description=f"{info.org_label()}; {info.service_count} services",
                            category="host-org"),
                source_event=event,
            )
        for port, proto in info.services:
            await self.emit(EventType.OPEN_PORT,
                            OpenPortData(host=ip, port=port, protocol="tcp", banner=proto),
                            source_event=event)
            if proto and proto != "UNKNOWN":
                await self.emit(EventType.TECHNOLOGY,
                                TechnologyData(host=ip, name=proto, category="service", source="censys"),
                                source_event=event)
        cap = int(self.opt("max_dns_names") or 500)
        for name in info.dns_names[:cap]:
            await self.emit(EventType.SUBDOMAIN,
                            SubdomainData(hostname=name, source="censys"),
                            source_event=event)
