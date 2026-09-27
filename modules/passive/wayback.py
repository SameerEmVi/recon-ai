"""
wayback — Historical URL enumeration via the Wayback Machine CDX API.

Reactive module: fires on SUBDOMAIN events and queries
http://web.archive.org/cdx/search/cdx **per host** for that host's archived
URLs. Produces a URL event for every unique archived URL.
No API key required — the CDX API is public.

Why per-host (not one domain-wide query):
  CDX returns results sorted by SURT urlkey, which orders the apex host first
  and subdomains last. A single ``*.{domain}/*`` query therefore exhausts its
  ``limit`` on apex URLs before ever reaching a subdomain, so subdomain URLs
  (e.g. a login page on a facility subdomain) were silently never pulled.
  Querying each discovered in-scope host separately gives every host its own
  full ``limit`` — the same approach `gau`/`waybackurls` take.

Watches:  SUBDOMAIN  (the seed domain is published as a SUBDOMAIN, so the apex
                      is covered too; every enumerated in-scope subdomain fires
                      this module in turn)
Produces: URL
"""

from __future__ import annotations

from urllib.parse import urlparse

from events.types import Event, EventType, UrlData
from modules.base import BaseModule
from modules.registry import register


@register
class WaybackModule(BaseModule):
    name = "wayback"
    description = "Historical URL enumeration via Wayback Machine CDX API (per-host)"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["URL"]
    flags = ["passive", "safe", "url-enum"]
    options = {
        "timeout": 60,
        "limit": 10000,   # per host — every discovered host gets its own budget
    }

    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        # Dedup: never query the same host's archive twice (a host can arrive as
        # SUBDOMAIN from several enum sources, and the apex arrives as the seed).
        self._queried_hosts: set[str] = set()

    async def handle_event(self, event: Event) -> None:
        host = (getattr(event.data, "hostname", "") or "").lower().rstrip(".")
        if not host or host in self._queried_hosts:
            return
        # Claim the host *before* awaiting so concurrent handlers don't double-fire.
        self._queried_hosts.add(host)

        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed — install recon-ai[passive]")
            return

        url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"{host}/*",       # single trailing wildcard → prefix match on this host
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(self.opt("limit")),
        }
        self._log.info("querying Wayback Machine for %s (limit=%s)", host, self.opt("limit"))

        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard("wayback:web.archive.org"):
                    r = await client.get(url, params=params, follow_redirects=True)
                r.raise_for_status()
                rows = r.json()
        except Exception as exc:
            self._log.warning("Wayback Machine request for %s failed: %s", host, exc)
            return

        if not isinstance(rows, list):
            return

        seen_urls: set[str] = set()
        url_count = 0

        # First row is the header ["original"], skip it.
        for row in rows[1:]:
            if not row:
                continue
            raw_url = str(row[0]).strip()
            if not raw_url or raw_url in seen_urls:
                continue
            if not raw_url.startswith(("http://", "https://")):
                continue
            seen_urls.add(raw_url)

            # Defensive: a per-host prefix query should only return this host,
            # but never let an unexpected cross-host row escape the scope gate
            # implicitly — emit() still runs it through stamp_and_publish anyway.
            if await self.emit(
                EventType.URL,
                UrlData(url=raw_url, found_via="wayback"),
                source_event=event,
            ):
                url_count += 1

        self._log.info("wayback: %d URLs for %s", url_count, host)
