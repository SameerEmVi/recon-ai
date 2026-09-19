"""
wayback — Historical URL enumeration via Wayback Machine CDX API.

Queries http://web.archive.org/cdx/search/cdx for all archived URLs
under *.{domain}. Produces URL events for every unique URL found.
No API key required — the CDX API is public.

Produces: URL events, SUBDOMAIN events (from URL hostnames)
"""

from __future__ import annotations

from urllib.parse import urlparse
from uuid import UUID

from events.types import EventType, SubdomainData, UrlData
from modules.base import BaseModule
from modules.registry import register


@register
class WaybackModule(BaseModule):
    name = "wayback"
    description = "Historical URL enumeration via Wayback Machine CDX API"
    watched_events = []
    produced_events = ["URL", "SUBDOMAIN"]
    flags = ["passive", "safe", "url-enum"]
    options = {
        "timeout": 60,
        "limit": 10000,
        "emit_subdomains": True,   # also emit SUBDOMAIN from URL hostnames
    }

    async def run(self, domain: str, scan_id: UUID) -> None:
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed — install recon-ai[passive]")
            return

        url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(self.opt("limit")),
        }
        self._log.info("querying Wayback Machine for %s (limit=%s)", domain, self.opt("limit"))

        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{domain}"):
                    r = await client.get(url, params=params, follow_redirects=True)
                r.raise_for_status()
                rows = r.json()
        except Exception as exc:
            self._log.warning("Wayback Machine request failed: %s", exc)
            return

        seen_urls: set[str] = set()
        seen_hosts: set[str] = set()
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

            if await self.emit(
                EventType.URL,
                UrlData(url=raw_url, found_via="wayback"),
            ):
                url_count += 1

            if self.opt("emit_subdomains"):
                hostname = urlparse(raw_url).hostname or ""
                hostname = hostname.lower().rstrip(".")
                if hostname and hostname not in seen_hosts:
                    seen_hosts.add(hostname)
                    await self.emit(
                        EventType.SUBDOMAIN,
                        SubdomainData(hostname=hostname, source="wayback"),
                    )

        self._log.info("wayback: %d URLs from %d unique hosts for %s", url_count, len(seen_hosts), domain)
