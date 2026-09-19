"""
anubis — Passive subdomain enumeration via the Anubis OSINT database.

Queries https://jldc.me/anubis/subdomains/{domain}
Returns a JSON array of full hostnames. No API key required.

Produces: SUBDOMAIN events
"""

from __future__ import annotations

from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


@register
class AnubisModule(BaseModule):
    name = "anubis"
    description = "Passive subdomain enumeration via Anubis OSINT database (no key)"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["passive", "safe", "subdomain-enum"]
    options = {"timeout": 30}

    async def run(self, domain: str, scan_id: UUID) -> None:
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return

        url = f"https://jldc.me/anubis/subdomains/{domain}"
        self._log.info("querying Anubis for %s", domain)
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{domain}"):
                    r = await client.get(url, follow_redirects=True)
                r.raise_for_status()
                entries = r.json()
        except Exception as exc:
            self._log.warning("anubis request failed: %s", exc)
            return

        if not isinstance(entries, list):
            self._log.warning("anubis: unexpected response type %s", type(entries))
            return

        seen: set[str] = set()
        count = 0
        for hostname in entries:
            hostname = str(hostname).strip().lower().rstrip(".")
            if not hostname or hostname in seen:
                continue
            seen.add(hostname)
            if await self.emit(EventType.SUBDOMAIN, SubdomainData(hostname=hostname, source="anubis")):
                count += 1

        self._log.info("anubis: %d new subdomains for %s", count, domain)
