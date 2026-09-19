"""
chaos — Subdomain enumeration via ProjectDiscovery Chaos DNS dataset.

Queries https://dns.projectdiscovery.io/dns/{domain}/subdomains
Free tier returns JSON: {"domain": "...", "subdomains": ["api", "mail", ...]}
Subdomains are labels only — they are prefixed with the root domain.

Produces: SUBDOMAIN events
"""

from __future__ import annotations

from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


@register
class ChaosModule(BaseModule):
    name = "chaos"
    description = "Subdomain enumeration via ProjectDiscovery Chaos DNS dataset"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["passive", "safe", "subdomain-enum"]
    options = {"timeout": 30, "api_key": ""}

    async def run(self, domain: str, scan_id: UUID) -> None:
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return

        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = {}
        if self.opt("api_key"):
            headers["Authorization"] = self.opt("api_key")

        self._log.info("querying Chaos for %s", domain)
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{domain}"):
                    r = await client.get(url, headers=headers, follow_redirects=True)
                r.raise_for_status()
                data = r.json()
        except Exception as exc:
            self._log.warning("chaos request failed: %s", exc)
            return

        subdomains = data.get("subdomains") or []
        count = 0
        seen: set[str] = set()
        for label in subdomains:
            label = str(label).strip().lower().rstrip(".")
            if not label:
                continue
            hostname = f"{label}.{domain}" if not label.endswith(domain) else label
            if hostname in seen:
                continue
            seen.add(hostname)
            if await self.emit(EventType.SUBDOMAIN, SubdomainData(hostname=hostname, source="chaos")):
                count += 1

        self._log.info("chaos: %d new subdomains for %s", count, domain)
