"""
certspotter — Certificate Transparency subdomain enumeration via certspotter.com.

Queries https://api.certspotter.com/v1/issuances for DNS names in issued certs.
No API key required for the free tier (limited to 100 results/hour).

Produces: SUBDOMAIN events
"""

from __future__ import annotations

from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


@register
class CertspotterModule(BaseModule):
    name = "certspotter"
    description = "Certificate Transparency subdomain enumeration via certspotter.com"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["passive", "safe", "subdomain-enum"]
    options = {"timeout": 30, "api_key": ""}

    async def run(self, domain: str, scan_id: UUID) -> None:
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed — install recon-ai[passive]")
            return

        url = (
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names"
        )
        headers = {}
        if self.opt("api_key"):
            headers["Authorization"] = f"Bearer {self.opt('api_key')}"

        self._log.info("querying certspotter for %s", domain)
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{domain}"):
                    r = await client.get(url, headers=headers, follow_redirects=True)
                r.raise_for_status()
                issuances = r.json()
        except Exception as exc:
            self._log.warning("certspotter request failed: %s", exc)
            return

        seen: set[str] = set()
        count = 0
        for issuance in issuances:
            for dns_name in issuance.get("dns_names", []):
                hostname = dns_name.lstrip("*.").lower().rstrip(".")
                if not hostname or hostname in seen:
                    continue
                seen.add(hostname)
                if await self.emit(
                    EventType.SUBDOMAIN,
                    SubdomainData(hostname=hostname, source="certspotter"),
                ):
                    count += 1

        self._log.info("certspotter: %d new subdomains for %s", count, domain)
