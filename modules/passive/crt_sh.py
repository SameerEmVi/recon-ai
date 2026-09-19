"""
crt_sh — Certificate Transparency subdomain enumeration via crt.sh.

Queries https://crt.sh/?q=%.{domain}&output=json and parses all
DNS names from certificate records. No API key required.

Produces: SUBDOMAIN events
"""

from __future__ import annotations

from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


@register
class CrtShModule(BaseModule):
    name = "crt_sh"
    description = "Certificate Transparency subdomain enumeration via crt.sh"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["passive", "safe", "subdomain-enum"]
    options = {"timeout": 30, "include_expired": True}

    async def run(self, domain: str, scan_id: UUID) -> None:
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed — install recon-ai[passive]")
            return

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        self._log.info("querying crt.sh for %s", domain)

        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{domain}"):
                    r = await client.get(url, follow_redirects=True)
                r.raise_for_status()
                entries = r.json()
        except Exception as exc:
            self._log.warning("crt.sh request failed: %s", exc)
            return

        seen: set[str] = set()
        count = 0
        for entry in entries:
            for raw in entry.get("name_value", "").split("\n"):
                hostname = raw.strip().lstrip("*.").lower().rstrip(".")
                if not hostname or hostname in seen:
                    continue
                seen.add(hostname)
                if await self.emit(
                    EventType.SUBDOMAIN,
                    SubdomainData(hostname=hostname, source="crt_sh"),
                ):
                    count += 1

        self._log.info("crt_sh: %d new subdomains for %s", count, domain)
