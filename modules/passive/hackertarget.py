"""
hackertarget — Passive subdomain enumeration via hackertarget.com.

Queries https://api.hackertarget.com/hostsearch/?q={domain}
Response is plain text: "hostname,ip_address" one per line.
Free tier: 100 queries/day without an API key.

Produces: SUBDOMAIN, IP events
"""

from __future__ import annotations

from uuid import UUID

from events.types import EventType, IpData, SubdomainData
from modules.base import BaseModule
from modules.registry import register


@register
class HackertargetModule(BaseModule):
    name = "hackertarget"
    description = "Passive subdomain + IP enumeration via hackertarget.com"
    watched_events = []
    produced_events = ["SUBDOMAIN", "IP"]
    flags = ["passive", "safe", "subdomain-enum"]
    options = {"timeout": 30, "api_key": ""}

    async def run(self, domain: str, scan_id: UUID) -> None:
        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed — install recon-ai[passive]")
            return

        params: dict = {"q": domain}
        if self.opt("api_key"):
            params["apikey"] = self.opt("api_key")

        url = "https://api.hackertarget.com/hostsearch/"
        self._log.info("querying hackertarget for %s", domain)
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{domain}"):
                    r = await client.get(url, params=params, follow_redirects=True)
                r.raise_for_status()
                body = r.text
        except Exception as exc:
            self._log.warning("hackertarget request failed: %s", exc)
            return

        if "API count exceeded" in body or "error" in body.lower()[:50]:
            self._log.warning("hackertarget: rate limit or error: %s", body[:120])
            return

        count = 0
        for line in body.splitlines():
            line = line.strip()
            if not line or "," not in line:
                continue
            parts = line.split(",", 1)
            hostname = parts[0].strip().lower().rstrip(".")
            ip_addr = parts[1].strip() if len(parts) > 1 else ""

            if hostname:
                if await self.emit(
                    EventType.SUBDOMAIN,
                    SubdomainData(hostname=hostname, source="hackertarget"),
                ):
                    count += 1

            if ip_addr and ip_addr not in ("", "0.0.0.0"):
                await self.emit(
                    EventType.IP,
                    IpData(address=ip_addr, resolved_from=hostname or None),
                )

        self._log.info("hackertarget: %d new subdomains for %s", count, domain)
