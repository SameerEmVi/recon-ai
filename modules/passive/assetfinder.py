"""
assetfinder — Fast passive subdomain enumeration via assetfinder binary.

Runs: assetfinder --subs-only {domain}
Output is one hostname per line.

Produces: SUBDOMAIN events
"""

from __future__ import annotations

import asyncio
from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


@register
class AssetfinderModule(BaseModule):
    name = "assetfinder"
    description = "Fast passive subdomain enumeration via assetfinder binary"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["passive", "subdomain-enum", "fast"]
    options = {"timeout": 120}
    deps_binary = ["assetfinder"]

    async def run(self, domain: str, scan_id: UUID) -> None:
        cmd = ["assetfinder", "--subs-only", domain]
        self._log.info("running assetfinder for %s", domain)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            self._log.warning("assetfinder binary not found — module disabled")
            return

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.opt("timeout")
            )
        except asyncio.TimeoutError:
            proc.kill()
            self._log.warning("assetfinder timed out after %ds", self.opt("timeout"))
            return

        seen: set[str] = set()
        count = 0
        for raw in stdout.splitlines():
            hostname = raw.decode("utf-8", errors="replace").strip().lower().rstrip(".")
            if not hostname or hostname in seen or " " in hostname:
                continue
            seen.add(hostname)
            if await self.emit(EventType.SUBDOMAIN, SubdomainData(hostname=hostname, source="assetfinder")):
                count += 1

        self._log.info("assetfinder: %d new subdomains for %s", count, domain)
