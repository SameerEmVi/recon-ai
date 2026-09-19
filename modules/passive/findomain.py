"""
findomain — Fast passive subdomain enumeration via findomain binary.

Runs: findomain -t {domain} -q
Output is one hostname per line (quiet mode, no banner).

Produces: SUBDOMAIN events
"""

from __future__ import annotations

import asyncio
from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


@register
class FindomainModule(BaseModule):
    name = "findomain"
    description = "Fast passive subdomain enumeration via findomain binary"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["passive", "subdomain-enum", "fast"]
    options = {"timeout": 120}
    deps_binary = ["findomain"]

    async def run(self, domain: str, scan_id: UUID) -> None:
        cmd = ["findomain", "-t", domain, "-q"]
        self._log.info("running findomain for %s", domain)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            self._log.warning("findomain binary not found — module disabled")
            return

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.opt("timeout")
            )
        except asyncio.TimeoutError:
            proc.kill()
            self._log.warning("findomain timed out after %ds", self.opt("timeout"))
            return

        seen: set[str] = set()
        count = 0
        for raw in stdout.splitlines():
            hostname = raw.decode("utf-8", errors="replace").strip().lower().rstrip(".")
            if not hostname or hostname in seen or " " in hostname:
                continue
            seen.add(hostname)
            if await self.emit(EventType.SUBDOMAIN, SubdomainData(hostname=hostname, source="findomain")):
                count += 1

        self._log.info("findomain: %d new subdomains for %s", count, domain)
