"""
amass — Passive subdomain enumeration via the amass binary.

Runs: amass enum -passive -d {domain} -nocolor -silent
Output is one hostname per line.

Produces: SUBDOMAIN events
"""

from __future__ import annotations

import asyncio
import logging
from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register

log = logging.getLogger(__name__)


@register
class AmassModule(BaseModule):
    name = "amass"
    description = "Passive subdomain enumeration via amass binary"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["passive", "subdomain-enum", "slow"]
    options = {"timeout": 300}
    deps_binary = ["amass"]

    async def run(self, domain: str, scan_id: UUID) -> None:
        cmd = ["amass", "enum", "-passive", "-d", domain, "-nocolor", "-silent"]
        self._log.info("running amass passive for %s", domain)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            self._log.warning("amass binary not found — module disabled")
            return

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.opt("timeout")
            )
        except asyncio.TimeoutError:
            proc.kill()
            self._log.warning("amass timed out after %ds", self.opt("timeout"))
            return

        seen: set[str] = set()
        count = 0
        for raw in stdout.splitlines():
            hostname = raw.decode("utf-8", errors="replace").strip().lower().rstrip(".")
            if not hostname or hostname in seen or " " in hostname:
                continue
            seen.add(hostname)
            if await self.emit(EventType.SUBDOMAIN, SubdomainData(hostname=hostname, source="amass")):
                count += 1

        self._log.info("amass: %d new subdomains for %s", count, domain)
