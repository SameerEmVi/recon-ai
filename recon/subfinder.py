from __future__ import annotations

import logging
from uuid import UUID

from events.types import Event, EventType
from normalize.parsers import parse_subfinder_line
from recon.base import BaseReconTool

log = logging.getLogger(__name__)


class SubfinderWrapper(BaseReconTool):
    """Wraps subfinder for passive subdomain enumeration."""

    binary = "subfinder"

    async def run(self, domain: str, scan_job_id: UUID) -> None:
        lines = await self._run(["-d", domain, "-silent", "-all"], timeout=120)
        count = 0
        for line in lines:
            data = parse_subfinder_line(line)
            if data is None:
                continue
            event = Event.create(
                EventType.SUBDOMAIN,
                data,
                scan_job_id=scan_job_id,
                source_tool="subfinder",
            )
            if await self._ctrl.stamp_and_publish(event):
                count += 1
        log.info("subfinder: %d new subdomains for %s", count, domain)
