from __future__ import annotations

import logging

from events.types import Event, EventType
from normalize.parsers import parse_dnsx_line
from recon.base import BaseReconTool

log = logging.getLogger(__name__)


class DnsxWrapper(BaseReconTool):
    """Wraps dnsx for DNS resolution. Emits DNS_RECORD + IP events."""

    binary = "dnsx"

    async def resolve(self, hostname: str, source_event: Event) -> None:
        lines = await self._run(
            ["-silent", "-nc", "-resp", "-a", "-aaaa", "-cname"],
            timeout=30,
            stdin_data=hostname + "\n",
        )
        for line in lines:
            result = parse_dnsx_line(line, hostname)
            if result is None:
                continue
            dns_data, ip_data = result

            dns_event = Event.create(
                EventType.DNS_RECORD,
                dns_data,
                scan_job_id=source_event.scan_job_id,
                source_tool="dnsx",
                source_event_id=source_event.id,
                distance=source_event.distance,
            )
            await self._ctrl.stamp_and_publish(dns_event)

            if ip_data is not None:
                ip_event = Event.create(
                    EventType.IP,
                    ip_data,
                    scan_job_id=source_event.scan_job_id,
                    source_tool="dnsx",
                    source_event_id=source_event.id,
                    distance=source_event.distance,
                )
                await self._ctrl.stamp_and_publish(ip_event)
