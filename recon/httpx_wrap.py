from __future__ import annotations

import logging

from events.types import Event, EventType
from normalize.parsers import parse_httpx_json
from recon.base import BaseReconTool

log = logging.getLogger(__name__)


class HttpxWrapper(BaseReconTool):
    """Wraps httpx for HTTP service probing. Emits HTTP_SERVICE events."""

    binary = "httpx"

    async def probe(self, host: str, source_event: Event) -> None:
        lines = await self._run(
            [
                "-target", host,
                "-silent", "-json",
                "-title", "-server", "-status-code",
                "-content-length", "-follow-redirects",
            ],
            timeout=60,
        )
        from ratelimit import get_limiter
        limiter = get_limiter(self._ctrl)
        for line in lines:
            data = parse_httpx_json(line, fallback_host=host)
            if data is None:
                continue
            # Feed the target's own HTTP response into WAF detection so the whole
            # scan backs off if the target is fronted by a WAF that starts blocking.
            limiter.observe_http(
                status=data.status_code,
                headers={"server": data.server} if data.server else None,
            )
            event = Event.create(
                EventType.HTTP_SERVICE,
                data,
                scan_job_id=source_event.scan_job_id,
                source_tool="httpx",
                source_event_id=source_event.id,
                distance=source_event.distance,
            )
            await self._ctrl.stamp_and_publish(event)
