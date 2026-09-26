from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from typing import Any
from uuid import UUID

from events.types import Event, EventType
from normalize.parsers import parse_httpx_json
from recon.base import BaseReconTool

log = logging.getLogger(__name__)


class HttpxWrapper(BaseReconTool):
    """Wraps httpx for HTTP service probing. Emits HTTP_SERVICE events."""

    binary = "httpx"

    @staticmethod
    def _args(target: str) -> list[str]:
        return [
            "-target", target,
            "-silent", "-json",
            "-title", "-server", "-status-code",
            "-content-length", "-follow-redirects",
            "-td",  # tech-detect: httpx's bundled Wappalyzer fingerprint DB
        ]

    async def _probe_one(
        self,
        target: str,
        publish: Callable[[Event], Coroutine[Any, Any, Any]],
        scan_job_id: UUID,
        source_event: Event | None,
    ) -> None:
        lines = await self._run(self._args(target), timeout=60)
        from ratelimit import get_limiter
        limiter = get_limiter(self._ctrl)
        for line in lines:
            data = parse_httpx_json(line, fallback_host=target)
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
                scan_job_id=scan_job_id,
                source_tool="httpx",
                source_event_id=source_event.id if source_event else None,
                distance=source_event.distance if source_event else 0,
            )
            await publish(event)

    async def probe(self, host: str, source_event: Event) -> None:
        await self._probe_one(
            host, self._ctrl.stamp_and_publish, source_event.scan_job_id, source_event
        )

    async def probe_urls(
        self,
        urls: list[str],
        publish: Callable[[Event], Coroutine[Any, Any, Any]],
        scan_job_id: UUID | None = None,
    ) -> None:
        """Probe explicit URLs/hosts (agent tools) — no source event."""
        sid = scan_job_id or self._ctrl.scan_id
        for url in urls:
            await self._probe_one(url, publish, sid, None)
