"""
gau (GetAllUrls) wrapper — passive historical URL fetching.

gau queries Common Crawl, Wayback Machine, and other indexes.
No active requests are made to the target.

Output: one URL per line.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any
from uuid import UUID

from events.types import Event, EventType, UrlData

log = logging.getLogger(__name__)

_NOT_FOUND_WARNED = False


class GauWrapper:
    def __init__(self, timeout: int = 120, limiter=None) -> None:
        self._timeout = timeout
        from ratelimit import NOOP
        self._limiter = limiter if limiter is not None else NOOP

    async def fetch(
        self,
        hostname: str,
        publish: Callable[[Event], Coroutine[Any, Any, None]],
        scan_job_id: UUID | None = None,
    ) -> None:
        global _NOT_FOUND_WARNED

        cmd = ["gau", "--threads", "5", "--timeout", "30", hostname]
        log.debug("[gau] %s", " ".join(cmd))

        async with self._limiter.guard("gau"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                if not _NOT_FOUND_WARNED:
                    log.warning("[gau] binary not found — skipping historical URL fetch")
                    _NOT_FOUND_WARNED = True
                return

            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                log.warning("[gau] timed out after %ds", self._timeout)
                return

        import uuid as _uuid
        sid = scan_job_id or _uuid.uuid4()
        count = 0
        for raw_line in stdout.splitlines():
            url = raw_line.decode("utf-8", errors="replace").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue

            from urllib.parse import urlparse
            parsed = urlparse(url)
            if not parsed.hostname:
                continue

            try:
                event = Event.create(
                    EventType.URL,
                    UrlData(url=url, found_via="gau"),
                    scan_job_id=sid,
                    source_tool="gau",
                )
                await publish(event)
                count += 1
            except Exception as exc:
                log.debug("[gau] skipped %s: %s", url[:80], exc)

        log.info("[gau] %s → %d URLs", hostname, count)
