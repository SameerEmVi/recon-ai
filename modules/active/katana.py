"""
katana — Active web crawling via the katana binary.

Reactive: fires on HTTP_SERVICE events. Crawls the target URL up to a
configurable depth, following links and JS includes. Emits URL events
for every unique URL discovered.

Watches:  HTTP_SERVICE
Produces: URL
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from events.types import Event, EventType, UrlData
from modules.base import BaseModule
from modules.registry import register


@register
class KatanaModule(BaseModule):
    name = "katana"
    description = "Active web crawling via katana binary (ProjectDiscovery)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["URL"]
    flags = ["active", "web", "crawl", "slow"]
    options = {"timeout": 180, "depth": 3, "concurrency": 10, "js_crawl": True}
    deps_binary = ["katana"]

    async def handle_event(self, event: Event) -> None:
        url = event.data.url
        if not url:
            return

        cmd = [
            "katana",
            "-u", url,
            "-d", str(self.opt("depth")),
            "-c", str(self.opt("concurrency")),
            "-silent",
            "-timeout", "10",
        ]
        if self.opt("js_crawl"):
            cmd += ["-jc", "-js-crawl"]

        self._log.info("katana crawling %s (depth=%s)", url, self.opt("depth"))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            self._log.warning("katana binary not found — module disabled")
            return

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.opt("timeout")
            )
        except asyncio.TimeoutError:
            proc.kill()
            self._log.warning("katana timed out after %ds on %s", self.opt("timeout"), url)
            return

        seen: set[str] = set()
        count = 0
        for raw in stdout.splitlines():
            found_url = raw.decode("utf-8", errors="replace").strip()
            if not found_url or not found_url.startswith(("http://", "https://")):
                continue
            parsed = urlparse(found_url)
            if not parsed.hostname or found_url in seen:
                continue
            seen.add(found_url)
            if await self.emit(
                EventType.URL,
                UrlData(url=found_url, found_via="katana"),
                source_event=event,
            ):
                count += 1

        self._log.info("katana: %d URLs from %s", count, url)
