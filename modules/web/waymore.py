"""
waymore — deep historical URL enumeration (xnl-h4ck3r/waymore).

Reactive module: on each SUBDOMAIN, pulls archived URLs (Wayback, Common Crawl,
Alien Vault, URLScan) for that host and emits them as URL events. waymore writes
to a file, so we collect into a temp file and read it back. Warn-and-skips
without `waymore`.

Watches:  SUBDOMAIN
Produces: URL
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from urllib.parse import urlparse

from events.types import Event, EventType, UrlData
from modules.base import BaseModule
from modules.registry import register
from modules.web.urlfinder import parse_urls


@register
class WaymoreModule(BaseModule):
    name = "waymore"
    description = "Deep historical URL enumeration via waymore"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["URL"]
    flags = ["passive", "url-enum", "slow"]
    deps_binary = ["waymore"]
    options = {"timeout": 300}

    async def handle_event(self, event: Event) -> None:
        host = event.data.hostname
        if not host:
            return
        text = await self._collect(host)
        if not text:
            return
        count = 0
        for url in parse_urls(text):
            if urlparse(url).hostname and await self.emit(
                EventType.URL,
                UrlData(url=url, found_via="waymore"),
                source_event=event,
            ):
                count += 1
        if count:
            self._log.info("waymore: %d URLs from %s", count, host)

    async def _collect(self, host: str) -> str | None:
        """Run waymore (URL mode) into a temp file and return its contents."""
        tmp = tempfile.NamedTemporaryFile(prefix="waymore_", suffix=".txt", delete=False)
        tmp.close()
        try:
            cmd = ["waymore", "-i", host, "-mode", "U", "-oU", tmp.name]
            async with self.guard(f"urlenum:{host}"):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd, stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                except FileNotFoundError:
                    self._log.warning("waymore not found — module disabled")
                    return None
                try:
                    await asyncio.wait_for(proc.communicate(), timeout=self.opt("timeout"))
                except asyncio.TimeoutError:
                    proc.kill()
                    self._log.warning("waymore timed out on %s", host)
                    return None
            with open(tmp.name, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as exc:
            self._log.debug("waymore failed for %s: %s", host, exc)
            return None
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
