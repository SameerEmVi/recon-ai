"""
whatweb — technology fingerprinting via the WhatWeb binary (optional).

Reactive module: fires on HTTP_SERVICE events, runs WhatWeb against the URL,
normalizes its plugin output into the existing TECHNOLOGY event model, and emits
each detection with source="whatweb" for provenance. Warn-and-skips if the
`whatweb` binary isn't installed.

This is a second, richer fingerprint source alongside httpx's bundled Wappalyzer
DB (see modules/web/fingerprint.py). Because every detection is emitted through
self.emit → stamp_and_publish → ScopeEngine, results are scope-enforced and
deduplicated by the EventBus (tech:<host>:<name>:<version>) — a technology found
by both httpx and WhatWeb collapses to one event; the surviving one records its
first detector via TechnologyData.source.

Watches:  HTTP_SERVICE
Produces: TECHNOLOGY
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from urllib.parse import urlparse

from events.types import Event, EventType, TechnologyData
from modules.base import BaseModule
from modules.registry import register
from modules.web.fingerprint import _category_for


@register
class WhatWebModule(BaseModule):
    name = "whatweb"
    description = "Technology fingerprinting via the WhatWeb binary"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["TECHNOLOGY"]
    flags = ["active", "web", "fingerprint", "slow"]
    options = {"timeout": 60}
    deps_binary = ["whatweb"]

    async def handle_event(self, event: Event) -> None:
        url = getattr(event.data, "url", None)
        if not url:
            return
        host = urlparse(url).hostname or ""
        if not host:
            return

        text = await self._run_whatweb(url)
        if not text:
            return

        from normalize.parsers import parse_whatweb_json

        seen: set[str] = set()
        count = 0
        for tech in parse_whatweb_json(text):
            name = tech.get("name")
            version = tech.get("version")
            if not name:
                continue
            key = f"{name.lower()}:{version or ''}"
            if key in seen:
                continue
            seen.add(key)
            if await self.emit(
                EventType.TECHNOLOGY,
                TechnologyData(
                    host=host,
                    name=name,
                    version=version,
                    category=_category_for(name),
                    source="whatweb",
                ),
                source_event=event,
            ):
                count += 1

        if count:
            self._log.info("whatweb: %d technologies on %s", count, host)

    async def _run_whatweb(self, url: str) -> str | None:
        """Run WhatWeb with JSON logging (rate-limited) and return the JSON text."""
        tmp = tempfile.NamedTemporaryFile(
            prefix="whatweb_", suffix=".json", delete=False
        )
        tmp.close()
        try:
            cmd = ["whatweb", "--no-errors", "--log-json=" + tmp.name, url]
            async with self.guard(f"http:{urlparse(url).hostname or url}"):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                except FileNotFoundError:
                    self._log.warning("whatweb binary not found — module disabled")
                    return None
                try:
                    await asyncio.wait_for(proc.communicate(), timeout=self.opt("timeout"))
                except asyncio.TimeoutError:
                    proc.kill()
                    self._log.warning("whatweb timed out on %s", url)
                    return None
            with open(tmp.name, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as exc:
            self._log.debug("whatweb failed for %s: %s", url, exc)
            return None
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
