"""
gowitness — Web screenshots via gowitness binary.

Reactive: fires on HTTP_SERVICE events. Takes a screenshot of each live
HTTP service and saves it to ./screenshots/{scan_id}/. Emits an ANOMALY
event pointing to the saved file so results are queryable via MCP.

Watches:  HTTP_SERVICE
Produces: ANOMALY
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from urllib.parse import urlparse

from events.types import AnomalyData, Event, EventType
from modules.base import BaseModule
from modules.registry import register


@register
class GoWitnessModule(BaseModule):
    name = "gowitness"
    description = "Web screenshots via gowitness binary"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["ANOMALY"]
    flags = ["active", "web", "screenshots", "slow"]
    options = {"timeout": 30, "screenshot_dir": "screenshots"}
    deps_binary = ["gowitness"]

    async def handle_event(self, event: Event) -> None:
        url = event.data.url
        if not url:
            return

        scan_dir = Path(self.opt("screenshot_dir")) / str(self._ctrl.scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "gowitness",
            "single",
            "--url", url,
            "--screenshot-path", str(scan_dir),
            "--timeout", str(self.opt("timeout")),
        ]

        self._log.debug("gowitness screenshot: %s", url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            self._log.warning("gowitness binary not found — module disabled")
            return

        try:
            _, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.opt("timeout") + 5
            )
        except asyncio.TimeoutError:
            proc.kill()
            self._log.warning("gowitness timed out on %s", url)
            return

        if proc.returncode != 0:
            return

        # Locate the screenshot file gowitness just wrote.
        host = urlparse(url).hostname or url
        screenshot_path = str(scan_dir)
        await self.emit(
            EventType.ANOMALY,
            AnomalyData(
                host=host,
                description=f"screenshot saved to {screenshot_path}",
                category="screenshot",
            ),
            source_event=event,
        )

        self._log.info("gowitness: screenshot saved for %s → %s", url, screenshot_path)
