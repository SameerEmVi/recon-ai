"""
nuclei — Information-only vulnerability scanning via nuclei.

Reactive module: fires on HTTP_SERVICE events, runs nuclei with
-severity info only. No exploit templates are loaded.

Watches:  HTTP_SERVICE
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

from events.types import Event
from modules.base import BaseModule
from modules.registry import register


@register
class NucleiModule(BaseModule):
    name = "nuclei"
    description = "Template scanning via nuclei binary (configurable severity)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "web", "slow", "vuln"]
    options = {"timeout": 180, "severity": "info"}
    deps_binary = ["nuclei"]

    async def handle_event(self, event: Event) -> None:
        from recon.nuclei import NucleiWrapper
        await NucleiWrapper(timeout=self.opt("timeout"), limiter=self.rate_limiter).scan(
            event.data.url,
            self._ctrl.stamp_and_publish,
            scan_job_id=self._ctrl.scan_id,
            severity=self.opt("severity"),
        )
