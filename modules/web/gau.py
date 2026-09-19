"""
gau — Historical URL enumeration via the gau binary.

Reactive module: fires on SUBDOMAIN events, fetches historical URLs
from Common Crawl, Wayback Machine, and OTX.

Watches:  SUBDOMAIN
Produces: URL
"""

from __future__ import annotations

from events.types import Event
from modules.base import BaseModule
from modules.registry import register


@register
class GauModule(BaseModule):
    name = "gau"
    description = "Historical URL enumeration via gau binary (Common Crawl / Wayback)"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["URL"]
    flags = ["passive", "url-enum", "slow"]
    options = {"timeout": 120}
    deps_binary = ["gau"]

    async def handle_event(self, event: Event) -> None:
        from recon.gau import GauWrapper
        await GauWrapper(timeout=self.opt("timeout"), limiter=self.rate_limiter).fetch(
            event.data.hostname,
            self._ctrl.stamp_and_publish,
            scan_job_id=self._ctrl.scan_id,
        )
