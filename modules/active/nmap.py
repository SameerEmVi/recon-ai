"""
nmap — service/version detection on open ports.

Reactive module in the "naabu discovers, nmap identifies" combo: it fires on
each OPEN_PORT event (produced by naabu), runs `nmap -sV` against that port, and
emits a TECHNOLOGY event naming the service and version. It also re-emits the
OPEN_PORT enriched with a banner; dedup drops the plain re-emit but the banner
detail rides along for persistence.

Watches:  OPEN_PORT
Produces: TECHNOLOGY, FINDING_CANDIDATE (only when a script/opt surfaces one)
Requires: nmap on PATH (installed under Program Files (x86)/Nmap here)
"""

from __future__ import annotations

from events.types import Event, EventType, TechnologyData
from modules.base import BaseModule
from modules.registry import register


@register
class NmapModule(BaseModule):
    name = "nmap"
    description = "Service/version detection on open ports via nmap -sV"
    watched_events = ["OPEN_PORT"]
    produced_events = ["TECHNOLOGY"]
    flags = ["active", "port-scan", "service-detection", "slow"]
    options = {
        "timeout": 180,
        # Opt-in NSE scripts (e.g. "default,safe" or "banner"). Off by default.
        "scripts": None,
        # nmap --version-intensity 0..9 (higher = more probes). None = nmap default.
        "version_intensity": None,
    }
    deps_binary = ["nmap"]

    async def handle_event(self, event: Event) -> None:
        host = event.data.host
        port = event.data.port
        if not host or port is None:
            return

        from recon.nmap import NmapWrapper
        wrapper = NmapWrapper(timeout=self.opt("timeout"), limiter=self.rate_limiter)
        services = await wrapper.scan(
            host,
            str(port),
            scripts=self.opt("scripts"),
            version_intensity=self.opt("version_intensity"),
        )

        count = 0
        for svc in services:
            # Skip nmap results with no useful identification.
            if svc.service in ("", "unknown") and not svc.product:
                continue
            name = svc.product or svc.service
            if await self.emit(
                EventType.TECHNOLOGY,
                TechnologyData(
                    host=host,
                    name=name,
                    version=svc.version,
                    category="service",
                ),
                source_event=event,
            ):
                count += 1
                self._log.info(
                    "nmap: %s:%d → %s %s",
                    host, svc.port, name, svc.version or "",
                )

        if count == 0:
            self._log.debug("nmap: no service identified on %s:%s", host, port)
