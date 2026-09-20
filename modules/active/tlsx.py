"""
tlsx — subdomain discovery via TLS certificate SANs (ProjectDiscovery tlsx).

Reactive module: on each SUBDOMAIN, connects to :443, reads the certificate's
Subject Alternative Names and emits any new hostnames as SUBDOMAIN events (each
re-enters the pipeline and is scope-gated). Warn-and-skips without `tlsx`.

Watches:  SUBDOMAIN
Produces: SUBDOMAIN
"""

from __future__ import annotations

from events.types import Event, EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


def parse_tlsx_sans(text: str) -> list[str]:
    """Parse tlsx -san -resp-only output (one SAN per line) into hostnames."""
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        name = line.strip().lstrip("*.").lower().rstrip(".")
        if not name or " " in name or "." not in name:
            continue
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


@register
class TlsxModule(BaseModule):
    name = "tlsx"
    description = "Subdomain discovery via TLS certificate SANs (tlsx binary)"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "dns", "subdomain-enum", "tls", "fast"]
    deps_binary = ["tlsx"]
    options = {"timeout": 30, "port": 443}

    async def handle_event(self, event: Event) -> None:
        host = event.data.hostname
        if not host:
            return
        out = await self.run_proc(
            ["tlsx", "-u", f"{host}:{self.opt('port')}", "-silent", "-san", "-resp-only"],
            timeout=self.opt("timeout"),
            bucket=f"tls:{host}",
        )
        if not out:
            return
        count = 0
        for name in parse_tlsx_sans(out):
            if name == host.lower():
                continue
            if await self.emit(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=name, source="tlsx"),
                source_event=event,
            ):
                count += 1
        if count:
            self._log.info("tlsx: %d SAN hostnames from %s", count, host)
