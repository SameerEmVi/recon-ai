"""
dnsx — DNS resolution for discovered subdomains.

Reactive module: fires on every SUBDOMAIN event, resolves A/AAAA/CNAME
records, and emits DNS_RECORD + IP events.

Watches:  SUBDOMAIN
Produces: DNS_RECORD, IP
"""

from __future__ import annotations

from events.types import Event
from modules.base import BaseModule
from modules.registry import register


@register
class DnsxModule(BaseModule):
    name = "dnsx"
    description = "DNS resolution (A/AAAA/CNAME) via dnsx binary"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["DNS_RECORD", "IP"]
    flags = ["active", "dns", "fast"]
    options = {"timeout": 30}
    deps_binary = ["dnsx"]

    async def handle_event(self, event: Event) -> None:
        from recon.dnsx import DnsxWrapper
        await DnsxWrapper(self._ctrl).resolve(event.data.hostname, event)
