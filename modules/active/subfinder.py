"""
subfinder — Active subdomain enumeration using the subfinder binary.

Seed module: runs subfinder against the target domain at scan start.

Produces: SUBDOMAIN events
"""

from __future__ import annotations

from uuid import UUID

from modules.base import BaseModule
from modules.registry import register


@register
class SubfinderModule(BaseModule):
    name = "subfinder"
    description = "Subdomain enumeration via subfinder binary"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "subdomain-enum"]
    # Behaviour: queries passive sources via the subfinder binary — never contacts
    # the target. The "active" flag is historical; the capability is passive.
    capabilities = ["PASSIVE_EXTERNAL"]
    options = {"timeout": 120}
    deps_binary = ["subfinder"]

    async def run(self, domain: str, scan_id: UUID) -> None:
        from recon.subfinder import SubfinderWrapper
        # Delegate to existing wrapper — it already handles binary-not-found
        # and calls stamp_and_publish for each subdomain found.
        await SubfinderWrapper(self._ctrl).run(domain, scan_id)
