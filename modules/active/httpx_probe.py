"""
httpx_probe — HTTP/HTTPS service probing via the httpx binary.

Reactive module. Probes three ways:
  - SUBDOMAIN  → probe the HOSTNAME (so httpx sends the right Host header and we
                 hit the real name-based virtual host, not the IP's default vhost).
                 This is what makes dirsearch/nuclei/fingerprint/etc. target real
                 content, and it works without the resolved IP being in scope.
  - IP         → probe the IP on common HTTP ports.
  - OPEN_PORT  → probe that specific host:port.

Watches:  SUBDOMAIN, IP, OPEN_PORT
Produces: HTTP_SERVICE
"""

from __future__ import annotations

from events.types import Event, EventType
from modules.base import BaseModule
from modules.registry import register


@register
class HttpxProbeModule(BaseModule):
    name = "httpx_probe"
    description = "HTTP service detection via httpx binary"
    watched_events = ["SUBDOMAIN", "IP", "OPEN_PORT"]
    produced_events = ["HTTP_SERVICE"]
    flags = ["active", "http", "fast"]
    options = {"timeout": 60}
    deps_binary = ["httpx"]

    async def handle_event(self, event: Event) -> None:
        from recon.httpx_wrap import HttpxWrapper

        if event.type == EventType.SUBDOMAIN:
            # Probe by hostname: httpx tries http+https and sends the correct
            # Host header, so we hit the real vhost rather than the default one.
            target = event.data.hostname
        elif event.type == EventType.IP:
            target = event.data.address
        elif event.type == EventType.OPEN_PORT:
            # Build URL candidates for this specific port.
            host = event.data.host
            port = event.data.port
            if port in (443, 8443, 9443):
                target = f"https://{host}:{port}"
            elif port in (80, 8080, 8000, 8888, 3000, 5000, 9000, 9001):
                target = f"http://{host}:{port}"
            else:
                # Try both schemes for unknown ports.
                target = f"https://{host}:{port}"
        else:
            return

        await HttpxWrapper(self._ctrl).probe(target, event)
