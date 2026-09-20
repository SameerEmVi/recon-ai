"""
hakip2host — reverse-IP hostname discovery (hakluke/hakip2host).

Reactive module: feeds each discovered IP to hakip2host (DNS-PTR / DNS-A /
TLS-CN lookups) and emits recovered hostnames as SUBDOMAIN events, scope-gated.
Warn-and-skips without `hakip2host`.

Watches:  IP
Produces: SUBDOMAIN
"""

from __future__ import annotations

from events.types import Event, EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


def parse_hakip2host(text: str) -> list[str]:
    """Parse hakip2host output lines like:

        1.1.1.1 - [DNS-PTR] one.one.one.one
        1.1.1.1 - [TLS-CN] cloudflare-dns.com

    into hostnames.
    """
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "]" not in line:
            continue
        host = line.rsplit("]", 1)[-1].strip().rstrip(".").lower()
        if not host or " " in host or "." not in host:
            continue
        if host not in seen:
            seen.add(host)
            out.append(host)
    return out


@register
class HakIp2HostModule(BaseModule):
    name = "hakip2host"
    description = "Reverse-IP hostname discovery via hakip2host binary"
    watched_events = ["IP"]
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "dns", "subdomain-enum", "reverse-ip", "fast"]
    deps_binary = ["hakip2host"]
    options = {"timeout": 30}

    async def handle_event(self, event: Event) -> None:
        ip = event.data.address
        if not ip:
            return
        out = await self.run_proc(
            ["hakip2host"], input_text=ip + "\n",
            timeout=self.opt("timeout"), bucket=f"ip:{ip}",
        )
        if not out:
            return
        count = 0
        for host in parse_hakip2host(out):
            if await self.emit(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=host, source="hakip2host"),
                source_event=event,
            ):
                count += 1
        if count:
            self._log.info("hakip2host: %d hostnames from %s", count, ip)
