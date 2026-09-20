"""
urlfinder — passive URL enumeration (ProjectDiscovery urlfinder).

Reactive module: on each SUBDOMAIN, pulls known URLs for that host from passive
sources and emits them as URL events (which re-enter the pipeline for
paramfinder/apifinder/secretfinder). Warn-and-skips without `urlfinder`.

Watches:  SUBDOMAIN
Produces: URL
"""

from __future__ import annotations

from urllib.parse import urlparse

from events.types import Event, EventType, UrlData
from modules.base import BaseModule
from modules.registry import register


def parse_urls(text: str) -> list[str]:
    """One URL per line; keep valid http(s) URLs, de-duplicated."""
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        u = line.strip()
        if not u:
            continue
        p = urlparse(u)
        if p.scheme in ("http", "https") and p.hostname and u not in seen:
            seen.add(u)
            out.append(u)
    return out


@register
class UrlFinderModule(BaseModule):
    name = "urlfinder"
    description = "Passive URL enumeration via urlfinder binary (ProjectDiscovery)"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["URL"]
    flags = ["passive", "url-enum", "slow"]
    deps_binary = ["urlfinder"]
    options = {"timeout": 120}

    async def handle_event(self, event: Event) -> None:
        host = event.data.hostname
        if not host:
            return
        out = await self.run_proc(
            ["urlfinder", "-d", host, "-silent"],
            timeout=self.opt("timeout"), bucket=f"urlenum:{host}",
        )
        if not out:
            return
        count = 0
        for url in parse_urls(out):
            if await self.emit(
                EventType.URL,
                UrlData(url=url, found_via="urlfinder"),
                source_event=event,
            ):
                count += 1
        if count:
            self._log.info("urlfinder: %d URLs from %s", count, host)
