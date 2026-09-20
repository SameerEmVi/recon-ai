"""
github_subdomains — passive subdomain enumeration from GitHub code search.

Seed module: runs gwen001/github-subdomains against the seed domain. Requires a
GitHub token in $GITHUB_TOKEN (warn-and-skips without it or without the binary).

Produces: SUBDOMAIN
"""

from __future__ import annotations

import os
from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register


def parse_lines(text: str, domain: str) -> list[str]:
    """One hostname per line; keep those within the target domain."""
    domain = domain.strip().rstrip(".").lower()
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        h = line.strip().rstrip(".").lower()
        if not h or " " in h:
            continue
        if h == domain or h.endswith("." + domain):
            if h not in seen:
                seen.add(h)
                out.append(h)
    return out


@register
class GithubSubdomainsModule(BaseModule):
    name = "github_subdomains"
    description = "Passive subdomain enumeration via github-subdomains (needs GITHUB_TOKEN)"
    watched_events = []  # seed module
    produced_events = ["SUBDOMAIN"]
    flags = ["passive", "subdomain-enum", "slow"]
    deps_binary = ["github-subdomains"]
    options = {"timeout": 180, "token_env": "GITHUB_TOKEN"}

    async def run(self, domain: str, scan_id: UUID) -> None:
        token = os.environ.get(self.opt("token_env"))
        if not token:
            self._log.warning(
                "%s not set — github_subdomains skipped", self.opt("token_env")
            )
            return
        out = await self.run_proc(
            ["github-subdomains", "-d", domain, "-t", token, "-raw"],
            timeout=self.opt("timeout"),
        )
        if not out:
            return
        count = 0
        for host in parse_lines(out, domain):
            if await self.emit(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=host, source="github_subdomains"),
            ):
                count += 1
        if count:
            self._log.info("github_subdomains: %d hostnames", count)
