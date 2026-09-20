"""
puredns — wildcard-safe DNS bruteforce (puredns + massdns).

Seed module: brute-forces a wordlist against the target with puredns, which does
wildcard detection/filtering via massdns so catch-all domains don't flood the
scan. Complements dnsbrute (dnsx-based). Needs a resolvers file (puredns
requirement) — warn-and-skips without it or without the `puredns` binary.

Produces: SUBDOMAIN
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register

_BUNDLED_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "dns_names.txt"


def parse_hosts(text: str, domain: str) -> list[str]:
    """One hostname per line; keep those within the target domain, de-duplicated."""
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
class PureDnsModule(BaseModule):
    name = "puredns"
    description = "Wildcard-safe DNS bruteforce via puredns + massdns"
    watched_events = []  # seed module
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "dns", "subdomain-enum", "brute", "slow"]
    deps_binary = ["puredns"]
    options = {"wordlist": "", "resolvers": "", "timeout": 600}

    async def run(self, domain: str, scan_id: UUID) -> None:
        wordlist = self.opt("wordlist") or str(_BUNDLED_WORDLIST)
        if not Path(wordlist).exists():
            self._log.warning("puredns: wordlist not found: %s", wordlist)
            return

        cmd = ["puredns", "bruteforce", wordlist, domain, "--quiet"]
        resolvers = self.opt("resolvers")
        if resolvers and Path(resolvers).exists():
            cmd += ["-r", resolvers]
        else:
            self._log.warning(
                "puredns: no resolvers file (option 'resolvers') — puredns may "
                "refuse to run; provide one for reliable results"
            )

        out = await self.run_proc(cmd, timeout=self.opt("timeout"))
        if not out:
            return
        count = 0
        for host in parse_hosts(out, domain):
            if await self.emit(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=host, source="puredns"),
            ):
                count += 1
        if count:
            self._log.info("puredns: %d resolved hostnames", count)
